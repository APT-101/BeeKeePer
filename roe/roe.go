// Package roe implements the M1 Rules of Engagement egress compilation and
// matching (docs §3.3). Compile turns a task's test scope + company assets
// into an allow-list of domains / IPs / CIDRs with an optional port set;
// matching is deny-by-default. The compiled policy is persisted by the caller
// into task_egress and is what the sandbox/egress enforcement layer consults.
package roe

import (
	"net"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// EgressRule is one allow entry compiled from scope/company inputs.
type EgressRule struct {
	Domains  []string // exact or wildcard *.example.com (implies example.com + subdomains)
	IPs      []string // exact addresses
	CIDRs    []string // networks (ip/prefix)
	Ports    []uint16 // empty = all ports allowed for this entry
	ViaProxy bool     // HTTP(S) traffic should go through the recording proxy
}

// Compiled is the deny-by-default egress policy of one task.
type Compiled struct {
	Rules        []EgressRule
	DenyDefault  bool // true = enforce (block unlisted); false = observe, log-only
	Version      int  // compile revision (bump on every Compile)
	CompiledFrom string
}

// Host is a parsed target for matching.
type Host struct {
	Name string // hostname or IP literal (no port)
	Port uint16 // 0 = unknown/unconstrained
}

// ParseHost splits "host" or "host:port" (host may be IPv6 in brackets).
func ParseHost(target string) Host {
	t := strings.TrimSpace(target)
	if h, p, err := net.SplitHostPort(t); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			return Host{Name: strings.Trim(h, "[]"), Port: uint16(n)}
		}
		return Host{Name: strings.Trim(h, "[]")}
	}
	return Host{Name: strings.Trim(t, "[]")}
}

// Compile builds the deny-by-default egress policy from a task's scope rows and
// (optionally) the assets of the companies referenced by kind=company rows.
// Inputs are treated as untrusted: invalid IPs/CIDRs are skipped (caller may
// audit the skips via the returned warnings).
func Compile(scopeItems []db.TaskScope, companyAssets []db.Asset) (*Compiled, []string) {
	c := &Compiled{DenyDefault: true, Version: 1, CompiledFrom: "scope"}
	seen := map[string]bool{}
	var warnings []string

	addDomain := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" {
			return
		}
		key := "d:" + strings.ToLower(d)
		if seen[key] {
			return
		}
		seen[key] = true
		// 只取最后一条规则对应的集合：把通配与精确统一存进第一条规则（简化匹配）。
		if len(c.Rules) == 0 {
			c.Rules = append(c.Rules, EgressRule{ViaProxy: true})
		}
		c.Rules[0].Domains = append(c.Rules[0].Domains, strings.ToLower(d))
	}
	addIP := func(ip string) {
		i := strings.TrimSpace(ip)
		if net.ParseIP(i) == nil {
			warnings = append(warnings, "skip invalid IP: "+i)
			return
		}
		key := "i:" + i
		if seen[key] {
			return
		}
		seen[key] = true
		if len(c.Rules) == 0 {
			c.Rules = append(c.Rules, EgressRule{ViaProxy: true})
		}
		c.Rules[0].IPs = append(c.Rules[0].IPs, i)
	}
	addCIDR := func(cidr string) {
		cd := strings.TrimSpace(cidr)
		if !strings.Contains(cd, "/") {
			if net.ParseIP(cd) != nil {
				cd = cd + "/32"
			} else {
				warnings = append(warnings, "skip invalid CIDR: "+cidr)
				return
			}
		}
		if _, _, err := net.ParseCIDR(cd); err != nil {
			warnings = append(warnings, "skip invalid CIDR: "+cidr)
			return
		}
		key := "c:" + cd
		if seen[key] {
			return
		}
		seen[key] = true
		if len(c.Rules) == 0 {
			c.Rules = append(c.Rules, EgressRule{ViaProxy: true})
		}
		c.Rules[0].CIDRs = append(c.Rules[0].CIDRs, cd)
	}

	// 1) 显式任务范围（最高优先级来源）
	for _, s := range scopeItems {
		switch s.Kind {
		case "root_domain", "subdomain":
			d := s.Domain
			if d == "" {
				d = s.Value
			}
			addDomain(d)
		case "ip":
			v := stripHostPort(s.Net)
			if v == "" {
				v = s.Value
			}
			// AddAgentScope 会把裸 IP 规范成 host/net（如 10.0.0.5/32），统一按 CIDR 录入。
			if strings.Contains(v, "/") {
				addCIDR(v)
			} else {
				addIP(v)
			}
			if s.Value != "" && s.Value != v {
				if strings.Contains(s.Value, "/") {
					addCIDR(stripHostPort(s.Value))
				} else {
					addIP(s.Value)
				}
			}
		case "cidr":
			addCIDR(stripHostPort(s.Net))
			if s.Value != "" {
				addCIDR(stripHostPort(s.Value))
			}
		case "company":
			// 由调用方把该公司的资产展开后作为 companyAssets 传入
		default:
			// icp / keyword：无法表达为网络地址 → 记录但不进规则
			warnings = append(warnings, "scope kind "+s.Kind+" not expressible as egress rule")
		}
	}
	// 2) 公司已证实资产（kind=company 行解析后由调用方传入）
	for _, a := range companyAssets {
		switch a.Type {
		case "root_domain", "subdomain", "domain":
			addDomain(a.Domain)
		case "ip":
			addIP(stripHostPort(a.IP))
		case "cidr":
			addCIDR(a.CSegment)
		}
	}
	return c, warnings
}

// Allow decides whether a target is inside the compiled policy. denyDefault
// rules only; port sets are enforced when the entry declares them. The return
// reason states which entry matched (for audit/violation messages).
func Allow(target string, compiled *Compiled) (allowed bool, reason string) {
	if compiled == nil || len(compiled.Rules) == 0 {
		return !compiledDenyDefault(compiled), "no egress rules compiled"
	}
	h := ParseHost(target)
	ip := net.ParseIP(h.Name)
	for _, r := range compiled.Rules {
		if matchedRule(h, ip, r) {
			return true, "in-scope target"
		}
	}
	return !compiledDenyDefault(compiled), "target outside task egress scope (deny by default)"
}

func compiledDenyDefault(c *Compiled) bool { return c == nil || c.DenyDefault }

// matchedRule reports whether host/ip matches one rule entry (domain/wildcard,
// exact IP, or CIDR), honoring an entry-level port set. When the entry declares
// ports and the target carries a port, the port must be in the set.
func matchedRule(h Host, ip net.IP, r EgressRule) bool {
	if len(r.Ports) > 0 && h.Port != 0 {
		ok := false
		for _, p := range r.Ports {
			if p == h.Port {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if ip != nil {
		for _, cidr := range r.CIDRs {
			if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
				return true
			}
		}
		for _, e := range r.IPs {
			if net.ParseIP(e) != nil && net.ParseIP(e).Equal(ip) {
				return true
			}
		}
	}
	if h.Name != "" {
		host := strings.ToLower(h.Name)
		for _, d := range r.Domains {
			d = strings.ToLower(strings.TrimPrefix(d, "*."))
			if host == d {
				return true
			}
			if strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}
	return false
}

// stripHostPort drops a trailing :port (or brackets) from "host:port" values.
func stripHostPort(v string) string {
	v = strings.TrimSpace(v)
	if h, _, err := net.SplitHostPort(v); err == nil {
		return h
	}
	return v
}
