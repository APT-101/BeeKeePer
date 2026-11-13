package sandbox

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/roe"
)

// egressScriptMaxRules caps the generated iptables whitelist (defensive; task
// scopes are small, a pathological scope would otherwise produce a giant entry
// script).
const egressScriptMaxRules = 1000

// buildEgressEntry renders the container entry script that installs the
// netns-local iptables egress whitelist, then parks the container. Semantics
// (docs §3.3 L4 强制, applies ONLY inside the container's own netns):
//
//   - default OUTPUT policy DROP — only the whitelist below may connect out;
//   - loopback allowed (container-local services, docker embedded DNS);
//   - ESTABLISHED,RELATED allowed (returns for allowed connects);
//   - DNS queries allowed (udp/tcp 53) so resolution still works — resolution
//     is unrestricted, *connections* are whitelisted (a non-allowlisted
//     domain resolves fine but its IPs have no ACCEPT rule → DROP);
//   - allowlist targets: spec domains resolved to IPs (host-side resolution;
//     a domain that fails to resolve simply gets no rule — network layer
//     fails CLOSED for it), plus IPs and CIDRs. When policy ports are set,
//     targets are allowed ONLY on those ports (tcp+udp); empty ports = all.
//
// Requires the container to have NET_ADMIN (provider adds it) — the capability
// is confined to the container's own network namespace and gives no host
// access. Requires iptables in the sandbox image.
func buildEgressEntry(rules []roe.EgressRule) (string, error) {
	var ips, cidrs []string
	var ports []uint16
	for _, r := range rules {
		for _, d := range r.Domains {
			if addrs, err := net.LookupIP(d); err == nil {
				for _, a := range addrs {
					if v4 := a.To4(); v4 != nil {
						ips = append(ips, v4.String())
					}
				}
			}
			// 解析失败（含仅 AAAA）：该域获得零规则 → 网络层对其 fail-closed。
		}
		ips = append(ips, r.IPs...)
		cidrs = append(cidrs, r.CIDRs...)
		ports = append(ports, r.Ports...)
	}
	ips = dedupeStrings(ips)
	cidrs = dedupeStrings(cidrs)
	ports = dedupeUint16(ports)
	sort.Strings(ips)
	sort.Strings(cidrs)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })

	if len(ips)+len(cidrs) == 0 {
		return "", fmt.Errorf("egress 白名单为空（域全部解析失败且无 IP/CIDR）")
	}
	if len(ports) > 0 && (len(ips)+len(cidrs))*len(ports)*2 > egressScriptMaxRules {
		return "", fmt.Errorf("egress 白名单规则数超限")
	}

	// "ip" here is busybox's; use "command -v" style guard is unnecessary —
	// image guarantees iptables. tcp/udp port rules are emitted per target.
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("iptables -P OUTPUT DROP\n")
	b.WriteString("iptables -A OUTPUT -o lo -j ACCEPT\n")
	b.WriteString("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	// DNS: embedded docker resolver (127.0.0.11, loopback → covered by lo) and
	// any upstream forward (docker forwards out of the container netns — allow
	// 53 so resolution succeeds; connections stay whitelisted).
	b.WriteString("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT\n")
	b.WriteString("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT\n")

	allowTarget := func(target string) {
		if len(ports) == 0 {
			b.WriteString("iptables -A OUTPUT -d " + target + " -j ACCEPT\n")
			return
		}
		for _, p := range ports {
			b.WriteString("iptables -A OUTPUT -d " + target + " -p tcp --dport " + strconv.Itoa(int(p)) + " -j ACCEPT\n")
			b.WriteString("iptables -A OUTPUT -d " + target + " -p udp --dport " + strconv.Itoa(int(p)) + " -j ACCEPT\n")
		}
	}
	for _, ip := range ips {
		allowTarget(ip)
	}
	for _, c := range cidrs {
		allowTarget(c)
	}
	b.WriteString("exec sleep infinity\n")
	return b.String(), nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupeUint16(in []uint16) []uint16 {
	seen := map[uint16]bool{}
	out := in[:0]
	for _, p := range in {
		if p > 0 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
