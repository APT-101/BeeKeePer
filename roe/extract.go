package roe

import (
	"encoding/json"
	"regexp"
	"strings"
)

// URL 轨道：任何命令内嵌的 scheme URL。
var reURL = regexp.MustCompile(`(?i)\b(?:https?|ftp)://([^/\s"'<>]+)`)

// hostLike：形似主机的 token —— 域名/IPv4/IPv6（含 : 特征）或 host:port。
// 故意收紧：纯数字、单字母、无所谓 `-`/`+` 前缀的选项参数都会被拒，
// 避免把 `-c 3`、`dig +short` 之类的选项参数误当成网络目标。
var reHostLike = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?\.)+(?:[a-zA-Z]{2,}|[0-9]{1,3})|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)(?::\d{1,5})?$`)

var reCurl = regexp.MustCompile(`(?:^|\s)(?:curl|wget)\b`)

// ExtractTargets pulls explicit network targets out of a tool call's input.
// tool ∈ Bash | shell_send | shell_open parses the command text; WebFetch /
// fetch_url / SearchWeb read their url fields. Returns host[:port] fragments,
// deduplicated and in first-seen order, ready for roe.Allow. Non-network tools
// and opaque input yield an empty slice (caller then skips egress checking).
// Extraction is deliberately conservative: an unrecognized or ambiguous target
// is skipped (fail-open at extraction, fail-closed at match via deny_default).
func ExtractTargets(tool string, input json.RawMessage) []string {
	var raw string
	switch tool {
	case "WebFetch", "fetch_url", "SearchWeb":
		var m map[string]any
		if err := json.Unmarshal(input, &m); err != nil {
			return nil
		}
		u, _ := m["url"].(string)
		if u == "" || strings.HasPrefix(u, "data:") {
			return nil
		}
		raw = u
	case "Bash", "shell_send", "shell_open":
		var m map[string]any
		if err := json.Unmarshal(input, &m); err != nil {
			return nil
		}
		cmd, _ := m["command"].(string)
		if cmd == "" {
			raw, _ = m["text"].(string)
		} else {
			raw = cmd
		}
	default:
		return nil
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		// 剥掉 userinfo（user:pass@ / user@），保留 host[:port]
		if i := strings.LastIndex(s, "@"); i >= 0 && !strings.Contains(s[:i], "/") {
			s = s[i+1:]
		}
		s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://"), "ftp://")
		s = strings.Trim(s, "[]")
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}
		if s == "" {
			return
		}
		if !reHostLike.MatchString(s) {
			return
		}
		key := strings.ToLower(s)
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}

	// 1) 任何位置的 scheme URL
	for _, m := range reURL.FindAllStringSubmatch(raw, -1) {
		add(m[1])
	}
	// 2) curl/wget：整条命令的主机型 token（URL 轨道之外的无 scheme 目标）
	if reCurl.MatchString(raw) {
		for _, tok := range strings.Fields(raw) {
			add(strings.Trim(tok, `"'`))
		}
		return out
	}
	// 3) 其它网络工具：第一个主机型位置参数（预筛同样剥 userinfo）
	for _, tok := range strings.Fields(raw) {
		if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "+") {
			continue
		}
		h := strings.Trim(tok, `"'`)
		if i := strings.LastIndex(h, "@"); i >= 0 && !strings.Contains(h[:i], "/") {
			h = h[i+1:]
		}
		if reHostLike.MatchString(h) {
			add(h)
			break
		}
	}
	return out
}
