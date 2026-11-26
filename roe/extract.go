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

// reFileExt 常见文件扩展名——它们形似 TLD 但不是（实测任务 306：Config.xml
// 被拦 7 次、8028.dat、analyze2.py、t.txt……全是本地文件名）。hostLike 对
// "xxx.xml" 这类 token 无法与域名区分，这里显式排除；真域名不会以这些后缀
// 结尾（.xml/.py 等不在 IANA TLD 列表）。
var reFileExt = regexp.MustCompile(`(?i)\.(xml|json|py|dat|txt|log|bin|md|conf|cfg|yaml|yml|sh|html|js|css|csv|pcap|pyc|go|rs|ts|tsx|jsx|ini|toml|bak|tmp|out|err|tar|gz|bz2|xz|zip|7z|rar|img|iso|fw|pak|rom|cap|ubi|swu|dfu|enc|std|doc|pdf|xls)$`)

// reCurl：curl/wget —— 它们的位置参数几乎必是 URL/主机，全 token 扫描。
var reCurl = regexp.MustCompile(`(?:^|\s)(?:curl|wget)\b`)

// reNetTool 已知网络工具：第 3 类（非 curl 命令）只对含这些工具的命令做位置
// 参数提取。此前对任意命令全 token 扫描，python/gcc/xxd 的参数（文件名、
// import 路径）大量误入——实测任务 306：python 密码分析被拦 4 次全是
// Config.xml / xml.etree.ElementTree / cryptography.hazmat... 这类误报。
var reNetTool = regexp.MustCompile(`(?i)(?:^|\s)(nmap|dig|nslookup|host|ssh|scp|sftp|nc|netcat|ping|ping6|traceroute|tracepath|whois|ftp|telnet|openssl|ncat)\b`)

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
		// 常见文件扩展名不是 TLD——本地文件名（Config.xml / analyze2.py…）
		// 在这里排除，避免被 hostLike 当成域名拦下。
		if reFileExt.MatchString(s) {
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
	// 3) 其它已知网络工具：只有命令里出现网络工具时才扫主机型位置参数——
	//    python/gcc/xxd 等非网络工具的参数（文件名、import 路径）不再是目标
	//    （实测任务 306：python 密码分析被拦 4 次全为文件名/import 误报）。
	if reNetTool.MatchString(raw) {
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
	}
	return out
}
