// Package policy implements the M1 operation-policy tiers (docs §3.4): a
// per-task gate that maps a tool call onto allow / ask / deny before the
// existing intercept chain runs. The tiers are coarse (passive / active /
// full) and the classification is deliberately conservative: unknown tools
// and unclassifiable shell commands fall toward denial at lower tiers.
package policy

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Level is a task's operation-policy tier (tasks.op_policy).
type Level string

const (
	Passive Level = "passive" // 只读侦察：DNS/HTTP GET/文件读取；禁写目标、禁利用、禁爆破
	Active  Level = "active"  // 侦察 + 主动探测 + 轻度利用：扫描/爆破/写目标需审批
	Full    Level = "full"    // 现状基线：全放开，靠既有拦截门
)

// IsValid reports whether s is a defined tier.
func IsValid(s string) bool {
	switch Level(s) {
	case Passive, Active, Full:
		return true
	}
	return false
}

// Decision is the policy gate outcome: continue to the existing chain, degrade
// to approval, or hard-deny.
type Decision string

const (
	Allow Decision = "allow" // 放行到既有 intercept 链
	Ask   Decision = "ask"   // 降级为人工审批（active 下的扫描/爆破/写目标）
	Deny  Decision = "deny"  // 硬拒（passive 下的利用/爆破/写目标；未知工具）
)

// ToolCaps classifies one tool call for gating.
type ToolCaps struct {
	ReadonlyLocal bool // 本地只读（文件/仓库侦察）
	Network       bool // 出网（HTTP GET / DNS / 连接）
	SideEffect    bool // 写目标/利用/爆破/下载执行（被动禁止的一类）
}

// capsByTool is the static per-tool classification for known ARTEX tools.
// Platform-internal writes (report_finding, add_task_scope, upsert_*) are NOT
// side effects against the target — they are bookkeeping and stay allowed at
// every tier.
var capsByTool = map[string]ToolCaps{
	// 本地只读
	"Read": {ReadonlyLocal: true}, "Grep": {ReadonlyLocal: true},
	"Glob": {ReadonlyLocal: true}, "LS": {ReadonlyLocal: true},
	"MultiEdit": {ReadonlyLocal: true}, "Edit": {ReadonlyLocal: true},
	// 网络只读
	"WebFetch": {Network: true}, "web_search": {Network: true},
	"SearchWeb": {Network: true}, "fetch_url": {Network: true},
	// 平台内记账（非目标侧写操作，任何档位放行）
	"report_finding": {}, "add_task_scope": {}, "update_task_scope": {},
	"list_assets": {ReadonlyLocal: true}, "list_company": {ReadonlyLocal: true},
	"list_findings": {ReadonlyLocal: true}, "list_scope": {ReadonlyLocal: true},
	"list_skills": {ReadonlyLocal: true}, "list_custom_tools": {ReadonlyLocal: true},
	"list_mcp": {ReadonlyLocal: true}, "get_agent": {ReadonlyLocal: true},
	"list_agents": {ReadonlyLocal: true}, "get_company_assets": {ReadonlyLocal: true},
	"query_facts": {ReadonlyLocal: true}, "query_nodes": {ReadonlyLocal: true},
	"view_digest": {ReadonlyLocal: true}, "get_task_status": {ReadonlyLocal: true},
	"list_tasks": {ReadonlyLocal: true},
	// 明确的写/利用类（若被绑定到 agent）
	"Write": {SideEffect: true}, "shell_send": {SideEffect: true},
}

// command-side regexes: classify Bash / shell_open commands.
var (
	reScanTool    = regexp.MustCompile(`(?i)\b(nmap|masscan|zmap|nikto|wpscan|sqlmap|hydra|medusa|patator|msfconsole|msfvenom|metasploit|crackmapexec|cme|nbtscan|onesixtyone|gobuster|dirb|ffuf|wfuzz|subfinder|amass|dnsrecon|dnsenum|fierce|theharvester|whatweb|wafw00f|nikto|joomscan|drupalscan|burpsuite|sqlsus|uos|fscan|ratool)\b`)
	reWriteMethod = regexp.MustCompile(`(?i)(curl|wget|http|fetch|python|perl|ruby|node)[^\n]*\s(-X\s+(POST|PUT|DELETE|PATCH)|--data|-d\s+|--upload-file|-T\s+|--post-data|-O\s+.*\|\s*(sh|bash)|-o\s+[\w./]+\s*\|\s*(sh|bash)|/dev/tcp)`)
	reShellGrab   = regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\b.*\s(-e\s|--exec)|\bbash\s+-i\b|\bpython\s+-c\b.*\bimport\s+pty\b`)
	rePipeExec    = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n]*\|\s*(sh|bash|zsh|python|perl|node)\b`)
	reFileWrite   = regexp.MustCompile(`(?i)(^|;|&&|\|)\s*(echo|printf|cat)\b[^\n]*\s(>|>>)\s|(^|;|&&\||\|)\s*tee\s`)
	reNetworkCmd  = regexp.MustCompile(`(?i)\b(curl|wget|dig|nslookup|host|whois|ping|traceroute|nc|ncat|ssh|telnet|socat|openssl\s+s_client)\b`)
)

// classifyCommand inspects a shell command string and returns its caps.
// The classification is conservative: anything that can write/exploit/scan
// lands in SideEffect so lower tiers deny it.
func classifyCommand(cmd string) ToolCaps {
	switch {
	case reScanTool.MatchString(cmd):
		return ToolCaps{Network: true, SideEffect: true}
	case reShellGrab.MatchString(cmd):
		return ToolCaps{Network: true, SideEffect: true}
	case rePipeExec.MatchString(cmd):
		return ToolCaps{Network: true, SideEffect: true}
	case reWriteMethod.MatchString(cmd):
		return ToolCaps{Network: true, SideEffect: true}
	case reFileWrite.MatchString(cmd):
		return ToolCaps{SideEffect: true}
	case reNetworkCmd.MatchString(cmd):
		return ToolCaps{Network: true}
	default:
		// 只读/无副作用命令（ls/pwd/echo 无重定向/计算/字符串处理等）
		return ToolCaps{ReadonlyLocal: true}
	}
}

// capsFor resolves a tool call to its caps, inspecting the input for the
// shell-command tools. The bool reports whether the tool is known to the
// classifier; unknown tools (MCP, new custom tools) get zero caps with
// known=false so the gate can treat them conservatively.
func capsFor(tool string, input json.RawMessage) (ToolCaps, bool) {
	if c, ok := capsByTool[tool]; ok {
		return c, true
	}
	switch tool {
	case "Bash", "shell_open", "command", "script":
		var in struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(input, &in); err == nil && strings.TrimSpace(in.Command) != "" {
			return classifyCommand(in.Command), true
		}
		return ToolCaps{SideEffect: true}, true // 无法解析的命令输入 → 保守
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(input, &in); err == nil {
			return classifyCommand(in.Text), true
		}
		return ToolCaps{SideEffect: true}, true
	case "http":
		var in struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(input, &in); err == nil {
			switch strings.ToUpper(strings.TrimSpace(in.Method)) {
			case "", "GET", "HEAD", "OPTIONS":
				return ToolCaps{Network: true}, true
			default:
				return ToolCaps{Network: true, SideEffect: true}, true
			}
		}
		return ToolCaps{Network: true, SideEffect: true}, true
	}
	// 未知工具（MCP/自定义/新工具）：不给任何 read 标记 → 低档位 deny/ask
	return ToolCaps{}, false
}

// Gate decides one tool call under a task's policy tier. input may be nil for
// tools whose schema has no content worth inspecting (rare; treated as unknown).
func Gate(tool string, input json.RawMessage, level Level) (Decision, string) {
	if level == Full {
		return Allow, ""
	}
	caps, known := capsFor(tool, input)
	switch level {
	case Passive:
		// 只读侦察放行（含平台内记账工具）；一切可能写/利用/扫描的拒绝；未知工具拒绝。
		switch {
		case !known:
			return Deny, "操作政策档位为 passive：该工具不在只读白名单内（未知工具保守拒绝）。"
		case caps.SideEffect:
			return Deny, "操作政策档位为 passive：该操作超出只读侦察范围（禁写目标、禁利用、禁爆破）。"
		default:
			return Allow, ""
		}
	case Active:
		// 只读放行；扫描/爆破/写目标降级为审批；未知工具也降级审批。
		switch {
		case !known:
			return Ask, "操作政策档位为 active：该工具不在已知分类内，降级为人工审批。"
		case caps.SideEffect:
			return Ask, "操作政策档位为 active：该操作涉及主动探测/写目标，需要人工审批。"
		default:
			return Allow, ""
		}
	default:
		return Deny, "未知操作政策档位"
	}
}
