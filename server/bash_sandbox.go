package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/roe"
	"github.com/Autumn-27/artex/sandbox"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// catastrophicBash mirrors norma's built-in Bash safety floor (NFR-10): a small
// set of irreversibly destructive commands hard-denied regardless of mode. The
// sandbox version keeps the identical floor so routing Bash through a container
// never weakens it. If norma tightens the list, this copy must follow (kept in
// sync deliberately — the originals are unexported).
var catastrophicBashRe = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*/(\s|$)`),
	regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;`),
	regexp.MustCompile(`\bmkfs\.\w+\s+/dev/`),
	regexp.MustCompile(`\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd)`),
}

// sandboxedBash builds the Bash tool routed through the M1 execution sandbox
// (docs §3.2). It is installed in place of the built-in Bash ONLY when
// ARTEX_SANDBOX=container; off/host keep the harness's original Bash (parity
// with the pre-M1 baseline). The permission chain stays identical (safety
// floor + AskUser); the guard's policy/egress gates run before this tool, as
// for every other tool. Known deviations vs the built-in Bash (docs §8.3):
//   - run_in_background is not supported: commands always run synchronously
//     with the exec timeout (no background task manager inside the sandbox);
//   - command output is capped at 64KiB (sandbox default);
//   - timeout does NOT auto-background; it kills the exec.
func (s *Server) sandboxedBash() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "Bash",
		Description: "在一个隔离沙箱容器中执行 shell 命令，返回合并的 stdout/stderr。用于跑测试/构建/包管理器/git/探测工具。" +
			"注意：沙箱容器内可写区只有 /tmp；宿主工作目录只读挂载于 /workspace。命令产物请通过 stdout 返回（写入容器内文件无法回流宿主）。",
		Prompt: "命令在沙箱容器内通过 shell 执行，不受单命令限制：可用 && / ; 串联、管道、heredoc。超时默认 120s、上限 600s，超时直接终止（不会转入后台）。" +
			"需要交互输入的程序无法使用（无 stdin 通道），请改用非交互写法。",
		Schema: objSchema(map[string]any{
			"command":    strParam("The shell command to execute."),
			"timeout_ms": map[string]any{"type": "integer", "description": "Timeout in ms (default 120000, max 600000)."},
		}, "command"),
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(c context.Context, input json.RawMessage, pc permission.Context) permission.Decision {
			var in struct {
				Command string `json:"command"`
			}
			_ = json.Unmarshal(input, &in)
			for _, re := range catastrophicBashRe {
				if re.MatchString(in.Command) {
					return permission.Denied("denied: command appears irreversibly destructive and is blocked by the safety floor")
				}
			}
			return permission.AskUser("run shell command in sandbox: " + in.Command)
		},
		Run: s.runSandboxedBash,
	})
}

func (s *Server) runSandboxedBash(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if s.m.SandboxProvider() == nil || s.m.SandboxProvider().Type() != "container" {
		return actool.Errorf("Bash 沙箱未启用（ARTEX_SANDBOX 非 container）"), nil
	}
	var in struct {
		Command   string `json:"command"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return actool.Errorf("参数解析失败: " + err.Error()), nil
	}
	if strings.TrimSpace(in.Command) == "" {
		return actool.Errorf("Error: command is required"), nil
	}
	timeout := 120 * time.Second
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
		if timeout > 600*time.Second {
			timeout = 600 * time.Second
		}
	}
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return actool.Errorf("Bash(沙箱) 仅限任务运行上下文中使用"), nil
	}
	taskID := strconv.FormatInt(ri.TaskID, 10)
	spec := sandbox.Spec{
		Workspace: filepath.Join(s.m.dir, "tasks", taskID),
		SkillsDir: s.skillDir,
	}
	// L4 容器网络级白名单（docs §3.3）：规则来自任务 egress 编译结果，与 guard
	// egress 门双层一致。未编译/读取失败 → 零规则（网络层对全部出网 fail-closed，
	// 比命令层更严）。观察模式（deny_default=false）同样应用白名单（网络层无观察语义）。
	if e, eerr := s.m.pg.GetTaskEgress(ri.TaskID); eerr == nil && e != nil {
		spec.Egress = []roe.EgressRule{{
			Domains: e.AllowDomains, IPs: e.AllowIPs, CIDRs: e.AllowCIDRs,
			Ports: intsToUint16(e.AllowPorts),
		}}
	}
	sb, err := s.m.FetchSandbox(ctx, taskID, spec)
	if err != nil {
		// fail closed: 容器不可用 → Bash 拒用（红警语义，绝不静默退回宿主）。
		return actool.Errorf("沙箱不可用（container fail-closed）：" + err.Error()), nil
	}
	if sb == nil {
		return actool.Errorf("沙箱未就绪"), nil
	}
	var env []string
	if tc != nil {
		env = tc.Env
	}
	res, err := sb.Exec(ctx, sandbox.ExecRequest{Cmd: in.Command, Timeout: timeout, Env: env})
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			return actool.Errorf("沙箱命令超时（" + timeout.String() + "）"), nil
		}
		return actool.Errorf("沙箱执行失败: " + err.Error()), nil
	}
	out := strings.TrimSpace(string(res.Stdout))
	if se := strings.TrimSpace(string(res.Stderr)); se != "" {
		if out != "" {
			out += "\n"
		}
		out += se
	}
	if res.ExitCode != 0 {
		if out == "" {
			out = "(no output)"
		}
		return actool.Errorf(fmt.Sprintf("%s\n\n[exit code %d]", out, res.ExitCode)), nil
	}
	if out == "" {
		out = "(command produced no output)"
	}
	return actool.Text(out), nil
}
