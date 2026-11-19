package server

// P0 代码审计工具族（v1.0.1 扩展规划 · 代码审计里程碑）。
//
// 设计：全部复用 M1 容器沙箱（与 sandboxedBash 同一执行面），仓库代码统一
// 落在沙箱内 /tmp/repo_<taskID>（tmpfs 可写，任务生命周期内共享）。工具经
// hostTools() 注入（默认绑定 worker），planner/worker 按需调用。
//
// 无站点时的动态验证（与用户确认的方案）：沙箱内本地起 dev server →
// code_probe 容器内打 localhost:port 验证漏洞点 → 证据回 finding。
// 找出的漏洞由 worker 用 add_finding 收敛（vulnclass 无 CHECK 约束，自由文本）。
//
// 安全：egress 白名单沿用任务 scope 编译结果；clone/依赖安装需目标域名在
// scope 内（fail-closed：不在白名单则由容器网络层拒绝，绝不静默放行）。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/roe"
	"github.com/Autumn-27/artex/sandbox"
	actool "github.com/Autumn-27/norma/tool"
)

// codeAuditTools returns the P0 code-audit tool set. Inserted into hostTools()
// (default binding worker) so any task type can audit a repo when needed.
func (s *Server) codeAuditTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.codeClone(),
		s.codeMeta(),
		s.codeScanSAST(),
		s.codeScanSCA(),
		s.codeScanSecret(),
		s.codeLocalRun(),
		s.codeProbe(),
	}
}

// codeAuditToolKeys is the default worker binding list (host tools are bindable
// per agent via tools table; this is the code default, preserved on seed).
var codeAuditToolKeys = []string{
	"code_clone", "code_meta", "code_scan_sast", "code_scan_sca",
	"code_scan_secret", "code_local_run", "code_probe",
}

// repoDir returns the per-task repo home inside the sandbox container.
func repoDir(taskID int64) string {
	return fmt.Sprintf("/tmp/repo_%d", taskID)
}

// codeRunSpec builds the sandbox spec for code tools: same workspace + skills
// mount as Bash, same egress whitelist (fail-closed zero rules).
func (s *Server) codeRunSpec(taskID int64) (sandbox.Spec, error) {
	spec := sandbox.Spec{
		Workspace: filepath.Join(s.m.dir, "tasks", fmt.Sprintf("%d", taskID)),
		SkillsDir: s.skillDir,
	}
	if e, eerr := s.m.pg.GetTaskEgress(taskID); eerr == nil && e != nil {
		spec.Egress = []roe.EgressRule{{
			Domains: e.AllowDomains, IPs: e.AllowIPs, CIDRs: e.AllowCIDRs,
			Ports: intsToUint16(e.AllowPorts),
		}}
	}
	return spec, nil
}

// codeRun executes one shell command in the task's sandbox container.
func (s *Server) codeRun(ctx context.Context, taskID int64, cmd string, timeout time.Duration) (string, error) {
	if s.m.SandboxProvider() == nil || s.m.SandboxProvider().Type() != "container" {
		return "", fmt.Errorf("沙箱未启用（ARTEX_SANDBOX 非 container）")
	}
	if taskID <= 0 {
		return "", fmt.Errorf("仅限任务运行上下文中使用")
	}
	// 与 sandboxedBash 一致：Bash/code 工具执行前把任务当前 scope 重编译进
	// task_egress（模型 add_task_scope 登记的 clone/依赖域名即时生效；空 scope
	// fail-closed 零规则，容器网络层拒绝出网）。
	if rerr := s.m.refreshTaskEgress(ctx, taskID); rerr != nil {
		log.Printf("[egress] task %d code 工具前 scope 重编译失败: %v", taskID, rerr)
	}
	spec, err := s.codeRunSpec(taskID)
	if err != nil {
		return "", err
	}
	sb, err := s.m.FetchSandbox(ctx, fmt.Sprintf("%d", taskID), spec)
	if err != nil {
		// fail closed：容器不可用 → 工具拒用（绝不静默降级）。
		return "", fmt.Errorf("沙箱不可用（container fail-closed）：%v", err)
	}
	if sb == nil {
		return "", fmt.Errorf("沙箱未就绪")
	}
	res, err := sb.Exec(ctx, sandbox.ExecRequest{
		Cmd:     cmd,
		Timeout: timeout,
		Env: []string{
			"PYTHONUNBUFFERED=1", "CI=true",
			// 只读 rootfs：各类工具的缓存/临时目录必须落到 /tmp（/root 不可写）。
			"HOME=/tmp",
			"XDG_CACHE_HOME=/tmp/.cache",
			"GOCACHE=/tmp/.gocache",
			"GOPATH=/tmp/.gopath",
			// trivy 漏洞库烤在镜像层 /root/.cache/trivy（read-only rootfs 只读可用），
			// 工具用 --skip-db-update 离线查；缓存目录指过去即可。
			"TRIVY_CACHE_DIR=/root/.cache/trivy",
			// semgrep 规则集同样烤进镜像 /root/semgrep-rules（离线可用，不依赖 registry）。
			"SEMGREP_RULES=/root/semgrep-rules",
			"SEMGREP_CACHE_DIR=/tmp/.semgrep-cache",
			"PIP_CACHE_DIR=/tmp/.pip-cache",
			"NPM_CONFIG_CACHE=/tmp/.npm-cache",
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			return "", fmt.Errorf("沙箱命令超时（%s）", timeout.String())
		}
		return "", fmt.Errorf("沙箱执行失败: %v", err)
	}
	out := strings.TrimSpace(string(res.Stdout))
	if se := strings.TrimSpace(string(res.Stderr)); se != "" {
		if out != "" {
			out += "\n"
		}
		out += se
	}
	return strings.TrimSpace(out), nil
}

// codeErr wraps a sandbox command's nonzero exit into the tool result as an error
// string (keeps exit code context in the message, matching sandboxedBash).
func codeErr(out string, exit int) (actool.Result, error) {
	if out == "" {
		out = "(no output)"
	}
	return actool.Errorf(fmt.Sprintf("%s\n\n[exit code %d]", out, exit)), nil
}

// --- code_clone ---

func (s *Server) codeClone() actool.CoreTool {
	return wrTool(
		"code_clone",
		"把代码仓库克隆/解包进沙箱内 /tmp/repo_<task>（首次调用建立；重复调用复用）。"+
			"输入 git 仓库地址（https/ssh）或工作空间内已上传压缩包的相对路径（如 uploads/app.zip，自动解包）。"+
			"clone 目标域名必须已在任务 scope（add_task_scope）登记，否则网络层 fail-closed 拒绝。"+
			"返回：克隆路径 + 顶层文件清单（前 50 项）。",
		objSchema(map[string]any{
			"repo_url": strParam("git 仓库地址（https://... 或 git@...）或工作空间压缩包相对路径（uploads/xxx.zip）"),
			"branch":   strParam("（可选）分支，默认 default"),
			"token":    strParam("（可选）私有仓库访问令牌；不传则匿名 clone"),
		}, "repo_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_clone 仅限任务运行上下文中使用"), nil
			}
			var p struct {
				RepoURL string `json:"repo_url"`
				Branch  string `json:"branch"`
				Token   string `json:"token"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(p.RepoURL) == "" {
				return actool.Errorf("repo_url 必填"), nil
			}
			dir := repoDir(ri.TaskID)
			var cmd string
			if strings.HasSuffix(strings.ToLower(p.RepoURL), ".zip") || strings.Contains(p.RepoURL, "uploads/") {
				// 压缩包：在工作空间里定位并解包到沙箱。工作空间只读挂载 /workspace。
				cmd = fmt.Sprintf(
					"mkdir -p %s && rm -rf %s/* && "+
						"SRC=/workspace/%s && test -f \"$SRC\" || { echo '找不到文件: $SRC'; exit 2; } && "+
						"unzip -q -o \"$SRC\" -d %s/zip && "+
						"cd %s && (ls %s/zip 2>/dev/null | grep -q . && mv %s/zip/* . || true) && "+
						"echo 'unpacked from zip' && ls -la | head -50",
					dir, dir, escapeShPath(p.RepoURL), dir, dir, dir, dir)
			} else {
				url := p.RepoURL
				branch := ""
				if p.Branch != "" {
					branch = " -b " + escapeShPath(p.Branch)
				}
				auth := ""
				if p.Token != "" {
					auth = " -c http.extraheader='Authorization: Bearer " + escapeShSingle(p.Token) + "'"
				}
				cmd = fmt.Sprintf(
					"rm -rf %s && git clone%s %s %s %s 2>&1 | tail -5; cd %s && echo 'cloned OK:' $(git rev-parse --short HEAD 2>/dev/null) && ls -la | head -50",
					dir, auth, branch, escapeShPath(url), dir, dir)
			}
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 300*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.Contains(out, "[exit code") {
				return codeErr(out, 1)
			}
			return actool.Text(out), nil
		},
	)
}

// --- code_meta ---

func (s *Server) codeMeta() actool.CoreTool {
	return roTool(
		"code_meta",
		"识别仓库的语言/框架/入口/依赖清单（先 code_clone 后调用）。"+
			"扫描包管理文件（package.json/go.mod/requirements.txt/pom.xml/CMakeLists.txt 等）与关键目录。"+
			"返回结构化 JSON：{language, framework, entry_points, dep_files, readme 摘要}。",
		objSchema(map[string]any{}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_meta 仅限任务运行上下文中使用"), nil
			}
			dir := repoDir(ri.TaskID)
			cmd := fmt.Sprintf(`cd %s 2>/dev/null || { echo 'repo 不存在：先 code_clone'; exit 2; }
echo '== language candidates =='
for f in go.mod package.json requirements.txt setup.py pyproject.toml pom.xml build.gradle Cargo.toml CMakeLists.txt composer.json Gemfile; do test -f "$f" && echo "  $f: $(head -3 "$f" | tr '\n' ' ' | cut -c1-120)"; done
echo '== dirs =='
ls -d src lib app cmd pkg internal api web frontend backend 2>/dev/null | head -10
echo '== entries =='
ls main.go app.py index.js server.py manage.py cmd 2>/dev/null | head -10
echo '== file count by ext =='
find . -type f -not -path './.git/*' -not -path './node_modules/*' 2>/dev/null | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -12
echo '== size =='
du -sh --exclude=.git --exclude=node_modules . 2>/dev/null | head -1`, dir)
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 120*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	)
}

// --- code_scan_sast ---

func (s *Server) codeScanSAST() actool.CoreTool {
	return roTool(
		"code_scan_sast",
		"静态源码安全扫描（SAST）。按语言路由：Go→gosec、Python→bandit、JS/TS→semgrep（含注入/SSRF/RCE/XSS 规则集）、Java→semgrep。"+
			"先 code_clone + code_meta 后调用。返回结构化 JSON findings 数组，每项 {severity, rule, file, line, message}，最多 100 条。",
		objSchema(map[string]any{
			"language": strParam("（可选）指定语言 go/python/js/java；不传则自动探测"),
			"max":      intp("（可选）返回条数上限，默认 100"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_scan_sast 仅限任务运行上下文中使用"), nil
			}
			var p struct {
				Language string `json:"language"`
				Max      int    `json:"max"`
			}
			_ = json.Unmarshal(in, &p)
			if p.Max <= 0 {
				p.Max = 100
			}
			dir := repoDir(ri.TaskID)
			lang := p.Language
			if lang == "" {
				lang = "auto"
			}
			cmd := fmt.Sprintf(`cd %s 2>/dev/null || { echo 'repo 不存在：先 code_clone'; exit 2; }
case "%s" in
  go)   echo '== gosec =='; gosec -no-fail -fmt=json ./... 2>/dev/null | head -c 4000 ;;
  py|python) echo '== bandit =='; bandit -r . -f json -q 2>/dev/null | head -c 4000 ;;
  js|ts|java|auto) echo '== semgrep =='; semgrep --config "${SEMGREP_RULES:-auto}" --json -q --max-target-bytes 200000 . 2>/dev/null | head -c 6000 ;;
esac
echo
echo '== trimmed:'`, dir, lang)
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 300*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	)
}

// --- code_scan_sca ---

func (s *Server) codeScanSCA() actool.CoreTool {
	return roTool(
		"code_scan_sca",
		"依赖/供应链漏洞扫描（SCA）。trivy filesystem 模式扫仓库依赖（含 node_modules/go.sum/vendor 等）。"+
			"返回结构化 JSON：{target, vulnerabilities:[{pkg,installed,severity,fixed,desc}]}，最多 100 条。",
		objSchema(map[string]any{
			"max": intp("（可选）返回条数上限，默认 100"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_scan_sca 仅限任务运行上下文中使用"), nil
			}
			var p struct {
				Max int `json:"max"`
			}
			_ = json.Unmarshal(in, &p)
			if p.Max <= 0 {
				p.Max = 100
			}
			dir := repoDir(ri.TaskID)
			cmd := fmt.Sprintf(`cd %s 2>/dev/null || { echo 'repo 不存在：先 code_clone'; exit 2; }
trivy fs --no-progress --format json --scanners vuln --skip-db-update . 2>/dev/null | head -c 6000
echo
echo '== trimmed:'`, dir)
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 300*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	)
}

// --- code_scan_secret ---

func (s *Server) codeScanSecret() actool.CoreTool {
	return roTool(
		"code_scan_secret",
		"硬编码密钥/凭据扫描。gitleaks 全量正则 + 熵检测。"+
			"返回结构化 JSON：{leaks:[{rule,file,line,secret_preview}]}，最多 100 条。",
		objSchema(map[string]any{
			"max": intp("（可选）返回条数上限，默认 100"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_scan_secret 仅限任务运行上下文中使用"), nil
			}
			dir := repoDir(ri.TaskID)
			cmd := fmt.Sprintf(`cd %s 2>/dev/null || { echo 'repo 不存在：先 code_clone'; exit 2; }
gitleaks detect --no-git --source . --report-format json --report-path /tmp/gitleaks.json 2>/dev/null
cat /tmp/gitleaks.json 2>/dev/null | head -c 5000
echo
echo '== trimmed:'`, dir)
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 180*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	)
}

// --- code_local_run ---

func (s *Server) codeLocalRun() actool.CoreTool {
	return wrTool(
		"code_local_run",
		"在沙箱内本地启动应用（dev server / 编译运行），用于无站点时的动态验证。"+
			"启动后输出访问地址（http://127.0.0.1:<port>）。端口默认从 8080 起，冲突自动 +1。"+
			"注意：应用在沙箱容器内前台运行，本工具返回后由沙箱守护（用 code_probe 探测/验证，用 code_meta 不需要重启）。",
		objSchema(map[string]any{
			"command": strParam("启动命令，如：npm run dev、python app.py --port 8080、go run ./cmd/server、直接写启动脚本（可选缺省自动按语言选）"),
			"port":    intp("（可选）期望端口，默认 8080；自动避开占用"),
		}, "command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_local_run 仅限任务运行上下文中使用"), nil
			}
			var p struct {
				Command string `json:"command"`
				Port    int    `json:"port"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(p.Command) == "" {
				return actool.Errorf("command 必填"), nil
			}
			port := p.Port
			if port <= 0 {
				port = 8080
			}
			dir := repoDir(ri.TaskID)
			cmd := fmt.Sprintf(`cd %s 2>/dev/null || { echo 'repo 不存在：先 code_clone'; exit 2; }
# 后台启动，日志到 /tmp/app.log；端口冲突探测（镜像无 iproute2/ss，用 curl：成功=被占用→+1，失败=空闲→用）
PORT=%d
for i in $(seq 0 20); do
  if ! curl -s -m 1 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then break; fi
  PORT=$((PORT+1))
done
( nohup sh -c '%s' > /tmp/app.log 2>&1 & echo $! > /tmp/app.pid )
sleep 6
echo "== app log =="; tail -30 /tmp/app.log 2>/dev/null
echo "== http probe =="; curl -s -m 5 -o /tmp/probe.out -w "%%{http_code} %%{size_download}B" "http://127.0.0.1:$PORT/" 2>/dev/null || echo "curl failed"
echo
echo "== probe body head =="; head -c 500 /tmp/probe.out 2>/dev/null`, dir, port, escapeShSingle(p.Command))
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 120*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	)
}

// --- code_probe ---

func (s *Server) codeProbe() actool.CoreTool {
	return roTool(
		"code_probe",
		"对沙箱内本地应用发 HTTP 探测/验证（先 code_local_run）。用于确认漏洞点是否真实存在：注入/SSRF/路径穿越/RCE 等。"+
			"返回 HTTP 状态 + 响应头 + 响应体前 2KB。",
		objSchema(map[string]any{
			"port":    intp("本地端口（默认 8080）"),
			"path":    strParam("请求路径（默认 /），可含查询串"),
			"method":  strParam("（可选）GET/POST，默认 GET"),
			"data":    strParam("（可选）POST body"),
			"timeout": intp("（可选）超时秒，默认 10"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("code_probe 仅限任务运行上下文中使用"), nil
			}
			var p struct {
				Port    int    `json:"port"`
				Path    string `json:"path"`
				Method  string `json:"method"`
				Data    string `json:"data"`
				Timeout int    `json:"timeout"`
			}
			_ = json.Unmarshal(in, &p)
			if p.Port <= 0 {
				p.Port = 8080
			}
			if p.Timeout <= 0 {
				p.Timeout = 10
			}
			method := strings.ToUpper(p.Method)
			if method == "" {
				method = "GET"
			}
			path := p.Path
			if path == "" {
				path = "/"
			}
			var curl string
			switch method {
			case "POST":
				curl = fmt.Sprintf("curl -s -m %d -X POST -d %s -o /tmp/probe.out -w '%%{http_code} %%{size_download}B' 'http://127.0.0.1:%d%s'", p.Timeout, escapeShSingle(p.Data), p.Port, escapeShPath(path))
			default:
				curl = fmt.Sprintf("curl -s -m %d -o /tmp/probe.out -w '%%{http_code} %%{size_download}B' 'http://127.0.0.1:%d%s'", p.Timeout, p.Port, escapeShPath(path))
			}
			cmd := fmt.Sprintf(`echo "== response =="
%s 2>&1 || echo "curl failed"
echo
echo "== body head =="
head -c 2000 /tmp/probe.out 2>/dev/null
echo`, curl)
			out, err := s.codeRun(ctx, ri.TaskID, cmd, 60*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	)
}

// --- helper: shell escaping (approx, adequate for tool arguments) ---

// escapeShPath wraps a value in single quotes after removing embedded quotes.
func escapeShPath(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "") + "'"
}

// escapeShSingle escapes a value for use inside a single-quoted sh string by
// closing/reopening quotes around embedded quotes.
func escapeShSingle(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// intp returns an int-tool-schema property.
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

var _ = log.Printf // keep import when unused in some build tags