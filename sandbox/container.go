package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DockerRunner abstracts the docker operations a container sandbox needs. The
// production implementation talks to the local docker CLI; tests inject a fake.
// Keeping this behind an interface lets the whole provider be unit-tested
// WITHOUT a docker daemon on the host (docs §8.3: host-side dev / server-side
// acceptance).
type DockerRunner interface {
	// Ping verifies the docker daemon is reachable. Any error → provider must
	// fail closed (no silent fallback to host execution).
	Ping(ctx context.Context) error
	// Create starts a detached container from the config and returns its id.
	Create(ctx context.Context, cfg ContainerConfig) (string, error)
	// Exec runs one command inside the container.
	Exec(ctx context.Context, spec ExecSpec) (ExecResult, error)
	// Remove deletes the container (force).
	Remove(ctx context.Context, id string) error
}

// ContainerConfig is the docker run parameter set. Field names mirror the CLI
// flags so the mapping stays explicit and testable.
type ContainerConfig struct {
	ID       string
	Image    string
	CapDrop  []string
	CapAdd   []string // e.g. ["NET_ADMIN"] — netns-local iptables for egress whitelisting
	ReadOnly bool
	Tmpfs    []string // e.g. ["/tmp"]
	Binds    []string // host:container:mode, e.g. ["/host/work:/workspace:ro"]
	Env      []string
	Network  string   // "" | "host" (default bridge when empty)
	Entry    []string // container main process (docker run IMAGE entry...)
}

// ExecSpec is one docker exec invocation.
type ExecSpec struct {
	ContainerID string
	WorkDir     string
	Env         []string
	Cmd         []string // ["/bin/sh","-c",<cmd>]
	Stdin       []byte
	Timeout     time.Duration
	MaxOut      int64
}

// containerExecResult merges captured stdout/stderr from docker CLI.
func (es ExecSpec) deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	t := es.Timeout
	if t <= 0 {
		t = 120 * time.Second
	}
	return context.WithTimeout(ctx, t)
}

// dockerCLI is the production runner driving the local docker CLI.
type dockerCLI struct{}

// NewDockerCLI returns a DockerRunner over the docker CLI on PATH.
func NewDockerCLI() DockerRunner { return dockerCLI{} }

func (dockerCLI) Ping(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker daemon unreachable: %w", err)
	}
	if strings.TrimSpace(out.String()) == "" {
		return errors.New("docker daemon unreachable: empty server version")
	}
	return nil
}

func (dockerCLI) Create(ctx context.Context, cfg ContainerConfig) (string, error) {
	args := []string{"run", "-d"}
	if cfg.ID != "" {
		args = append(args, "--name", cfg.ID)
	}
	for _, c := range cfg.CapDrop {
		args = append(args, "--cap-drop", c)
	}
	for _, c := range cfg.CapAdd {
		args = append(args, "--cap-add", c)
	}
	if cfg.ReadOnly {
		args = append(args, "--read-only")
	}
	for _, t := range cfg.Tmpfs {
		args = append(args, "--tmpfs", t)
	}
	for _, b := range cfg.Binds {
		args = append(args, "-v", b)
	}
	for _, e := range cfg.Env {
		args = append(args, "-e", e)
	}
	if cfg.Network != "" && cfg.Network != "egress" {
		args = append(args, "--network", cfg.Network)
	}
	args = append(args, cfg.Image)
	args = append(args, cfg.Entry...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker run: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	id := strings.TrimSpace(out.String())
	if id == "" {
		return "", errors.New("docker run returned empty container id")
	}
	return id, nil
}

func (dockerCLI) Exec(ctx context.Context, spec ExecSpec) (ExecResult, error) {
	cctx, cancel := spec.deadline(ctx)
	defer cancel()
	args := []string{"exec"}
	if spec.WorkDir != "" {
		args = append(args, "-w", spec.WorkDir)
	}
	for _, e := range spec.Env {
		args = append(args, "-e", e)
	}
	args = append(args, spec.ContainerID)
	args = append(args, spec.Cmd...)
	cmd := exec.CommandContext(cctx, "docker", args...)
	if len(spec.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	maxOut := spec.MaxOut
	if maxOut <= 0 {
		maxOut = maxOutputDefault
	}
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	start := time.Now()
	err := cmd.Run()
	res := ExecResult{
		Stdout:   truncateBytes(so.Bytes(), maxOut),
		Stderr:   truncateBytes(se.Bytes(), maxOut),
		Duration: time.Since(start),
	}
	if cctx.Err() == context.DeadlineExceeded {
		return res, errors.New("sandbox exec timed out after " + spec.Timeout.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("docker exec failed: %w", err)
	}
	return res, nil
}

func (dockerCLI) Remove(ctx context.Context, id string) error {
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", id)
	var se bytes.Buffer
	cmd.Stderr = &se
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker rm: %v: %s", err, strings.TrimSpace(se.String()))
	}
	return nil
}

// ContainerProvider creates one container per task (lazily, on first sandbox
// use). Type()=="container", not degraded. New fails CLOSED when the docker
// daemon is unavailable — callers surface the error / red banner rather than
// falling back to host execution.
type ContainerProvider struct {
	Runner DockerRunner
}

// NewContainer builds a container provider with an explicit runner (tests inject
// a fake; production passes sandbox.NewDockerCLI()).
func NewContainer(runner DockerRunner) Provider {
	return &ContainerProvider{Runner: runner}
}

func (p *ContainerProvider) Type() string   { return "container" }
func (p *ContainerProvider) Degraded() bool { return false }

// New pings the daemon, then creates the task container. The container is kept
// running (sleep infinity) so successive Execs share one instance.
func (p *ContainerProvider) New(ctx context.Context, taskID string, spec Spec) (Sandbox, error) {
	if p.Runner == nil {
		return nil, errors.New("container provider: nil runner")
	}
	if err := p.Runner.Ping(ctx); err != nil {
		return nil, err // fail closed: no silent fallback
	}
	img := spec.Image
	if img == "" {
		img = "artex-sandbox:latest"
	}
	if spec.Network == "host" {
		return nil, errors.New("container provider: network=host 被禁用（egress 强制要求默认 bridge）")
	}
	id := sanitizeContainerName("artex-sb-" + taskID)
	// read-only rootfs 在 container 提供者下恒为 true（独占语义，防误关）：容器只
	// 有 tmpfs /tmp 可写，宿主数据一律只读挂载。host/off 提供者仍直接读写宿主。
	cfg := ContainerConfig{
		ID:       id,
		Image:    img,
		CapDrop:  capList(spec.CapDrop),
		ReadOnly: true,
		Env:      spec.EnvAllow,
		Entry:    []string{"sleep", "infinity"},
	}
	// M1 L4 出口白名单（docs §3.3 网络级强制）：容器 netns 内 iptables 默认
	// OUTPUT DROP，只放行回环/已建立连接/嵌入式 DNS(127.0.0.11) 与白名单目标
	// （spec.Egress 规则：域解析为 IP、IP、CIDR、端口）。需要 NET_ADMIN（仅
	// 作用于容器自身 netns，不影响宿主）。规则失败时容器整体 fail-closed
	// 拒绝创建（iptables 就绪前不放行任何流量）。
	if len(spec.Egress) > 0 {
		script, err := buildEgressEntry(spec.Egress)
		if err != nil {
			return nil, fmt.Errorf("egress policy 无法编译为容器规则: %w", err)
		}
		cfg.CapAdd = append(cfg.CapAdd, "NET_ADMIN")
		cfg.Entry = []string{"sh", "-c", script}
	}
	// 可写 scratch 区（readonly rootfs 下唯一可写目录）。tmpfs 保证容器停止后
	// 即销毁；/workspace 与 /skills 只读挂载宿主数据。
	cfg.Tmpfs = []string{"/tmp"}
	if spec.Workspace != "" {
		cfg.Binds = append(cfg.Binds, spec.Workspace+":/workspace:ro")
	}
	if spec.SkillsDir != "" {
		cfg.Binds = append(cfg.Binds, spec.SkillsDir+":/skills:ro")
	}
	cid, err := p.Runner.Create(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &containerSandbox{runner: p.Runner, id: cid, spec: spec}, nil
}

func capList(caps []string) []string {
	c := append([]string{}, caps...)
	if len(c) == 0 {
		return []string{"ALL"}
	}
	return c
}

// sanitizeContainerName replaces characters docker disallows in container names.
// Input is always "artex-sb-"+numericTaskID, so the first character is already
// alphanumeric; this is a safety net for unusual task ids.
func sanitizeContainerName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "artex-sb"
	}
	return out
}

type containerSandbox struct {
	runner DockerRunner
	id     string
	spec   Spec
}

func (s *containerSandbox) Exec(ctx context.Context, req ExecRequest) (ExecResult, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	spec := ExecSpec{
		ContainerID: s.id,
		WorkDir:     req.WorkDir,
		Env:         req.Env,
		Cmd:         []string{"/bin/sh", "-c", req.Cmd},
		Stdin:       req.Stdin,
		Timeout:     timeout,
		MaxOut:      req.MaxOut,
	}
	return s.runner.Exec(ctx, spec)
}

func (s *containerSandbox) WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	enc := base64.StdEncoding.EncodeToString(data)
	cmd := "mkdir -p " + shellQuote(dirOf(path)) + " && base64 -d > " + shellQuote(path)
	_, err := s.runner.Exec(ctx, ExecSpec{
		ContainerID: s.id,
		Cmd:         []string{"/bin/sh", "-c", cmd},
		Stdin:       []byte(enc),
		Timeout:     30 * time.Second,
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *containerSandbox) ReadFile(ctx context.Context, path string, max int64) ([]byte, error) {
	res, err := s.runner.Exec(ctx, ExecSpec{
		ContainerID: s.id,
		Cmd:         []string{"/bin/sh", "-c", "base64 < " + shellQuote(path)},
		Timeout:     30 * time.Second,
		MaxOut:      max*2 + 1024, // base64 inflates 4/3
	})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox read %s: exit %d: %s", path, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(res.Stdout)))
	if err != nil {
		return nil, fmt.Errorf("sandbox read %s: bad base64 payload: %w", path, err)
	}
	if max > 0 && int64(len(b)) > max {
		return b[:max], nil
	}
	return b, nil
}

func (s *containerSandbox) Probe(ctx context.Context, host string, port uint16, timeout time.Duration) (bool, error) {
	// 容器与宿主共享宿主出口网络；可达性探针由宿主 TCP 直连完成（不产生 shell）。
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return false, nil // 不可达/关闭是探测结果而非错误
	}
	_ = conn.Close()
	return true, nil
}

func (s *containerSandbox) Close(ctx context.Context) error {
	if s.id == "" {
		return nil
	}
	if err := s.runner.Remove(ctx, s.id); err != nil {
		return err
	}
	s.id = ""
	return nil
}

func dirOf(path string) string {
	i := strings.LastIndexAny(path, "/\\")
	if i <= 0 {
		return "./"
	}
	return path[:i]
}

// shellQuote wraps s in single quotes for /bin/sh, escaping embedded quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
