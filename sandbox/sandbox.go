// Package sandbox implements the M1 execution-layer abstraction (docs §3.2):
// the host keeps tool handlers + orchestration, while execution primitives are
// forwarded to a sandbox runtime. This package defines the contract and ships
// the host provider (ARTEX_SANDBOX=host — same execution as the pre-M1
// baseline, flagged as degraded). Container/namespace providers slot in behind
// the same interface and fail closed when unavailable.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/roe"
)

// Spec declares one sandbox instance for a task.
type Spec struct {
	Image       string   // 默认 artex-sandbox:latest（container 提供者用）
	CapDrop     []string // 默认 ["ALL"]（container 提供者用）
	ReadOnlyFS  bool     // 默认 true（container 提供者用）
	Network     string   // "egress"(默认) | "host"(禁用项)
	Egress      []roe.EgressRule
	Workspace   string // 宿主 workDir（可写，任务间不共享）
	SkillsDir   string // 只读挂载
	EvidenceDir string // 只读导出
	EnvAllow    []string
	Limits      Limits
}

// Limits are resource caps applied by container providers (best effort).
type Limits struct {
	CPUs  int
	MemMB int
	Pids  int
}

// ExecRequest is one command execution forwarded into the sandbox.
type ExecRequest struct {
	Cmd       string
	Stdin     []byte
	Timeout   time.Duration
	MaxOut    int64 // 默认 64KiB
	WorkDir   string
	Env       []string
	PseudoTTY bool
}

// ExecResult is the outcome of one Exec.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	OOM      bool
	Duration time.Duration
}

// Sandbox is one task-scoped execution context.
type Sandbox interface {
	Exec(ctx context.Context, req ExecRequest) (ExecResult, error)
	WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error
	ReadFile(ctx context.Context, path string, max int64) ([]byte, error)
	Probe(ctx context.Context, host string, port uint16, timeout time.Duration) (open bool, err error)
	Close(ctx context.Context) error
}

// Provider creates task sandboxes. Type is one of "container" | "namespace" |
// "host"; Degraded reports whether execution currently runs on the host
// without isolation (the UI should show a persistent red banner then).
type Provider interface {
	Type() string
	Degraded() bool
	New(ctx context.Context, taskID string, spec Spec) (Sandbox, error)
}

// Mode is the ARTEX_SANDBOX value.
type Mode string

const (
	ModeContainer Mode = "container"
	ModeNamespace Mode = "namespace"
	ModeHost      Mode = "host"
	ModeOff       Mode = "off"
)

// ParseMode validates an ARTEX_SANDBOX value ("" = default off → host, parity
// with the pre-M1 baseline). Returns the canonical lowercase mode.
func ParseMode(v string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(v))); m {
	case "":
		return ModeOff, nil
	case ModeContainer, ModeNamespace, ModeHost, ModeOff:
		return m, nil
	}
	return "", fmt.Errorf("ARTEX_SANDBOX=%q: 必须是 container|namespace|host|off", v)
}

// NewProvider selects the provider for a mode. container/namespace are not
// compiled into this build: they FAIL CLOSED (caller keeps the pre-M1 path and
// surfaces the error / red banner) rather than silently degrading. off → the
// baseline host provider (non-degraded); host → the same execution but flagged
// degraded so operators see the isolation gap.
func NewProvider(mode Mode) (Provider, error) {
	switch mode {
	case ModeOff:
		return hostProviderOff{}, nil
	case ModeHost:
		return hostProvider{}, nil
	case ModeContainer, ModeNamespace:
		return nil, errors.New("sandbox provider " + string(mode) + " 未在当前构建中实现；请设 ARTEX_SANDBOX=off 或 host")
	}
	return nil, errors.New("invalid sandbox mode")
}

// hostProvider executes commands directly on the host (pre-M1 behavior).
// off-mode is not marked degraded (identical to baseline); host-mode is
// flagged degraded so operators see the isolation gap.
type hostProvider struct{}

func (hostProvider) Type() string   { return "host" }
func (hostProvider) Degraded() bool { return true }

// NewHost returns a non-degraded host provider (ARTEX_SANDBOX=off — baseline).
func NewHost() Provider { return hostProviderOff{} }

type hostProviderOff struct{}

func (hostProviderOff) Type() string   { return "host" }
func (hostProviderOff) Degraded() bool { return false }
func (hostProviderOff) New(ctx context.Context, taskID string, spec Spec) (Sandbox, error) {
	return &hostSandbox{spec: spec}, nil
}

// New returns a host sandbox for the spec (degraded provider path).
func (hostProvider) New(ctx context.Context, taskID string, spec Spec) (Sandbox, error) {
	return &hostSandbox{spec: spec}, nil
}

type hostSandbox struct{ spec Spec }

const maxOutputDefault = 64 << 10 // 64KiB

func (s *hostSandbox) Exec(ctx context.Context, req ExecRequest) (ExecResult, error) {
	start := time.Now()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	maxOut := req.MaxOut
	if maxOut <= 0 {
		maxOut = maxOutputDefault
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	shell, flag := shellCmd()
	cmd := exec.CommandContext(cctx, shell, append([]string{flag}, req.Cmd)...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	env := os.Environ()
	if len(req.Env) > 0 {
		env = mergeEnv(env, req.Env)
	}
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	if len(req.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}
	err := cmd.Run()

	res := ExecResult{
		Stdout:   truncateBytes(so.Bytes(), maxOut),
		Stderr:   truncateBytes(se.Bytes(), maxOut),
		Duration: time.Since(start),
	}
	if cctx.Err() == context.DeadlineExceeded {
		return res, errors.New("command timed out after " + timeout.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("failed to run command: %w", err)
	}
	return res, nil
}

func (s *hostSandbox) WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func (s *hostSandbox) ReadFile(ctx context.Context, path string, max int64) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if max > 0 && int64(len(b)) > max {
		return b[:max], nil
	}
	return b, nil
}

func (s *hostSandbox) Probe(ctx context.Context, host string, port uint16, timeout time.Duration) (bool, error) {
	// 宿主探针：TCP 直连尝试（探测不产生 shell，无需命令）。
	d := netDialer{timeout: timeout}
	return d.probeTCP(ctx, host, port)
}

func (s *hostSandbox) Close(ctx context.Context) error { return nil }

// netDialer wraps net.DialTimeout for Probe.
type netDialer struct{ timeout time.Duration }

// probeTCP reports whether a TCP connection to host:port succeeds within t.
func (d netDialer) probeTCP(ctx context.Context, host string, port uint16) (bool, error) {
	address := host + ":" + fmt.Sprint(port)
	timeout := d.timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, nil // 关闭/不可达不是错误，是探测结果
	}
	conn.Close()
	return true, nil
}

func shellCmd() (shell, flag string) {
	if runtime.GOOS == "windows" {
		return "cmd", "/C"
	}
	return "/bin/sh", "-c"
}

func mergeEnv(base, extra []string) []string {
	out := append([]string(nil), base...)
	return append(out, extra...)
}

func truncateBytes(b []byte, max int64) []byte {
	if int64(len(b)) > max {
		return b[:max]
	}
	return b
}
