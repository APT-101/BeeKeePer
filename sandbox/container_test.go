package sandbox

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/roe"
)

// fakeRunner records docker operations so the provider's parameter mapping is
// assertable without a docker daemon (docs §8.3 host-side development).
type fakeRunner struct {
	pingErr     error
	createID    string
	createCalls []ContainerConfig
	execCalls   []ExecSpec
	execResult  ExecResult
	execErr     error
	removeCalls []string
}

func (f *fakeRunner) Ping(ctx context.Context) error { return f.pingErr }

func (f *fakeRunner) Create(ctx context.Context, cfg ContainerConfig) (string, error) {
	f.createCalls = append(f.createCalls, cfg)
	if f.createID != "" {
		return f.createID, nil
	}
	return "cid-1", nil
}

func (f *fakeRunner) Exec(ctx context.Context, spec ExecSpec) (ExecResult, error) {
	f.execCalls = append(f.execCalls, spec)
	return f.execResult, f.execErr
}

func (f *fakeRunner) Remove(ctx context.Context, id string) error {
	f.removeCalls = append(f.removeCalls, id)
	return nil
}

func TestContainerProviderNewFailsClosedWithoutDocker(t *testing.T) {
	p := NewContainer(&fakeRunner{pingErr: errors.New("daemon down")})
	_, err := p.New(context.Background(), "7", Spec{})
	if err == nil || !strings.Contains(err.Error(), "daemon") {
		t.Fatalf("expected fail-closed ping error, got %v", err)
	}
}

func TestContainerProviderNewHardensContainer(t *testing.T) {
	f := &fakeRunner{createID: "cid-42"}
	p := NewContainer(f)
	sb, err := p.New(context.Background(), "7", Spec{
		Image: "artex-sandbox:latest", Workspace: "/host/work/dir", SkillsDir: "/opt/artex/skills",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sb == nil {
		t.Fatal("nil sandbox")
	}
	if len(f.createCalls) != 1 {
		t.Fatalf("want 1 create, got %d", len(f.createCalls))
	}
	c := f.createCalls[0]
	if c.ID != "artex-sb-7" {
		t.Errorf("container name = %q", c.ID)
	}
	if len(c.CapDrop) != 1 || c.CapDrop[0] != "ALL" {
		t.Errorf("cap_drop = %v, want [ALL]", c.CapDrop)
	}
	if !c.ReadOnly {
		t.Error("rootfs must be read-only")
	}
	if len(c.Tmpfs) != 1 || c.Tmpfs[0] != "/tmp" {
		t.Errorf("tmpfs = %v, want [/tmp]", c.Tmpfs)
	}
	joined := strings.Join(c.Binds, "|")
	if !strings.Contains(joined, "/host/work/dir:/workspace:ro") {
		t.Errorf("workspace bind missing: %v", c.Binds)
	}
	if !strings.Contains(joined, "/opt/artex/skills:/skills:ro") {
		t.Errorf("skills bind missing: %v", c.Binds)
	}
	if len(c.Entry) != 2 || c.Entry[0] != "sleep" || c.Entry[1] != "infinity" {
		t.Errorf("entry = %v", c.Entry)
	}
}

func TestContainerNewRejectsHostNetwork(t *testing.T) {
	f := &fakeRunner{}
	p := NewContainer(f)
	_, err := p.New(context.Background(), "7", Spec{Network: "host"})
	if err == nil || !strings.Contains(err.Error(), "禁用") {
		t.Fatalf("host network must be rejected, got %v", err)
	}
	if len(f.createCalls) != 0 {
		t.Fatal("container must not be created for rejected network")
	}
}

func TestContainerExecMapsArgs(t *testing.T) {
	f := &fakeRunner{execResult: ExecResult{Stdout: []byte("hello"), ExitCode: 7}}
	p := NewContainer(f)
	sb, err := p.New(context.Background(), "7", Spec{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sb.Exec(context.Background(), ExecRequest{
		Cmd: "echo hi", WorkDir: "/workspace", Env: []string{"A=1"},
		Timeout: 5 * time.Second, MaxOut: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 || string(res.Stdout) != "hello" {
		t.Fatalf("res = %+v", res)
	}
	if len(f.execCalls) != 1 {
		t.Fatalf("want 1 exec, got %d", len(f.execCalls))
	}
	sp := f.execCalls[0]
	if sp.ContainerID != "cid-1" {
		t.Errorf("container id = %q", sp.ContainerID)
	}
	if sp.WorkDir != "/workspace" || len(sp.Env) != 1 {
		t.Errorf("workdir/env = %q %v", sp.WorkDir, sp.Env)
	}
	if len(sp.Cmd) != 3 || sp.Cmd[0] != "/bin/sh" || sp.Cmd[2] != "echo hi" {
		t.Errorf("cmd = %v", sp.Cmd)
	}
	if sp.Timeout != 5*time.Second || sp.MaxOut != 100 {
		t.Errorf("timeout/maxout = %v %d", sp.Timeout, sp.MaxOut)
	}
}

func TestContainerWriteReadFileRoundTrip(t *testing.T) {
	f := &fakeRunner{execResult: ExecResult{Stdout: []byte(base64.StdEncoding.EncodeToString([]byte("payload-1")))}}
	p := NewContainer(f)
	sb, err := p.New(context.Background(), "7", Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.WriteFile(context.Background(), "/tmp/scripts/x.sh", []byte("echo ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	if len(f.execCalls) != 1 {
		t.Fatalf("write: want 1 exec, got %d", len(f.execCalls))
	}
	w := f.execCalls[0]
	if !strings.Contains(w.Cmd[2], "mkdir -p '/tmp/scripts'") || !strings.Contains(w.Cmd[2], "base64 -d > '/tmp/scripts/x.sh'") {
		t.Errorf("write cmd = %q", w.Cmd[2])
	}
	if string(w.Stdin) != base64.StdEncoding.EncodeToString([]byte("echo ok")) {
		t.Errorf("write stdin = %q", string(w.Stdin))
	}
	f.execResult = ExecResult{Stdout: []byte(base64.StdEncoding.EncodeToString([]byte("payload-1")) + "\n")}
	got, err := sb.ReadFile(context.Background(), "/tmp/scripts/x.sh", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload-1" {
		t.Errorf("read = %q", string(got))
	}
	if len(f.execCalls) != 2 || !strings.Contains(f.execCalls[1].Cmd[2], "base64 < '/tmp/scripts/x.sh'") {
		t.Errorf("read cmd = %q", f.execCalls[1].Cmd[2])
	}
}

func TestContainerReadFileTruncates(t *testing.T) {
	big := "abcdefgh"
	f := &fakeRunner{execResult: ExecResult{Stdout: []byte(base64.StdEncoding.EncodeToString([]byte(big)))}}
	sb := &containerSandbox{runner: f, id: "cid-1"}
	got, err := sb.ReadFile(context.Background(), "/x", 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcd" {
		t.Errorf("truncated read = %q", string(got))
	}
}

func TestContainerCloseRemovesOnce(t *testing.T) {
	f := &fakeRunner{}
	sb := &containerSandbox{runner: f, id: "cid-1"}
	if err := sb.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sb.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.removeCalls) != 1 || f.removeCalls[0] != "cid-1" {
		t.Errorf("remove calls = %v", f.removeCalls)
	}
}

func TestSanitizeContainerName(t *testing.T) {
	cases := map[string]string{
		"artex-sb-7":   "artex-sb-7",
		"artex-sb-7.2": "artex-sb-7.2",
		"artex-sb-x y": "artex-sb-x-y",
	}
	for in, want := range cases {
		if got := sanitizeContainerName(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContainerProbe(t *testing.T) {
	f := &fakeRunner{}
	sb := &containerSandbox{runner: f, id: "cid-1"}
	// 探测不由 runner 执行（宿主 TCP 直连）；不可达 → (false, nil)。
	open, err := sb.Probe(context.Background(), "nonexistent.invalid", 80, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Error("nonexistent host must probe closed")
	}
	if len(f.execCalls) != 0 {
		t.Error("probe must not exec in the container")
	}
}

func TestContainerProviderNewInstallsEgressWhitelist(t *testing.T) {
	f := &fakeRunner{createID: "cid-eg"}
	p := NewContainer(f)
	sb, err := p.New(context.Background(), "7", Spec{
		Image:     "artex-sandbox:latest",
		Workspace: "/home/u/ws",
		Egress:    []roe.EgressRule{{IPs: []string{"10.0.0.5"}, CIDRs: []string{"192.168.8.0/24"}, Ports: []uint16{443}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sb == nil {
		t.Fatal("nil sandbox")
	}
	if len(f.createCalls) != 1 {
		t.Fatalf("want 1 create, got %d", len(f.createCalls))
	}
	c := f.createCalls[0]
	if len(c.CapAdd) != 1 || c.CapAdd[0] != "NET_ADMIN" {
		t.Errorf("cap_add = %v, want [NET_ADMIN]", c.CapAdd)
	}
	if len(c.Entry) != 3 || c.Entry[0] != "sh" || c.Entry[1] != "-c" {
		t.Fatalf("entry = %v", c.Entry)
	}
	script := c.Entry[2]
	for _, want := range []string{
		"iptables -P OUTPUT DROP",
		"iptables -A OUTPUT -o lo -j ACCEPT",
		"--ctstate ESTABLISHED,RELATED",
		"-p udp --dport 53 -j ACCEPT",
		"-d 10.0.0.5 -p tcp --dport 443 -j ACCEPT",
		"-d 10.0.0.5 -p udp --dport 443 -j ACCEPT",
		"-d 192.168.8.0/24 -p tcp --dport 443 -j ACCEPT",
		"exec sleep infinity",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("entry script missing %q:\n%s", want, script)
		}
	}
}

func TestBuildEgressEntryNoPortsAllowsAllPorts(t *testing.T) {
	script, err := buildEgressEntry([]roe.EgressRule{{IPs: []string{"10.0.0.5"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "-d 10.0.0.5 -j ACCEPT") {
		t.Errorf("no-port rule should allow the IP without port filters:\n%s", script)
	}
	if strings.Contains(script, "-d 10.0.0.5 -p tcp --dport") || strings.Contains(script, "-d 10.0.0.5 -p udp --dport") {
		t.Error("no-port rule must not emit --dport filters for the allowlist target")
	}
}

// 空白名单不再拒建容器（会堵死固件/离线审计的本地文件操作），改为生成
// "全禁"entry：OUTPUT 全 DROP、零放行目标——网络层 fail-closed 语义保留，
// 容器本身可用（实测任务 kali-sandbox-verify 因旧行为堵死全部沙箱命令）。
func TestBuildEgressEntryEmptyDenied(t *testing.T) {
	for _, rules := range [][]roe.EgressRule{
		{{Domains: []string{"definitely-not-a-real-host-xyz.invalid"}}},
		{},
	} {
		script, err := buildEgressEntry(rules)
		if err != nil {
			t.Fatalf("empty whitelist must produce a deny-all entry, got error: %v", err)
		}
		if !strings.Contains(script, "iptables -P OUTPUT DROP") {
			t.Errorf("deny-all entry must set OUTPUT policy DROP:\n%s", script)
		}
		// 除回环/已建立连接/DNS 之外，不得出现任何目标放行行
		for _, line := range strings.Split(script, "\n") {
			if strings.Contains(line, "-j ACCEPT") && !strings.Contains(line, "-o lo") &&
				!strings.Contains(line, "conntrack") && !strings.Contains(line, "--dport 53") {
				t.Errorf("deny-all entry must not allow any target, got line: %s", line)
			}
		}
		if !strings.Contains(script, "exec sleep infinity") {
			t.Errorf("deny-all entry must still keep the container alive:\n%s", script)
		}
	}
}

func TestBuildEgressEntryRuleLimit(t *testing.T) {
	var many []string
	for i := 0; i < 60; i++ {
		many = append(many, "10.0."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1))
	}
	_, err := buildEgressEntry([]roe.EgressRule{{IPs: many, Ports: []uint16{80, 443, 22, 53, 8080, 8443, 9000, 3306, 5432, 6379, 27017}}})
	if err == nil {
		t.Fatal("oversized whitelist must fail closed")
	}
}
