package sandbox

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Mode
		err  bool
	}{
		{"", ModeOff, false},
		{"off", ModeOff, false},
		{"host", ModeHost, false},
		{"container", ModeContainer, false},
		{"namespace", ModeNamespace, false},
		{"HOST", ModeHost, false},
		{"weird", "", true},
	} {
		got, err := ParseMode(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("ParseMode(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseMode(%q) = %v,%v want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestNewProviderHost(t *testing.T) {
	p, err := NewProvider(ModeOff)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type() != "host" || p.Degraded() {
		t.Errorf("off provider should be non-degraded host, got type=%s degraded=%v", p.Type(), p.Degraded())
	}
	p2, _ := NewProvider(ModeHost)
	if !p2.Degraded() {
		t.Error("host mode must be flagged degraded")
	}
}

func TestNewProviderContainerFailsClosed(t *testing.T) {
	if _, err := NewProvider(ModeContainer); err == nil {
		t.Fatal("container provider must fail closed when not compiled in")
	}
	if _, err := NewProvider(ModeNamespace); err == nil {
		t.Fatal("namespace provider must fail closed when not compiled in")
	}
}

func TestHostExecEcho(t *testing.T) {
	s, err := NewHost().New(context.Background(), "t1", Spec{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	res, err := s.Exec(context.Background(), ExecRequest{Cmd: "echo hello-sandbox", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "hello-sandbox") {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestHostExecExitCodeAndTimeout(t *testing.T) {
	s, _ := NewHost().New(context.Background(), "t2", Spec{})
	defer s.Close(context.Background())
	res, err := s.Exec(context.Background(), ExecRequest{Cmd: "exit 7", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", res.ExitCode)
	}
	_, err = s.Exec(context.Background(), ExecRequest{Cmd: longSleepCmd(), Timeout: 300 * time.Millisecond})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("unexpected error: %v", err)
	}
}

// longSleepCmd returns a command that blocks for a few seconds on any platform
// (deliberately shorter than the wait for the kill: Windows does not terminate
// the child tree, so the shell reaps the ping before Wait returns).
func longSleepCmd() string {
	if runtime.GOOS == "windows" {
		return "ping -n 3 127.0.0.1 >nul"
	}
	return "sleep 3"
}

func TestHostWriteRead(t *testing.T) {
	s, _ := NewHost().New(context.Background(), "t3", Spec{})
	defer s.Close(context.Background())
	dir := t.TempDir()
	path := dir + "/probe.txt"
	if err := s.WriteFile(context.Background(), path, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := s.ReadFile(context.Background(), path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "evidence" {
		t.Errorf("read back %q", b)
	}
}
