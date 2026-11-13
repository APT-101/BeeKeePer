package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/events"
	"github.com/Autumn-27/artex/policy"
)

// fixedResolver returns a fixed tier for tests.
func fixedResolver(level policy.Level) func(context.Context) (policy.Level, bool) {
	return func(context.Context) (policy.Level, bool) { return level, true }
}

func TestPolicyGateDisabledByDefault(t *testing.T) {
	// No resolver → pre-M1 behavior: everything allowed through the gate.
	g := New()
	b, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -X POST -d a=1 http://target/"}`))
	if b {
		t.Fatalf("default gate should not block, msg=%q", msg)
	}
}

func TestPolicyGatePassiveDeniesWrite(t *testing.T) {
	g := New()
	g.SetPolicyResolver(fixedResolver(policy.Passive))
	g.SetEventPublisher(func(events.Event) {})
	b, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -X POST -d a=1 http://target/login"}`))
	if !b {
		t.Fatal("passive gate must deny a POST via Bash")
	}
	if msg == "" {
		t.Fatal("block message must be non-empty")
	}
}

func TestPolicyGatePassiveAllowsRecon(t *testing.T) {
	g := New()
	g.SetPolicyResolver(fixedResolver(policy.Passive))
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"dig example.com A +short"}`))
	if b {
		t.Fatal("passive gate must allow read-only recon")
	}
}

func TestPolicyGateActiveAsks(t *testing.T) {
	// Active + no interceptor wired → approval impossible → fail-safe deny.
	g := New()
	g.SetPolicyResolver(fixedResolver(policy.Active))
	b, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"nmap -sS target"}`))
	if !b {
		t.Fatal("active gate without approval channel must fail safe to block")
	}
	if msg == "" {
		t.Fatal("block message must be non-empty")
	}
}

func TestPolicyGateFullFallsThrough(t *testing.T) {
	g := New()
	g.SetPolicyResolver(fixedResolver(policy.Full))
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"rm -rf /"}`))
	if b {
		t.Fatal("full tier must fall through to the existing chain (no block here)")
	}
}

func TestPolicyGateUnknownTaskFallsThrough(t *testing.T) {
	g := New()
	g.SetPolicyResolver(func(context.Context) (policy.Level, bool) { return "", false })
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Write",
		json.RawMessage(`{"path":"/tmp/x"}`))
	if b {
		t.Fatal("unknown task (ok=false) must fall through")
	}
}
