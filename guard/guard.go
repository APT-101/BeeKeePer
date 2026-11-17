// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/events"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/policy"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// ToolCallPayload is the payload of EvToolCalled / EvApprovalRequested.
type ToolCallPayload struct {
	Tool string `json:"tool"`
}

// ToolDenyPayload is the payload of EvToolDenied.
type ToolDenyPayload struct {
	Tool   string `json:"tool"`
	Reason string `json:"reason,omitempty"`
}

// EgressViolationPayload is the payload of EvEgressViolation (M1): scope
// containment was triggered for a tool call. Blocked=false means observe mode
// (deny_default=false) — the call proceeded but the violation was recorded.
type EgressViolationPayload struct {
	Tool    string `json:"tool"`
	Reason  string `json:"reason,omitempty"`
	Blocked bool   `json:"blocked"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor                         // optional; nil disables user-configured rules
	onEvent     func(events.Event)                             // M0 platform event bus; nil disables events
	policyRes   func(ctx context.Context) (policy.Level, bool) // M1 op-policy tier; nil disables the gate
	egressCheck EgressCheck                                    // M1 egress gate; nil disables
}

// SetPolicyResolver wires the M1 operation-policy gate. The resolver returns
// the current task's tier from the hook ctx, plus ok=false when the task is
// unknown or policy gating is off for this run. Passing nil (default) disables
// the gate entirely — the pre-M1 behavior is unchanged. The gate runs BEFORE
// the intercept chain and only hard-acts at non-full tiers; full/unknown tiers
// fall through to the existing chain untouched.
func (g *Guard) SetPolicyResolver(res func(ctx context.Context) (policy.Level, bool)) {
	g.policyRes = res
}

// EgressCheck decides whether a tool call targets outside the task's compiled
// egress scope. deny=true → the call is blocked and an EvEgressViolation is
// emitted; observe=true → the call proceeds (log-only / deny_default=false)
// but the violation is still emitted; both=false → in-scope or no network
// target. The check runs AFTER the op-policy gate and BEFORE the intercept
// chain. The provider is responsible for persisting egress_violations rows
// (the guard has no db access and stays a pure decision point).
type EgressCheck func(ctx context.Context, tool string, input json.RawMessage) (deny, observe bool, reason string)

// SetEgressChecker wires the M1 egress gate. Passing nil (default) disables it
// — the pre-M1 behavior is unchanged.
func (g *Guard) SetEgressChecker(c EgressCheck) { g.egressCheck = c }

// SetEventPublisher wires the platform event bus (M0). Passing nil disables
// event emission. The bus is strictly observational — no guard decision
// depends on it.
func (g *Guard) SetEventPublisher(pub func(events.Event)) { g.onEvent = pub }

// emit publishes e when a publisher is wired (nil-safe, never blocks).
func (g *Guard) emit(e events.Event) {
	if g.onEvent != nil {
		g.onEvent(e)
	}
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// NewWithPolicy builds a Guard with both user intercept rules and the M1
// operation-policy gate wired. pol may be nil (gate off) for parity with
// NewWithInterceptor.
func NewWithPolicy(ic *intercept.Interceptor, pol func(ctx context.Context) (policy.Level, bool)) *Guard {
	g := newGuard(ic)
	g.policyRes = pol
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	g.record(ev.ToolName, "allow", "", cmd)
	g.emit(events.Event{
		Kind:    events.EvToolCalled,
		Payload: ToolCallPayload{Tool: ev.ToolName},
	})
	// M1 operation-policy gate (docs §3.4): runs BEFORE the intercept chain.
	// At passive/active tiers a non-allow decision here short-circuits to block
	// or to the approval flow; full/unknown tiers fall through untouched.
	if g.policyRes != nil {
		if level, ok := g.policyRes(ctx); ok && level != policy.Full {
			dec, reason := policy.Gate(ev.ToolName, ev.Input, level)
			switch dec {
			case policy.Deny:
				g.emit(events.Event{
					Kind:    events.EvToolDenied,
					Payload: ToolDenyPayload{Tool: ev.ToolName, Reason: reason},
				})
				return g.block(ev.ToolName, systemBlockMessage(reason), cmd)
			case policy.Ask:
				if !g.policyAsk(ctx, ev.ToolName, ev.Input, reason) {
					g.emit(events.Event{
						Kind:    events.EvToolDenied,
						Payload: ToolDenyPayload{Tool: ev.ToolName, Reason: "审批未通过（操作政策档位要求审批）"},
					})
					return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（操作政策档位要求审批）"), cmd)
				}
			}
		}
	}
	// M1 egress gate (docs §3.3): AFTER the op-policy gate, BEFORE intercept
	// rules — scope containment outranks user rules but yields to tiering.
	if g.egressCheck != nil {
		deny, observe, reason := g.egressCheck(ctx, ev.ToolName, ev.Input)
		if deny || observe {
			g.emit(events.Event{
				Kind:    events.EvEgressViolation,
				Payload: EgressViolationPayload{Tool: ev.ToolName, Reason: reason, Blocked: deny},
			})
		}
		if deny {
			return g.block(ev.ToolName, systemBlockMessage(reason), cmd)
		}
	}
	return g.applyIntercept(ctx, ev)
}

// policyAsk implements the active-tier "degrade to approval" path by reusing
// the intercept approval flow. When no interceptor is wired (or the tool is
// not intercept-enabled) the gate fails SAFE: approval is impossible, so the
// call is denied rather than silently allowed.
func (g *Guard) policyAsk(ctx context.Context, tool string, input json.RawMessage, reason string) bool {
	if g.interceptor == nil || !g.interceptor.IsToolEnabled(tool) || ctx.Err() != nil {
		return false
	}
	dec := intercept.Decision{Action: "ask", Message: reason}
	convID := intercept.ConvIDFromContext(ctx)
	if !g.interceptor.HandleAsk(ctx, convID, dec, tool, input) {
		return false
	}
	g.emit(events.Event{
		Kind:    events.EvApprovalRequested,
		Payload: ToolCallPayload{Tool: tool},
	})
	return true
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		g.emit(events.Event{
			Kind:    events.EvToolDenied,
			Payload: ToolDenyPayload{Tool: ev.ToolName, Reason: dec.Message},
		})
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		g.emit(events.Event{
			Kind:    events.EvApprovalRequested,
			Payload: ToolCallPayload{Tool: ev.ToolName},
		})
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【BeeKeePer 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
