// Package events implements the platform event bus (M0, docs/platformization-plan-v1.md §3.1).
//
// It weaves every interesting occurrence in the agent runtime — tool calls,
// approvals, planner rounds, findings, config changes — into one typed,
// correlation-aware stream. Consumers count metrics, feed audit trails and
// export to webhooks/SIEM. The enforcement semantics of the underlying
// subsystems are unchanged: the bus is strictly observational.
//
// Design notes:
//   - Publish is fire-and-forget. Persist sinks run synchronously (a failure is
//     logged, never blocks the publisher); fan-out to subscribers is async with
//     bounded buffers and drop-on-full (counted, observable via Stats).
//   - Per-subscriber FIFO ordering is preserved (single consumer goroutine per
//     subscription); no cross-subscriber ordering guarantees.
//   - Correlation: events published under a context carrying a correlation id
//     (WithCorr) inherit it as ParentID unless the event already sets one.
package events

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Kind identifies one event class. New kinds are added as subsystems grow
// (M1 sandbox/egress, ADR-003 escalation) without breaking existing consumers.
type Kind string

const (
	EvSessionStarted    Kind = "session_started"
	EvPlannerRound      Kind = "planner_round"
	EvIntentClaimed     Kind = "intent_claimed"
	EvIntentFinished    Kind = "intent_finished"
	EvToolCalled        Kind = "tool_called"
	EvToolResult        Kind = "tool_result"
	EvToolDenied        Kind = "tool_denied"
	EvApprovalRequested Kind = "approval_requested"
	EvApprovalDecided   Kind = "approval_decided"
	EvFindingReported   Kind = "finding_reported"
	EvConfigChanged     Kind = "config_changed"

	// M1 / ADR-003 reservations — unused until those milestones land.
	EvEgressViolation Kind = "egress_violation"
	EvSandboxCreated  Kind = "sandbox_created"
	EvTaskTimeout     Kind = "task_timeout"
	EvEscalation      Kind = "escalation"
)

// Event is one platform occurrence. ID forms the leaf of a correlation chain:
// an intent's tool call, its approval and its result share ParentID links back
// to the chain head. All fields are JSON-friendly for webhook/SIEM export.
type Event struct {
	ID        string    `json:"id"`
	ParentID  string    `json:"parent_id,omitempty"`
	Kind      Kind      `json:"kind"`
	TaskID    string    `json:"task_id,omitempty"`
	IntentID  int64     `json:"intent_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	TS        time.Time `json:"ts"`
	Payload   any       `json:"payload,omitempty"`
}

// Now returns the timestamp applied to new events. Overridable in tests.
var Now = time.Now

// NewEvent builds an event with a fresh RFC4122 id and a now timestamp.
func NewEvent(kind Kind) Event {
	return Event{ID: uuid.NewString(), Kind: kind, TS: Now()}
}

// --- correlation id propagation ------------------------------------------------

type corrKey struct{}

// WithCorr returns a context carrying corrID. Events published under it inherit
// the id as ParentID when the event does not carry its own.
func WithCorr(ctx context.Context, corrID string) context.Context {
	if corrID == "" {
		return ctx
	}
	return context.WithValue(ctx, corrKey{}, corrID)
}

// CorrFrom returns the correlation id carried by ctx ("" when absent).
func CorrFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(corrKey{}).(string)
	return v
}
