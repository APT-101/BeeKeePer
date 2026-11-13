package metrics

import (
	"strings"
	"testing"
)

func TestCounterGaugeBasics(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("artex_tool_calls_total", "tool calls", "tool", "agent")
	c.Inc(1, "Bash", "worker")
	c.Inc(1, "Bash", "worker")
	c.Inc(1, "graph_overview", "planner")

	if got := c.Get("Bash", "worker"); got != 2 {
		t.Errorf("Bash counter = %v, want 2", got)
	}
	if got := c.Get("graph_overview", "planner"); got != 1 {
		t.Errorf("graph counter = %v, want 1", got)
	}
	if got := c.Get("other", "worker"); got != 0 {
		t.Errorf("untouched combo = %v, want 0", got)
	}

	g := r.Gauge("artex_tasks_running", "running tasks")
	g.Set(3)
	g.Add(1)
	if got := g.Get(); got != 4 {
		t.Errorf("gauge = %v, want 4", got)
	}
}

func TestTextFormat(t *testing.T) {
	r := NewRegistry()
	r.Counter("artex_events_published_total", "published events", "kind").
		Inc(2, "tool_called")
	r.Gauge("artex_tasks_running", "running tasks").Set(1)

	out := r.Text()
	for _, want := range []string{
		"# HELP artex_events_published_total published events",
		"# TYPE artex_events_published_total counter",
		`artex_events_published_total{kind="tool_called"} 2`,
		"# TYPE artex_tasks_running gauge",
		"artex_tasks_running 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q in:\n%s", want, out)
		}
	}
}

func TestLabelArityPanics(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("m_total", "", "a", "b")
	defer func() {
		if recover() == nil {
			t.Error("expected panic on bad label arity")
		}
	}()
	c.Inc(1, "only-one")
}

func TestSameNameReturnsSameHandle(t *testing.T) {
	r := NewRegistry()
	a := r.Counter("x_total", "h")
	b := r.Counter("x_total", "h2") // help ignored on reuse
	// Handles wrap the same underlying metric: mutate through a, observe through b.
	a.Inc(3)
	if got := b.Get(); got != 3 {
		t.Errorf("b.Get() = %v, want 3 (same underlying metric)", got)
	}
	// A gauge registered under an existing counter name stays a counter; reuse
	// semantics are documented as "first registration wins".
	r.Gauge("x_total", "ignored")
	if strings.Contains(r.Text(), "# TYPE x_total gauge") {
		t.Error("gauge registration must not overwrite an existing counter type")
	}
}
