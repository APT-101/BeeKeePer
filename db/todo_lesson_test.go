package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestMarkTodoSatisfied covers the M2 dependency-loop auto-satisfy (docs §8.10):
// a fact landing in the graph upgrades matching pending/in_progress todos to
// completed, deterministically, without relying on the model's TodoWrite.
func TestMarkTodoSatisfied(t *testing.T) {
	skipNoPG(t)
	d, err := Open(mustTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	// 独立 exploration：满足 satisfied_by_fact_id 的 FK（需真实 graph 节点 id），
	// 段末整段删除（无 task 引用，级联清理 todo/nodes）。
	expID, err := d.CreateExploration("auto-satisfy-test", "todo auto satisfy")
	if err != nil {
		t.Fatal(err)
	}
	exp := d.Exploration(expID)
	t.Cleanup(func() { _, _ = d.ExecContext(ctx, `DELETE FROM explorations WHERE id=$1`, expID) })
	factA, err := exp.AddNode(KindFact, map[string]any{"summary": "fact A"}, 5, "confirmed", "probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	factB, err := exp.AddNode(KindFact, map[string]any{"summary": "fact B"}, 5, "confirmed", "probe", nil)
	if err != nil {
		t.Fatal(err)
	}

	items := []TodoItem{
		{Seq: 1, Title: "pending-step", Status: "pending", FactID: sql.NullInt64{Int64: factA, Valid: true}},
		{Seq: 2, Title: "progress-step", Status: "in_progress", FactID: sql.NullInt64{Int64: factB, Valid: true}},
		{Seq: 3, Title: "done-step", Status: "completed", FactID: sql.NullInt64{Int64: factA, Valid: true}},
	}
	if err := d.ReplaceTodos(ctx, expID, items); err != nil {
		t.Fatalf("ReplaceTodos: %v", err)
	}

	n, err := exp.MarkTodoSatisfied(ctx, factA)
	if err != nil {
		t.Fatalf("MarkTodoSatisfied: %v", err)
	}
	if n != 1 {
		t.Fatalf("auto-satisfy rows = %d, want 1 (only the pending one)", n)
	}
	got, err := d.LoadTodos(ctx, expID)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != "completed" || got[1].Status != "in_progress" || got[2].Status != "completed" {
		t.Fatalf("states after satisfy = %s/%s/%s, want completed/in_progress/completed", got[0].Status, got[1].Status, got[2].Status)
	}
	if !strings.Contains(got[0].Note, "[auto]") {
		t.Fatalf("note of auto-satisfied todo should carry [auto] marker, got %q", got[0].Note)
	}
	if n2, _ := exp.MarkTodoSatisfied(ctx, 999999); n2 != 0 {
		t.Fatalf("unreferenced fact upgraded %d rows, want 0", n2)
	}
	if n3, _ := exp.MarkTodoSatisfied(ctx, factA); n3 != 0 {
		t.Fatalf("repeat satisfy upgraded %d rows, want 0 (idempotent)", n3)
	}
}
