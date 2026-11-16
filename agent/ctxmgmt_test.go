package agent

import (
	"strings"
	"testing"
)

func TestEstimateTokens(t *testing.T) {
	if estimateTokens("") != 0 {
		t.Fatal("empty string must estimate 0")
	}
	if estimateTokens("a") != 1 {
		t.Fatal("short string must estimate ≥1")
	}
	if estimateTokens("abcdef") != 2 {
		t.Fatalf("6 chars should estimate 2, got %d", estimateTokens("abcdef"))
	}
	if estimateTokens("中文字符串") != 5 { // 5 汉字 = 15 字节 → 15/3 ≈ 5 token（1 汉字≈1 token）
		t.Fatalf("5 CJK chars should estimate 5, got %d", estimateTokens("中文字符串"))
	}
}

func TestRenderContextManifestEmpty(t *testing.T) {
	if renderContextManifest(nil) != "" {
		t.Fatal("nil blocks must render empty")
	}
	if renderContextManifest([]ContextBlock{}) != "" {
		t.Fatal("empty blocks must render empty")
	}
}

func TestRenderContextManifestFormat(t *testing.T) {
	out := renderContextManifest([]ContextBlock{
		{Name: "graph_overview", Tokens: 120, Note: "态势"},
		{Name: "cold_digest", Tokens: 0, Foldable: true, Folded: true, Note: "可展开"},
	})
	for _, want := range []string{
		"上下文构成清单", "graph_overview：约 120 tokens", "态势",
		"cold_digest：约 0 tokens", "已折叠，用 expand_digest 展开", "合计约",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest missing %q:\n%s", want, out)
		}
	}
}

func TestComposeWorkerManifest(t *testing.T) {
	out := composeWorkerManifest("overview-text", 1, 3, true)
	for _, want := range []string{
		"worker_overview（任务全局态势）", "intent_mandate（本意图/启动指令/锚定资产）",
		"constraints（操作约束）", "1 个 digest 折叠了 3 条冷节点", "已折叠",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("worker manifest missing %q:\n%s", want, out)
		}
	}
	// 空 overview → 跳过 overview 块（仅保留意图/约束/冷区）
	out2 := composeWorkerManifest("", 0, 0, false)
	if strings.Contains(out2, "worker_overview") || strings.Contains(out2, "constraints") || strings.Contains(out2, "已折叠") {
		t.Errorf("empty overview/constraints/digests must be omitted:\n%s", out2)
	}
	if !strings.Contains(out2, "intent_mandate") {
		t.Error("intent_mandate must always be listed")
	}
}

func TestComposePlannerManifest(t *testing.T) {
	out := composePlannerManifest("situation-text", "todo-text", "lesson-text", 2, 7)
	if !strings.Contains(out, "graph_overview（本任务态势）") {
		t.Error("manifest must list graph_overview")
	}
	if !strings.Contains(out, "planner_todos（跨唤醒规划待办）") {
		t.Error("manifest must list planner_todos")
	}
	if !strings.Contains(out, "lesson_notes（跨任务经验）") {
		t.Error("manifest must list lesson_notes")
	}
	if !strings.Contains(out, "2 个 digest 折叠了 7 条冷节点") {
		t.Errorf("manifest must state digest fold count:\n%s", out)
	}
	if !strings.Contains(out, "已折叠，用 expand_digest 展开") {
		t.Error("folded digest block must be marked expandable")
	}
	// 空 chunks：跳过 todo/lesson，digest 未启用时不标折叠
	out2 := composePlannerManifest("situation-only", "", "", 0, 0)
	if strings.Contains(out2, "planner_todos") || strings.Contains(out2, "lesson_notes") {
		t.Errorf("empty chunks must be omitted:\n%s", out2)
	}
	if strings.Contains(out2, "已折叠") {
		t.Errorf("no digests must not be marked folded:\n%s", out2)
	}
	if !strings.Contains(out2, "graph_overview") {
		t.Error("non-empty situational must still be listed")
	}
}
