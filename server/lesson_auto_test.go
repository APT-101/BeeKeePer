package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

func intentPayload(summary string) db.Node {
	p, _ := json.Marshal(map[string]any{"summary": summary})
	return db.Node{ID: 42, Kind: "intent", Payload: p}
}

func TestAutoLessonSummaryBlocked(t *testing.T) {
	n := intentPayload("枚举 example.com 的登录接口并验证默认口令")
	s, d := autoLessonSummary("blocked", &n, errors.New("Bash 执行失败: 连接被拒绝 (exit 1)"), "")
	if !strings.Contains(s, "[自动]") || !strings.Contains(s, "意图「") || !strings.Contains(s, "枚举 example.com") {
		t.Errorf("blocked summary malformed: %s", s)
	}
	if !strings.Contains(s, "执行出错") || !strings.Contains(s, "连接被拒绝") {
		t.Errorf("blocked summary should carry the error: %s", s)
	}
	if d["auto"] != true || d["state"] != "blocked" || d["intent_id"] != int64(42) {
		t.Errorf("detail wrong: %v", d)
	}
	if _, ok := d["error"].(string); !ok {
		t.Errorf("detail.error missing: %v", d)
	}
}

func TestAutoLessonSummaryExhausted(t *testing.T) {
	n := intentPayload("爆破后台登录")
	s, _ := autoLessonSummary("exhausted", &n, nil, harness.ReasonMaxTurns)
	if !strings.Contains(s, "撞步数上限") || !strings.Contains(s, "换角度") {
		t.Errorf("max_turns summary: %s", s)
	}
	s2, _ := autoLessonSummary("exhausted", &n, nil, harness.ReasonTimeout)
	if !strings.Contains(s2, "运行超时") {
		t.Errorf("timeout summary: %s", s2)
	}
}

func TestAutoLessonSummaryNilIntentAndBlockedNoErr(t *testing.T) {
	s, _ := autoLessonSummary("blocked", nil, nil, "")
	if !strings.Contains(s, "执行被阻断") {
		t.Errorf("blocked w/o error summary: %s", s)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("一二三四五", 3); got != "一二三…" {
		t.Errorf("truncate: %q", got)
	}
	if got := truncateRunes("abc", 5); got != "abc" {
		t.Errorf("short input must stay: %q", got)
	}
	if got := truncateRunes("", 3); got != "" {
		t.Errorf("empty: %q", got)
	}
}

func TestNodeSummaryFallback(t *testing.T) {
	p, _ := json.Marshal(map[string]any{"text": "用 text 键的节点"})
	if got := nodeSummary(p); got != "用 text 键的节点" {
		t.Errorf("text fallback: %q", got)
	}
	if got := nodeSummary([]byte(`{"other":1}`)); got != "" {
		t.Errorf("no summary: %q", got)
	}
	if got := nodeSummary(nil); got != "" {
		t.Errorf("nil payload: %q", got)
	}
}
