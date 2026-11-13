package agent

import (
	"encoding/json"
	"testing"
)

// TestIntentItemReason ensures the M3 decision-card reason field survives the
// JSON boundary of add_intent (schema/param → payload projection).
func TestIntentItemReason(t *testing.T) {
	var a struct {
		Intents []intentItem `json:"intents"`
		intentItem
	}
	raw := []byte(`{"reason":"疑点：登录接口报错泄露了数据库类型","summary":"探测登录接口 SQLi","intents":[{"summary":"枚举后台路径","reason":"从 JS 里看到 admin 路径"}]}`)
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if a.intentItem.Reason != "疑点：登录接口报错泄露了数据库类型" {
		t.Errorf("top-level reason lost: %q", a.intentItem.Reason)
	}
	if a.intentItem.Summary != "探测登录接口 SQLi" {
		t.Errorf("top-level summary lost: %q", a.intentItem.Summary)
	}
	if len(a.Intents) != 1 || a.Intents[0].Reason != "从 JS 里看到 admin 路径" || a.Intents[0].Summary != "枚举后台路径" {
		t.Errorf("batch item reason/summary lost: %+v", a.Intents)
	}
	// reason 可选：无 reason 时不应破坏既有调用
	var b struct{ intentItem }
	if err := json.Unmarshal([]byte(`{"summary":"纯侦察"}`), &b); err != nil {
		t.Fatal(err)
	}
	if b.intentItem.Reason != "" || b.intentItem.Summary != "纯侦察" {
		t.Errorf("absent reason broke existing calls: %+v", b.intentItem)
	}
}
