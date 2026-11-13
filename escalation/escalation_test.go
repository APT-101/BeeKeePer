package escalation

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// fakeProvider returns a canned assistant message (single text block).
type fakeProvider struct{ reply string }

func (f fakeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {}
}

func (f fakeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if req.MaxTokens != 600 {
		return llm.Message{}, "", llm.Usage{}, nil // guard sanity (not asserted)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(f.reply)}}, "stop", llm.Usage{}, nil
}

func TestAskReturnsCeaseAtAttemptCap(t *testing.T) {
	prov := fakeProvider{reply: `{"verdict":"continue","reason":"x"}`}
	res, err := Ask(context.Background(), prov,
		AskRequest{TaskID: "1", IntentID: 7, Trigger: TrigStuck, Attempt: 3}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VCease {
		t.Fatalf("verdict = %v, want cease (attempt cap)", res.Verdict)
	}
	// cap hit → provider must NOT be called; f.reply would have been continue.
}

func TestAskFirstAttemptAllowed(t *testing.T) {
	// attempt=1, max=1 → 首次质询允许调用模型。
	res, err := Ask(context.Background(), fakeProvider{reply: `{"verdict":"continue","reason":"[实际操作]a [成功后的后果]b [命中规则]c"}`},
		AskRequest{TaskID: "1", Trigger: TrigPolicyGate, Attempt: 1}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VContinue {
		t.Fatalf("first attempt must be adjudicated, got %v", res.Verdict)
	}
}

func TestAskParsesVerdicts(t *testing.T) {
	for _, tc := range []struct {
		reply string
		want  Verdict
	}{
		{`{"verdict":"continue","reason":"[实际操作]重试 GET [成功后的后果]拿到响应 [命中规则]无"}`, VContinue},
		{"协商后：\n```json\n{\"verdict\":\"pivot\",\"reason\":\"[实际操作]nmap [成功后的后果]暴露面 [命中规则]passive 禁扫描\",\"hint_text\":\"改用被动源\"}\n```", VPivot},
		{`{"verdict":"cease","reason":"[实际操作]爆破 [成功后的后果]锁定 [命中规则]policy active 需审批"}`, VCease},
	} {
		res, err := Ask(context.Background(), fakeProvider{reply: tc.reply},
			AskRequest{TaskID: "1", Trigger: TrigPolicyGate}, 3)
		if err != nil {
			t.Errorf("Ask(%q): %v", tc.reply, err)
			continue
		}
		if res.Verdict != tc.want {
			t.Errorf("Ask(%q) verdict = %v, want %v", tc.reply, res.Verdict, tc.want)
		}
	}
}

func TestAskPromptsUseNarrowSnapshot(t *testing.T) {
	var captured string
	prov := spyingProvider{onComplete: func(req llm.CompletionRequest) {
		captured = req.System[0] + "\n" + req.Messages[0].Text()
	}, reply: `{"verdict":"continue","reason":"[实际操作]a [成功后的后果]b [命中规则]c"}`}
	_, _ = Ask(context.Background(), prov, AskRequest{
		TaskID:  "9",
		Trigger: TrigPolicyGate,
		Context: Snapshot{
			IntentSummary: "探测 login 端点",
			JustBlocked:   []BlockedCall{{Tool: "Bash", Input: json.RawMessage(`{"command":"curl -X POST ..."}`), Reason: "passive 禁写"}},
			RecentFacts:   []string{"版本头泄露"},
			CurrentTarget: []int64{42},
		},
	}, 3)
	for _, want := range []string{"policy_gate", "探测 login 端点", "passive 禁写", "Bash", "curl -X POST", "42"} {
		if !strings.Contains(captured, want) {
			t.Errorf("prompt missing %q (captured=%q)", want, captured)
		}
	}
}

func TestParseResultRejectsBadVerdict(t *testing.T) {
	if _, err := parseResult(`{"verdict":"fly","reason":"x"}`); err == nil {
		t.Fatal("invalid verdict must error")
	}
	if _, err := parseResult("no json here"); err == nil {
		t.Fatal("non-JSON reply must error")
	}
}

// spyingProvider records the request and returns a canned reply.
type spyingProvider struct {
	onComplete func(llm.CompletionRequest)
	reply      string
}

func (s spyingProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {}
}

func (s spyingProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	s.onComplete(req)
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(s.reply)}}, "stop", llm.Usage{}, nil
}
