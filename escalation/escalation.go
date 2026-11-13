// Package escalation implements the M1 execution-time challenge channel
// (docs §3.6, ADR-003): when a worker's tool call is gated/blocked and it
// believes the direction is still worth pursuing, it can ask a lightweight
// adjudicator for a verdict over a deliberately narrow snapshot. The verdict
// only redirects the current intent (continue / pivot / cease) — intent
// generation stays with the planner.
package escalation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

// Trigger names what fired the challenge.
type Trigger string

const (
	TrigPolicyGate Trigger = "policy_gate" // 工具被政策门/规则拦截且 worker 认为方向仍值得
	TrigNewSurface Trigger = "new_surface" // worker 发现重大新攻击面（可配置开关）
	TrigStuck      Trigger = "stuck"       // 意图撞 blocked/exhausted，worker 认为换姿势有机会
)

// BlockedCall is one gated tool call carried in a snapshot.
type BlockedCall struct {
	Tool   string          `json:"tool"`
	Input  json.RawMessage `json:"input,omitempty"` // 与 LLM 审查同一信任边界：只用本次调用，不填充历史
	Reason string          `json:"reason,omitempty"`
}

// Snapshot is EVERYTHING sent to the adjudicator — deliberately NOT the
// full history, global situation, or other intents' context.
type Snapshot struct {
	IntentSummary string        `json:"intent_summary,omitempty"`
	JustBlocked   []BlockedCall `json:"just_blocked,omitempty"`
	RecentFacts   []string      `json:"recent_facts,omitempty"` // ≤3 条
	CurrentTarget []int64       `json:"current_target,omitempty"`
	VerdictHint   string        `json:"verdict_hint,omitempty"` // worker 自述倾向，不构成裁决依据
}

// AskRequest is one adjudication request.
type AskRequest struct {
	TaskID   string
	IntentID int64
	Trigger  Trigger
	Context  Snapshot
	Attempt  int // 同一触发源第几次质询（轮询上限依据）
}

// Verdict redirects only the current intent.
type Verdict string

const (
	VContinue Verdict = "continue" // 允许重试：换姿势/降采样后继续（仍过既有门链）
	VPivot    Verdict = "pivot"    // 换方向：写回 hint，本意图置 done（部分写回）
	VCease    Verdict = "cease"    // 收手：意图置 blocked + blocked_reason=裁决理由
)

// Result is the adjudicator's decision.
type Result struct {
	Verdict  Verdict `json:"verdict"`
	Reason   string  `json:"reason"`              // 必须含「实际操作、成功后的后果、命中规则」三段说明
	HintText string  `json:"hint_text,omitempty"` // pivot 时写回探索图
}

const systemPrompt = `你是渗透测试平台的操作裁决器。worker 的一次工具调用被平台安全机制拦截，它认为方向仍然值得。请根据给定的【最小快照】做出裁决，只重定向这条意图本身，不要提出新意图（意图生成权归 planner）。

输出必须是严格 JSON（不要 markdown 代码围栏），结构：
{"verdict":"continue|pivot|cease","reason":"...","hint_text":"..."}

判定原则：
- continue：换姿势/降采样后继续尝试，仍然要过一次既有门链；reason 中说明怎么换。
- pivot：方向本身有问题，换一个侦查方向；reason 说明换向理由，hint_text 写一条给 planner 下一步参考的线索。
- cease：该方向确实不可行/危险/无价值，收手；reason 作为意图的 blocked_reason。
reason 必须包含三段：[实际操作]做了什么、[成功后的后果]若成功会得到什么/影响什么、[命中规则]违反了哪条平台规则或政策。`

// buildPrompt renders the narrow snapshot into the adjudicator prompt.
func buildPrompt(req AskRequest) string {
	var b strings.Builder
	b.WriteString("【触发信号】" + string(req.Trigger))
	if req.Context.IntentSummary != "" {
		b.WriteString("\n【意图摘要】" + req.Context.IntentSummary)
	}
	if len(req.Context.JustBlocked) > 0 {
		b.WriteString("\n【被拦截的调用】")
		for i, c := range req.Context.JustBlocked {
			b.WriteString(fmt.Sprintf("\n %d) 工具=%s 原因=%s 参数=%s", i+1, c.Tool, c.Reason, string(c.Input)))
		}
	}
	if len(req.Context.RecentFacts) > 0 {
		b.WriteString("\n【近期事实(≤3)】\n - " + strings.Join(req.Context.RecentFacts, "\n - "))
	}
	if len(req.Context.CurrentTarget) > 0 {
		b.WriteString(fmt.Sprintf("\n【当前锚定资产】%v", req.Context.CurrentTarget))
	}
	if req.Context.VerdictHint != "" {
		b.WriteString("\n【worker 自述倾向(仅参考)】" + req.Context.VerdictHint)
	}
	return b.String()
}

// Ask runs one lightweight adjudication: a single non-streamed LLM call with
// only the snapshot. maxAttemptsPerIntent caps challenges of one intent source
// (default 1); hitting the cap returns a cease verdict without calling the
// model (the caller then follows the existing blocked path).
func Ask(ctx context.Context, prov llm.Provider, req AskRequest, maxAttemptsPerIntent int) (Result, error) {
	if prov == nil {
		return Result{}, errors.New("escalation: nil provider")
	}
	if maxAttemptsPerIntent <= 0 {
		maxAttemptsPerIntent = 1
	}
	if req.Attempt >= maxAttemptsPerIntent {
		return Result{
			Verdict: VCease,
			Reason:  fmt.Sprintf("质询轮数已达上限(%d)，按收手处理退回既有 blocked 路径", maxAttemptsPerIntent),
		}, nil
	}
	msg, _, _, err := prov.Complete(ctx, llm.CompletionRequest{
		System:    []string{systemPrompt},
		Messages:  []llm.Message{llm.UserText(buildPrompt(req))},
		MaxTokens: 600,
	})
	if err != nil {
		return Result{}, fmt.Errorf("escalation ask: %w", err)
	}
	return parseResult(msg.Text())
}

// parseResult parses the adjudicator's JSON reply. It tolerates code fences
// and leading prose, extracting the first JSON object.
func parseResult(reply string) (Result, error) {
	text := strings.TrimSpace(reply)
	if i := strings.Index(text, "{"); i >= 0 {
		text = text[i:]
	}
	if i := strings.LastIndex(text, "}"); i >= 0 {
		text = text[:i+1]
	}
	var r Result
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		return Result{}, fmt.Errorf("escalation: unparseable adjudicator reply: %v (raw=%q)", err, reply)
	}
	switch r.Verdict {
	case VContinue, VPivot, VCease:
	default:
		return Result{}, fmt.Errorf("escalation: invalid verdict %q", r.Verdict)
	}
	return r, nil
}
