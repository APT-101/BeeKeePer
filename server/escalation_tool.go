package server

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/escalation"
	"github.com/Autumn-27/artex/events"
	actool "github.com/Autumn-27/norma/tool"
)

// toolEscalate exposes the M1 challenge channel (docs §3.6, ADR-003) to task
// workers: after a security-gate block, a worker that still believes the
// direction is worth pursuing requests ONE adjudication over a deliberately
// narrow snapshot. The verdict only redirects this intent — intent generation
// stays with the planner, and continue/pivot/cease still pass the existing
// gate chain (no bypass). An unavailable adjudicator LLM fails SAFE: the tool
// errors and the intent falls back to the existing blocked path.
func (s *Server) toolEscalate() actool.CoreTool {
	return wrTool("escalate",
		"质询裁决：当你的工具调用被平台安全门拦截(政策挡位/范围外目标)，而你判断该方向仍值得继续时，调用本工具请求一次性裁决。\n"+
			"参数：blocked_tool(被拦截的工具名)、blocked_reason(拦截原因，取自拦截消息)、intent_summary(本意图在做什么的一句话)、current_facts(可选，最近掌握的事实，最多3条)、target_ids(可选，当前锚定的资产 id 列表)、attempt(可选，同来源第几次质询，从1开始)。\n"+
			"裁决三种：continue(换个姿势/降采样后重试，仍须过既有门链)、pivot(换侦查方向)、cease(收手)。同一意图请勿无限制重试——达到上限后平台按收手处理。",
		objSchema(map[string]any{
			"blocked_tool":   strParam("被拦截的工具名，如 Bash/WebFetch"),
			"blocked_reason": strParam("拦截原因（取自拦截消息）"),
			"intent_summary": strParam("本意图目标的一句话摘要"),
			"current_facts":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "最近事实，最多3条"},
			"target_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "当前锚定的资产 id"},
			"attempt":        map[string]any{"type": "integer", "description": "同触发源的质询轮数，从1开始（默认1）"},
		}, "blocked_tool", "blocked_reason", "intent_summary"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 || s.m.pg == nil {
				return actool.Errorf("escalate 仅限任务运行上下文中使用"), nil
			}
			var p struct {
				BlockedTool   string   `json:"blocked_tool"`
				BlockedReason string   `json:"blocked_reason"`
				IntentSummary string   `json:"intent_summary"`
				CurrentFacts  []string `json:"current_facts"`
				TargetIDs     []int64  `json:"target_ids"`
				Attempt       int      `json:"attempt"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(p.BlockedTool) == "" || strings.TrimSpace(p.BlockedReason) == "" {
				return actool.Errorf("blocked_tool 与 blocked_reason 为必填"), nil
			}
			if p.Attempt < 1 {
				p.Attempt = 1
			}
			if !s.m.escalationCap(ri.TaskID, ri.IntentID, int64(p.Attempt)) {
				return actool.Errorf("质询轮数已达上限(" + strconv.Itoa(s.m.escalationMaxAttempts()) + ")，按收手处理，退回既有 blocked 路径"), nil
			}
			t, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10))
			if !ok || s.m.pg == nil {
				return actool.Errorf("任务上下文缺失"), nil
			}
			var profID int64
			if t.ActiveLLMProfileID != nil {
				profID = *t.ActiveLLMProfileID
			}
			prov, _, ok := s.providerForProfile(profID)
			if !ok {
				if ap, err := s.m.pg.ActiveProfile(); err == nil && ap != nil {
					prov, _, ok = s.providerForProfile(ap.ID)
				}
			}
			if !ok {
				// LLM 不可用 → fail 走既有 blocked 路径（安全侧）。
				return actool.Errorf("裁决服务不可用，按收手处理（退回既有 blocked 路径）"), nil
			}
			req := escalation.AskRequest{
				TaskID:   t.ID,
				IntentID: ri.IntentID,
				Trigger:  escalation.TrigPolicyGate,
				Attempt:  p.Attempt,
				Context: escalation.Snapshot{
					IntentSummary: p.IntentSummary,
					JustBlocked:   []escalation.BlockedCall{{Tool: p.BlockedTool, Input: nil, Reason: p.BlockedReason}},
					RecentFacts:   clipStrings(p.CurrentFacts, 3),
					CurrentTarget: p.TargetIDs,
				},
			}
			res, err := escalation.Ask(ctx, prov, req, s.m.escalationMaxAttempts())
			if err != nil {
				s.emitEscalation(ctx, t.ID, ri.IntentID, p, "error", err.Error())
				return actool.Errorf("质询失败: " + err.Error() + "（按收手处理，退回既有 blocked 路径）"), nil
			}
			s.emitEscalation(ctx, t.ID, ri.IntentID, p, string(res.Verdict), res.Reason)
			switch res.Verdict {
			case escalation.VContinue:
				return actool.Text("裁决=continue：" + res.Reason + "。换姿势后重试，仍须过一次既有门链。"), nil
			case escalation.VPivot:
				hint := res.HintText
				if hint == "" {
					hint = "质询裁决 pivot：" + res.Reason
				}
				s.writePivotHint(ctx, t, hint)
				return actool.Text("裁决=pivot：换侦查方向。" + res.Reason + "（已向 planner 写回 hint：" + hint + "）"), nil
			default:
				return actool.Text("裁决=cease：收手。" + res.Reason + "（本意图退回既有 blocked 路径）"), nil
			}
		})
}

// emitEscalation publishes the ADR-003 challenge result event (M1 reservation).
func (s *Server) emitEscalation(ctx context.Context, taskID string, intentID int64, p struct {
	BlockedTool   string   `json:"blocked_tool"`
	BlockedReason string   `json:"blocked_reason"`
	IntentSummary string   `json:"intent_summary"`
	CurrentFacts  []string `json:"current_facts"`
	TargetIDs     []int64  `json:"target_ids"`
	Attempt       int      `json:"attempt"`
}, verdict, reason string) {
	s.m.publishEvent(events.Event{
		Kind:     events.EvEscalation,
		TaskID:   taskID,
		IntentID: intentID,
		Payload: map[string]any{
			"trigger":      string(escalation.TrigPolicyGate),
			"blocked_tool": p.BlockedTool,
			"attempt":      p.Attempt,
			"verdict":      verdict,
			"reason":       reason,
		},
	})
}

// writePivotHint attaches the adjudicator's redirect as an exploration-graph
// hint so the planner reads it on the next planning round. Best-effort.
func (s *Server) writePivotHint(ctx context.Context, t *Task, hint string) {
	ts := agent.NewToolSet(t.Store, "worker")
	if s.m.Assets() != nil {
		ts.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
		ts.SetComponentStore(s.m.Components(), s.m.FirmwareExtracts())
	}
	ts.SetNotify(t.Notify)
	ts.SetNotifyHint(t.NotifyHint)
	body, _ := json.Marshal(map[string]any{"text": hint})
	if _, err := ts.AddHintTool().Call(ctx, body, nil); err != nil {
		log.Printf("[escalation] pivot hint 写回失败: %v", err)
	}
}

// clipStrings keeps at most n items (declared caps like ≤3 facts).
func clipStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
