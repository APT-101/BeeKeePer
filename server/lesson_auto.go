// M2-3 学习闭环的自动侧（docs §8.8）：worker 意图 blocked/exhausted 结束时，引擎
// 自动沉淀一条跨任务 lesson（kind=blocked|exhausted、tags=["auto"]），让后续任务
// 不必等模型自觉 record_lesson 就能借鉴同类「撞墙」经验。限流：同源同 kind 最近
// 6h 内已有条目则跳过（防同一意图反复重跑刷屏 lesson 注入）。
//
// 说明：自动条目带 [自动] 前缀 + auto tag，区别于人工/模型显式沉淀；注入侧
// renderLessons 同样排除本任务，避免自引用。
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

// autoLessonDedupeWindow 是自动沉淀去重窗口。
const autoLessonDedupeWindow = 6 * time.Hour

// autoSinkLesson 在意图终结为 blocked/exhausted 时自动沉淀经验。
// 纯旁路：任何失败只记日志，绝不影响 worker 终结主流程。
func (e *Engine) autoSinkLesson(ctx context.Context, t *Task, intent *db.Node, state string, runErr error, reason harness.TerminalReason) {
	if state != "blocked" && state != "exhausted" {
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if taskID <= 0 {
		return
	}
	n, err := e.m.pg.LessonCountSince(ctx, state, taskID, intent.ID, autoLessonDedupeWindow)
	if err != nil {
		log.Printf("[auto-lesson] 限流查询失败: %v", err)
		return
	}
	if n > 0 {
		return // 同源同 kind 最近窗口内已沉淀，去重
	}
	summary, detail := autoLessonSummary(state, intent, runErr, reason)
	if _, err := e.m.pg.AddLesson(ctx, &db.LessonNote{
		SourceTaskID:   sql.NullInt64{Int64: taskID, Valid: true},
		SourceIntentID: sql.NullInt64{Int64: intent.ID, Valid: intent.ID > 0},
		Kind:           state,
		Summary:        summary,
		Detail:         detail,
		Tags:           []string{"auto"},
	}); err != nil {
		log.Printf("[auto-lesson] 沉淀失败: %v", err)
		return
	}
	log.Printf("[auto-lesson] 意图 #%d 自动沉淀 %s 经验（task=%s）", intent.ID, state, t.ID)
}

// autoLessonSummary 组装自动沉淀的摘要与 detail：
// 摘要面向跨任务注入（简短、可操作）；detail 留审计字段（原始错误/意图摘要等）。
func autoLessonSummary(state string, intent *db.Node, runErr error, reason harness.TerminalReason) (string, map[string]any) {
	about := "意图"
	if intent != nil {
		if s := nodeSummary(intent.Payload); s != "" {
			about = "意图「" + truncateRunes(s, 60) + "」"
		}
	}
	why := "结束原因未详"
	switch {
	case state == "blocked" && runErr != nil:
		why = "执行出错：" + truncateRunes(runErr.Error(), 160)
	case state == "blocked":
		why = "执行被阻断"
	case state == "exhausted" && reason == harness.ReasonMaxTurns:
		why = "撞步数上限：方向试过但未真正走通，宜换角度而非当作已覆盖"
	case state == "exhausted" && reason == harness.ReasonTimeout:
		why = "运行超时：宜更小粒度拆解/更快的探测，避免长任务超预算"
	case state == "exhausted":
		why = "资源耗尽"
	}
	detail := map[string]any{
		"state":  state,
		"auto":   true,
		"reason": reason,
	}
	if runErr != nil {
		detail["error"] = truncateRunes(runErr.Error(), 500)
	}
	if intent != nil {
		detail["intent_id"] = intent.ID
		if s := nodeSummary(intent.Payload); s != "" {
			detail["intent_summary"] = s
		}
	}
	return "[自动] " + about + " 结束后沉淀：" + why, detail
}

// nodeSummary 读节点 payload 的 summary（退化读 text——与 db.AssetRefs 同一口径）。
func nodeSummary(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	var p map[string]any
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	for _, k := range []string{"summary", "text"} {
		if v, ok := p[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// truncateRunes 按 rune 截断（中文按字符计）。
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
