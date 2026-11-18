// M3 planner 决策卡 API（docs §8.5）：把任务的 planner 决策痕迹投影为可读
// 决策卡 —— 意图清单（含 add_intent 依据 reason）+ 目标判定 + todo 快照
// （todo_items 来自 M2-1），供前端决策卡页面/审计使用。数据全部来自既有
// 探索图与 todo_items，无新表。活动细节另有 /api/exploration/activity*。
package server

import (
	"log"
	"net/http"
)

// GET /api/exploration/decisions?task=<id>
func (s *Server) decisions(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	intents, err := t.Store.DecisionIntents()
	if err != nil {
		log.Printf("[decisions] task=%s intents: %v", t.ID, err)
		writeErr(w, 500, err.Error())
		return
	}
	goals, err := t.Store.DecisionGoals()
	if err != nil {
		log.Printf("[decisions] task=%s goals: %v", t.ID, err)
		writeErr(w, 500, err.Error())
		return
	}
	todos := []map[string]any{}
	if s.m.pg != nil {
		if rows, terr := s.m.pg.LoadTodos(r.Context(), t.ExpID); terr == nil {
			for _, it := range rows {
				var factID any
				if it.FactID.Valid {
					factID = it.FactID.Int64
				}
				depends := []int64{}
				if len(it.Depends) > 0 {
					depends = it.Depends
				}
				todos = append(todos, map[string]any{
					"seq": it.Seq, "title": it.Title, "status": it.Status,
					"blocked_reason": it.Blocked, "note": it.Note,
					"fact_id": factID, "depends": depends,
				})
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"task_id": t.ID,
		"intents": intents,
		"goals":   goals,
		"todos":   todos,
	})
}
