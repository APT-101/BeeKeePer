// M2 状态与记忆的 server 装配（docs §3.5/§4）：
//   - pgTodoPersist：planner 规划待办落库（db.todo_items ↔ actool.Todo）
//   - lesson provider：跨任务经验注入 planner 提示
//   - record_lesson 工具：worker/planner 沉淀经验（db.lesson_notes）
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// pgTodoPersist implements agent.TodoPersist over db.todo_items.
type pgTodoPersist struct{ d *db.DB }

func (p *pgTodoPersist) LoadTodos(ctx context.Context, expID int64) ([]actool.Todo, error) {
	rows, err := p.d.LoadTodos(ctx, expID)
	if err != nil {
		return nil, err
	}
	out := make([]actool.Todo, 0, len(rows))
	for _, r := range rows {
		out = append(out, actool.Todo{Content: r.Title, Status: actool.TodoStatus(r.Status)})
	}
	return out, nil
}

func (p *pgTodoPersist) SaveTodos(ctx context.Context, expID int64, items []actool.Todo) error {
	rows := make([]db.TodoItem, 0, len(items))
	for i, it := range items {
		rows = append(rows, db.TodoItem{
			Seq: i + 1, Title: it.Content, Status: string(it.Status),
		})
	}
	return p.d.ReplaceTodos(ctx, expID, rows)
}

// agentTaskID resolves the current task id from the tool context (record_lesson
// source stamping); 0 when off-task.
func agentTaskID(ctx context.Context) int64 {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID > 0 {
		return ri.TaskID
	}
	return 0
}

// toolRecordLesson lets workers/planner persist cross-task lessons.
// kind ∈ blocked|exhausted|waf|lesson|misconfig；detail 自由 JSON；tags 检索用。
func (s *Server) toolRecordLesson() actool.CoreTool {
	run := func(ctx context.Context, msg json.RawMessage) (actool.Result, error) {
		var in struct {
			Kind    string         `json:"kind"`
			Summary string         `json:"summary"`
			Detail  map[string]any `json:"detail"`
			Tags    []string       `json:"tags"`
		}
		if err := json.Unmarshal(msg, &in); err != nil {
			return actool.Errorf("record_lesson 参数解析失败：" + err.Error()), nil
		}
		if !oneOf(in.Kind, "blocked", "exhausted", "waf", "lesson", "misconfig") {
			return actool.Errorf("record_lesson: kind 必须是 blocked/exhausted/waf/lesson/misconfig，收到 " + in.Kind), nil
		}
		if strings.TrimSpace(in.Summary) == "" {
			return actool.Errorf("record_lesson: summary 必填（一句话教训，供其他任务/规划参考）"), nil
		}
		if len(in.Tags) > 6 {
			in.Tags = in.Tags[:6]
		}
		l := &db.LessonNote{Kind: in.Kind, Summary: in.Summary, Detail: in.Detail, Tags: in.Tags}
		if tid := agentTaskID(ctx); tid > 0 {
			l.SourceTaskID = sql.NullInt64{Int64: tid, Valid: true}
			if ri := agent.RunInfoFrom(ctx); ri.IntentID > 0 {
				l.SourceIntentID = sql.NullInt64{Int64: ri.IntentID, Valid: true}
			}
		}
		id, err := s.m.pg.AddLesson(ctx, l)
		if err != nil {
			return actool.Errorf("record_lesson 落库失败：" + err.Error()), nil
		}
		return actool.Text("经验已沉淀（lesson_notes #" + itoa64(id) + "），供后续任务规划参考。"), nil
	}
	return wrTool("record_lesson",
		"沉淀一条跨任务经验（lesson_notes 经验库）：blocked=方向被封/已穷尽、exhausted=手段耗尽但方向仍值得（留待未来）、waf=被 WAF/规则拦、misconfig=目标误配、lesson=一般教训。summary 一句话讲清【什么场景下什么手段不work/值得试】；detail 存结构化补充（命令/证据/替代思路）；tags 放便于检索的领域词（如 cms、sqlite、bypass）。仅供跨任务参考，不是指令。",
		objSchema(map[string]any{
			"kind":    map[string]any{"type": "string", "description": "blocked|exhausted|waf|lesson|misconfig", "enum": []string{"blocked", "exhausted", "waf", "lesson", "misconfig"}},
			"summary": strParam("一句话教训"),
			"detail":  map[string]any{"type": "object", "description": "结构化补充（命令/证据/替代思路），省略为 {}"},
			"tags":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "检索词（≤6 个）"},
		}, "kind", "summary"),
		run)
}

// lessonInjector builds the planner lesson provider: recent cross-task lessons,
// excluding the current task's own notes. Errors degrade to empty (no prompt
// blocking).
func (s *Server) lessonInjector(ctx context.Context, taskID int64) ([]agent.LessonNote, error) {
	rows, err := s.m.pg.ListRecentLessons(ctx, taskID, "", "", 8)
	if err != nil {
		return nil, err
	}
	out := make([]agent.LessonNote, 0, len(rows))
	for _, r := range rows {
		n := agent.LessonNote{Kind: r.Kind, Summary: r.Summary, Tags: r.Tags}
		if r.SourceTaskID.Valid {
			n.TaskID = r.SourceTaskID.Int64
		}
		if r.SourceIntentID.Valid {
			n.IntentID = r.SourceIntentID.Int64
		}
		out = append(out, n)
	}
	return out, nil
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }
