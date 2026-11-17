// M2 状态与记忆的 agent 侧接入（docs §3.5/§4/§8.11）：
//   - TodoPersist 让 planner 的规划待办跨进程存活：DB 为真值 + 内存缓存，
//     轮末全量写回、首次唤醒从 DB 重建（norma 的 actool.TodoStore 是具体类型，
//     不能替换实现 —— 重建经 TodoWrite 工具的公开 Call 路径填充 store）。
//   - TodoMeta / PersistedTodo：平台侧 todo 结构字段（norma 只有 content/status），
//     让 planner 能显式声明"某步由哪个 fact 节点满足 / 依赖哪些前置"（M2-2 schema 化）。
//   - 平台版 TodoWrite（todoWriteTool）替换 agentcore 的 Todos 自动注入：
//     schema 扩展 satisfied_by_fact_id / depends_on，与系统侧 MarkTodoSatisfied 闭环。
//   - LessonProvider 供 planner 唤醒提示注入跨任务经验（来自 lesson_notes）。
//
// 两个钩子都走回调注入：nil = 特性关闭，保持既有纯内存行为。
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// TodoMeta 是平台侧 todo 的结构字段（超出 norma content/status，docs §8.11）：
//   - FactID（satisfied_by_fact_id）：声明"这条 todo 由哪个 graph fact 节点满足"。
//     模型在 TodoWrite 显式声明（值来自 get_worker_output/list_facts/node_detail
//     返回的 fact id）+ record_fact 系统侧 auto-mark（MarkTodoSatisfied）双通道，
//     使"意图产出 → 子目标达成"可证明、可确定性推进。
//   - Depends（depends_on）：前置 todo 的 1-based seq 引用（规划约束，推进由显式状态主导）。
type TodoMeta struct {
	FactID  int64   `json:"satisfied_by_fact_id,omitempty"`
	Depends []int64 `json:"depends_on,omitempty"`
}

// PersistedTodo 是 DB 往返项：norma 的 content/status + 平台扩展字段。
type PersistedTodo struct {
	Todo actool.Todo
	Meta TodoMeta
}

// TodoPersist persists the planner's attack-chain todo list. Implementations
// must be idempotent and cheap (round-boundary calls only).
type TodoPersist interface {
	// LoadTodos returns the persisted list for exploration id (empty when none).
	LoadTodos(ctx context.Context, expID int64) ([]PersistedTodo, error)
	// SaveTodos atomically replaces the persisted list (DB is the source of
	// truth across restarts).
	SaveTodos(ctx context.Context, expID int64, items []PersistedTodo) error
}

// LessonNote is the planner-facing projection of a cross-task lesson.
type LessonNote struct {
	Kind     string // blocked | exhausted | waf | lesson | misconfig
	Summary  string
	Tags     []string
	TaskID   int64 // source task (0 = human-entered, no task context)
	IntentID int64
}

// LessonProvider returns recent cross-task lessons for the planner prompt
// (current task's own notes excluded by the implementation).
type LessonProvider func(ctx context.Context, taskID int64) ([]LessonNote, error)

// todoPersist hooks into Planner (see planner.go todoFor / Plan).
func (p *Planner) SetTodoPersist(ps TodoPersist) { p.todoPersist = ps }

// SetLessonProvider wires cross-task lesson injection into the planner system
// prompt (nil = feature disabled).
func (p *Planner) SetLessonProvider(fn LessonProvider) { p.lessonProv = fn }

// todoFor returns the task's persistent planning todo store, creating it on
// first use and restoring it from the DB when a persistence backend is wired.
func (p *Planner) todoFor(ctx context.Context, expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
		if p.todoPersist != nil {
			items, err := p.todoPersist.LoadTodos(ctx, expID)
			if err != nil {
				log.Printf("[m2] todo load exp=%d: %v", expID, err)
				return s // 读库失败 → 空清单起步（不阻断规划）
			}
			if len(items) == 0 {
				return s
			}
			// actool.TodoStore 没有公开 replace API —— 经工具的 Call 路径填充。
			todos := make([]actool.Todo, 0, len(items))
			meta := map[int]TodoMeta{}
			for i, it := range items {
				todos = append(todos, it.Todo)
				if it.Meta.FactID > 0 || len(it.Meta.Depends) > 0 {
					meta[i] = it.Meta
				}
			}
			raw, jerr := json.Marshal(map[string]any{"todos": todos})
			if jerr == nil {
				if _, cerr := s.Tool().Call(ctx, raw, &actool.ToolContext{}); cerr != nil {
					log.Printf("[m2] todo restore exp=%d: %v", expID, cerr)
				}
			}
			p.todoMeta[expID] = meta
		}
	}
	return s
}

// syncTodos writes the round's todo snapshot (+ structured meta) back to the DB
// (round boundary).
func (p *Planner) syncTodos(ctx context.Context, expID int64) {
	if p.todoPersist == nil {
		return
	}
	list := p.todoFor(ctx, expID).List()
	p.todoMu.Lock()
	meta := p.todoMeta[expID]
	p.todoMu.Unlock()
	out := make([]PersistedTodo, 0, len(list))
	for i, it := range list {
		m := TodoMeta{}
		if meta != nil {
			m = meta[i]
		}
		out = append(out, PersistedTodo{Todo: it, Meta: m})
	}
	if err := p.todoPersist.SaveTodos(ctx, expID, out); err != nil {
		log.Printf("[m2] todo save exp=%d: %v", expID, err)
	}
}

// todoWriteTool 是平台版 TodoWrite（docs §8.11），替换 agentcore 的 Todos 自动注入：
// schema 在 content/status 之外增加 satisfied_by_fact_id（graph fact 节点 id）与
// depends_on（前置 todo 序号）。Run 仍写入 planner 的持久 store（跨轮保留），并平行
// 记录结构字段（syncTodos 时落库，成为系统 MarkTodoSatisfied 的匹配键）。
func (p *Planner) todoWriteTool(ctx context.Context, expID int64) actool.CoreTool {
	store := p.todoFor(ctx, expID)
	return actool.Build(actool.Spec{
		Name:        "TodoWrite",
		Description: "记录/更新本任务的规划待办清单（跨轮保留、DB 持久化）。每次调用【全量替换】整个清单；进行中只把一项标为 in_progress。**结构化字段（可选）**：satisfied_by_fact_id=已产出该步结论的 fact 节点 id（在 get_worker_output / list_facts / node_detail 返回里能看到 id）——系统会在该 fact 落图时把此步自动判为 completed（确定性达成，无需手动改状态）；depends_on=[前置步骤序号] 声明串行依赖（帮助自己看清前驱，推进仍靠显式状态）。",
		Prompt:      "status 取值 pending|in_progress|completed：一步完成立刻标 completed，别攒批；串行链用 depends_on 连出前驱；已有产出事实的步骤用 satisfied_by_fact_id 钉到具体 fact，让达成可证明。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"todos": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"content":              map[string]any{"type": "string"},
							"status":               map[string]any{"type": "string", "enum": []any{"pending", "in_progress", "completed"}},
							"satisfied_by_fact_id": map[string]any{"type": "integer", "description": "产出此步结论的 graph fact 节点 id（可选）"},
							"depends_on":           map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "前置步骤序号（可选）"},
						},
						"required": []any{"content", "status"},
					},
				},
			},
			"required": []any{"todos"},
		},
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Allowed()
		},
		Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Todos []struct {
					Content           string  `json:"content"`
					Status            string  `json:"status"`
					SatisfiedByFactID int64   `json:"satisfied_by_fact_id"`
					DependsOn         []int64 `json:"depends_on"`
				} `json:"todos"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Result{}, err
			}
			todos := make([]actool.Todo, 0, len(in.Todos))
			meta := map[int]TodoMeta{}
			for i, it := range in.Todos {
				todos = append(todos, actool.Todo{Content: it.Content, Status: actool.TodoStatus(it.Status)})
				if it.SatisfiedByFactID > 0 || len(it.DependsOn) > 0 {
					meta[i] = TodoMeta{FactID: it.SatisfiedByFactID, Depends: it.DependsOn}
				}
			}
			// store 无公开 set —— 走内置 TodoWrite 的 Call 路径写入。
			raw, jerr := json.Marshal(map[string]any{"todos": todos})
			if jerr != nil {
				return actool.Result{}, jerr
			}
			runCtx := context.Background()
			if ctx != nil {
				runCtx = ctx
			}
			if _, cerr := store.Tool().Call(runCtx, raw, &actool.ToolContext{}); cerr != nil {
				return actool.Result{}, cerr
			}
			p.todoMu.Lock()
			if p.todoMeta[expID] == nil {
				p.todoMeta[expID] = map[int]TodoMeta{}
			}
			if len(meta) > 0 {
				p.todoMeta[expID] = meta
			}
			p.todoMu.Unlock()
			return actool.Text("Todos have been modified successfully. Keep the todo list current and continue with the tasks."), nil
		},
	})
}

// renderLessons formats cross-task lessons for the planner system prompt.
func renderLessons(lessons []LessonNote) string {
	if len(lessons) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【跨任务经验（其他任务的教训沉淀，仅供参考的 heuristics——必须与当前任务的具体现象核对后再采信）】：\n")
	for i, l := range lessons {
		if i >= 8 {
			break
		}
		tag := ""
		if len(l.Tags) > 0 {
			tag = " [" + l.Tags[0] + "]"
		}
		b.WriteString(fmt.Sprintf("  %s%s: %s\n", l.Kind, tag, l.Summary))
	}
	return b.String()
}
