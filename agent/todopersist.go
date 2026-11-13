// M2 状态与记忆的 agent 侧接入（docs §3.5/§4）：
//   - TodoPersist 让 planner 的规划待办跨进程存活：DB 为真值 + 内存缓存，
//     轮末全量写回、首次唤醒从 DB 重建（norma 的 actool.TodoStore 是具体类型，
//     不能替换实现 —— 重建经 TodoWrite 工具的公开 Call 路径填充 store）。
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

	actool "github.com/Autumn-27/norma/tool"
)

// TodoPersist persists the planner's attack-chain todo list. Implementations
// must be idempotent and cheap (round-boundary calls only).
type TodoPersist interface {
	// LoadTodos returns the persisted list for exploration id (empty when none).
	LoadTodos(ctx context.Context, expID int64) ([]actool.Todo, error)
	// SaveTodos atomically replaces the persisted list (DB is the source of
	// truth across restarts).
	SaveTodos(ctx context.Context, expID int64, items []actool.Todo) error
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
			raw, jerr := json.Marshal(map[string]any{"todos": items})
			if jerr == nil {
				if _, cerr := s.Tool().Call(ctx, raw, &actool.ToolContext{}); cerr != nil {
					log.Printf("[m2] todo restore exp=%d: %v", expID, cerr)
				}
			}
		}
	}
	return s
}

// syncTodos writes the round's todo snapshot back to the DB (round boundary).
func (p *Planner) syncTodos(ctx context.Context, expID int64) {
	if p.todoPersist == nil {
		return
	}
	if err := p.todoPersist.SaveTodos(ctx, expID, p.todoFor(ctx, expID).List()); err != nil {
		log.Printf("[m2] todo save exp=%d: %v", expID, err)
	}
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
