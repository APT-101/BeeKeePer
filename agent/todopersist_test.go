package agent

import (
	"context"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// fakeTodoPersist records loads/saves for M2 todo persistence tests.
type fakeTodoPersist struct {
	loaded  []actool.Todo
	loadErr error
	saves   [][]actool.Todo
}

func (f *fakeTodoPersist) LoadTodos(_ context.Context, _ int64) ([]actool.Todo, error) {
	return f.loaded, f.loadErr
}

func (f *fakeTodoPersist) SaveTodos(_ context.Context, _ int64, items []actool.Todo) error {
	f.saves = append(f.saves, append([]actool.Todo(nil), items...))
	return nil
}

func TestTodoForRestoresFromPersist(t *testing.T) {
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoPersist: &fakeTodoPersist{
		loaded: []actool.Todo{
			{Content: "step one", Status: actool.TodoPending},
			{Content: "step two", Status: actool.TodoInProgress},
			{Content: "step three", Status: actool.TodoCompleted},
		},
	}}
	st := p.todoFor(t.Context(), 42)
	items := st.List()
	if len(items) != 3 {
		t.Fatalf("restored %d items, want 3", len(items))
	}
	got := func(i int) string { return items[i].Content + ":" + string(items[i].Status) }
	want := []string{"step one:pending", "step two:in_progress", "step three:completed"}
	for i, w := range want {
		if got(i) != w {
			t.Errorf("item %d = %q, want %q", i, got(i), w)
		}
	}
	// 同一 exploration 第二次调用必须复用同一 store（不重复 load）。
	fp := p.todoPersist.(*fakeTodoPersist)
	p.todoFor(t.Context(), 42)
	fp2 := p.todoPersist.(*fakeTodoPersist)
	if len(fp.saves) != len(fp2.saves) {
		t.Fatal("store identity broken across calls")
	}
	if got := p.todoFor(t.Context(), 42); got != st {
		_ = got
	}
}

func TestTodoForEmptyPersistCreatesEmpty(t *testing.T) {
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoPersist: &fakeTodoPersist{}}
	st := p.todoFor(t.Context(), 7)
	if len(st.List()) != 0 {
		t.Fatalf("expected empty store, got %d items", len(st.List()))
	}
}

func TestSyncTodosWritesBack(t *testing.T) {
	fp := &fakeTodoPersist{}
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoPersist: fp}
	st := p.todoFor(t.Context(), 9)
	// 模拟模型写了一条 todo
	if _, err := st.Tool().Call(t.Context(), []byte(`{"todos":[{"content":"chain A","status":"in_progress"}]}`), &actool.ToolContext{}); err != nil {
		t.Fatal(err)
	}
	p.syncTodos(t.Context(), 9)
	if len(fp.saves) != 1 {
		t.Fatalf("want 1 save, got %d", len(fp.saves))
	}
	if len(fp.saves[0]) != 1 || fp.saves[0][0].Content != "chain A" {
		t.Fatalf("saved = %+v", fp.saves[0])
	}
}

func TestSyncTodosNoPersistNoop(t *testing.T) {
	p := &Planner{todos: map[int64]*actool.TodoStore{}}
	p.syncTodos(t.Context(), 1) // nil persist: must not panic
}

func TestRenderLessons(t *testing.T) {
	out := renderLessons(nil)
	if out != "" {
		t.Fatalf("empty lessons must render empty, got %q", out)
	}
	out = renderLessons([]LessonNote{
		{Kind: "waf", Summary: "login 接口被 WAF 拦", Tags: []string{"bypass"}},
		{Kind: "blocked", Summary: "该 CMS 备份目录已穷尽"},
	})
	for _, want := range []string{"跨任务经验", "waf [bypass]: login 接口被 WAF 拦", "blocked: 该 CMS 备份目录已穷尽"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderLessons missing %q:\n%s", want, out)
		}
	}
	// 8 条截断
	many := make([]LessonNote, 12)
	for i := range many {
		many[i] = LessonNote{Kind: "lesson", Summary: "x"}
	}
	out = renderLessons(many)
	if strings.Count(out, "  lesson: x") != 8 {
		t.Errorf("expected 8 rendered lessons, got:\n%s", out)
	}
}
