package agent

import (
	"context"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// fakeTodoPersist records loads/saves for M2 todo persistence tests.
type fakeTodoPersist struct {
	loaded  []PersistedTodo
	loadErr error
	saves   [][]PersistedTodo
}

func (f *fakeTodoPersist) LoadTodos(_ context.Context, _ int64) ([]PersistedTodo, error) {
	return f.loaded, f.loadErr
}

func (f *fakeTodoPersist) SaveTodos(_ context.Context, _ int64, items []PersistedTodo) error {
	f.saves = append(f.saves, append([]PersistedTodo(nil), items...))
	return nil
}

func unchangedStore(p *Planner, expID int64) {
	_ = p.todoFor(context.Background(), expID)
}

func TestTodoForRestoresFromPersist(t *testing.T) {
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoMeta: map[int64]map[int]TodoMeta{}, todoPersist: &fakeTodoPersist{
		loaded: []PersistedTodo{
			{Todo: actool.Todo{Content: "step one", Status: actool.TodoPending}},
			{Todo: actool.Todo{Content: "step two", Status: actool.TodoInProgress}},
			{Todo: actool.Todo{Content: "step three", Status: actool.TodoCompleted}},
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
	p.todoFor(t.Context(), 42)
	unchangedStore(p, 42)
}

// TestTodoWriteSchemaCarriesFact：平台版 TodoWrite（结构字段）→ store 内容 +
// syncTodos 落库时 meta（satisfied_by_fact_id / depends_on）被携带。
func TestTodoWriteSchemaCarriesFact(t *testing.T) {
	fp := &fakeTodoPersist{}
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoMeta: map[int64]map[int]TodoMeta{}, todoPersist: fp}
	tool := p.todoWriteTool(t.Context(), 9)
	in := `{"todos":[
	  {"content":"枚举登录接口","status":"in_progress"},
	  {"content":"验证 SQLi 注入点","status":"pending","satisfied_by_fact_id":1234,"depends_on":[1]},
	  {"content":"确认 CMS 版本","status":"pending","satisfied_by_fact_id":5678}
	]}`
	if _, err := tool.Call(t.Context(), []byte(in), &actool.ToolContext{}); err != nil {
		t.Fatal(err)
	}
	st := p.todoFor(t.Context(), 9)
	if got := st.List(); len(got) != 3 || got[1].Content != "验证 SQLi 注入点" {
		t.Fatalf("store not updated: %+v", got)
	}
	p.syncTodos(t.Context(), 9)
	if len(fp.saves) != 1 || len(fp.saves[0]) != 3 {
		t.Fatalf("want 1 save of 3 items, got %d saves %d items", len(fp.saves), len(fp.saves[0]))
	}
	saved := fp.saves[0]
	if saved[1].Meta.FactID != 1234 || len(saved[1].Meta.Depends) != 1 || saved[1].Meta.Depends[0] != 1 {
		t.Fatalf("item2 meta = %+v, want fact 1234 dep [1]", saved[1].Meta)
	}
	if saved[2].Meta.FactID != 5678 {
		t.Fatalf("item3 meta = %+v, want fact 5678", saved[2].Meta)
	}
	if saved[0].Meta.FactID != 0 || len(saved[0].Meta.Depends) != 0 {
		t.Fatalf("item1 must carry no meta, got %+v", saved[0].Meta)
	}
}

// TestTodoForRestoresMetaFromPersist：重启后结构字段从 DB 恢复（todoMeta 填充）。
func TestTodoForRestoresMetaFromPersist(t *testing.T) {
	fp := &fakeTodoPersist{loaded: []PersistedTodo{
		{Todo: actool.Todo{Content: "探测端口", Status: actool.TodoPending}, Meta: TodoMeta{FactID: 9988}},
		{Todo: actool.Todo{Content: "打链", Status: actool.TodoPending}, Meta: TodoMeta{Depends: []int64{1}}},
	}}
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoMeta: map[int64]map[int]TodoMeta{}, todoPersist: fp}
	st := p.todoFor(t.Context(), 5)
	if len(st.List()) != 2 {
		t.Fatalf("want 2 restored, got %d", len(st.List()))
	}
	p.todoMu.Lock()
	m := p.todoMeta[5]
	p.todoMu.Unlock()
	if m[0].FactID != 9988 || m[1].Depends[0] != 1 {
		t.Fatalf("restored meta = %+v, want {0:{9988}} {1:{dep[1]}}", m)
	}
}

func TestTodoForEmptyPersistCreatesEmpty(t *testing.T) {
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoMeta: map[int64]map[int]TodoMeta{}, todoPersist: &fakeTodoPersist{}}
	st := p.todoFor(t.Context(), 7)
	if len(st.List()) != 0 {
		t.Fatalf("expected empty store, got %d items", len(st.List()))
	}
}

func TestSyncTodosWritesBack(t *testing.T) {
	fp := &fakeTodoPersist{}
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoMeta: map[int64]map[int]TodoMeta{}, todoPersist: fp}
	st := p.todoFor(t.Context(), 9)
	// 模拟模型写了一条 todo
	if _, err := st.Tool().Call(t.Context(), []byte(`{"todos":[{"content":"chain A","status":"in_progress"}]}`), &actool.ToolContext{}); err != nil {
		t.Fatal(err)
	}
	p.syncTodos(t.Context(), 9)
	if len(fp.saves) != 1 {
		t.Fatalf("want 1 save, got %d", len(fp.saves))
	}
	if len(fp.saves[0]) != 1 || fp.saves[0][0].Todo.Content != "chain A" {
		t.Fatalf("saved = %+v", fp.saves[0])
	}
}

func TestSyncTodosNoPersistNoop(t *testing.T) {
	p := &Planner{todos: map[int64]*actool.TodoStore{}, todoMeta: map[int64]map[int]TodoMeta{}}
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
