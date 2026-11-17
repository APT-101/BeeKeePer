// M2 状态与记忆（docs §3.5/§4）：
//
//	M2-1 todo_items：planner 规划待办落库（DB 为真值，轮末全量替换，启动重建）。
//	M2-3 lesson_notes：跨任务经验库（record_lesson 写入，planner 唤醒可选注入）。
//
// 注意 pgx stdlib 不扫描数组列 → 数组读取一律 array_to_string，参数写入由 pgx 编码。
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// nulls maps an empty string to NULL for optional text columns.
func nulls(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// TodoItem mirrors the persisted attack-chain todo row (subset of
// schema §M2-1 todo_items), mapped to/from the planner's actool.Todo list.
type TodoItem struct {
	Seq     int
	Title   string
	Status  string // pending | in_progress | completed | blocked | dropped
	Note    string
	Blocked string
	Depends []int64
	FactID  sql.NullInt64
	Version int
	Updated time.Time
}

// ReplaceTodos atomically replaces the task's todo list (DELETE + INSERT in one
// transaction). seq follows slice order — the source of truth is the planner's
// store snapshot written at round end.
func (d *DB) ReplaceTodos(ctx context.Context, expID int64, items []TodoItem) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM todo_items WHERE exploration_id=$1`, expID); err != nil {
		return fmt.Errorf("todo wipe: %w", err)
	}
	for i, it := range items {
		seq := i + 1
		if it.Seq > 0 {
			seq = it.Seq
		}
		status := it.Status
		if status == "" {
			status = "pending"
		}
		fact := sql.NullInt64{}
		if it.FactID.Valid {
			fact = it.FactID
		}
		dep := it.Depends
		if dep == nil {
			dep = []int64{}
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO todo_items (exploration_id, seq, title, status, depends_on, satisfied_by_fact_id, blocked_reason, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			expID, seq, it.Title, status, dep, fact, nulls(it.Blocked), it.Note); err != nil {
			return fmt.Errorf("todo insert #%d: %w", seq, err)
		}
	}
	return tx.Commit()
}

// LoadTodos returns the task's persisted todo list in seq order (empty slice when
// none). Restores the planner store on wake-up after a restart.
func (d *DB) LoadTodos(ctx context.Context, expID int64) ([]TodoItem, error) {
	rows, err := d.QueryContext(ctx, `
SELECT seq, title, status, COALESCE(blocked_reason,''), note,
       array_to_string(depends_on, ','),
       COALESCE(satisfied_by_fact_id,0),
       version
FROM todo_items WHERE exploration_id=$1 ORDER BY seq`, expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TodoItem{}
	for rows.Next() {
		var it TodoItem
		var depStr string
		var fact sql.NullInt64
		if err := rows.Scan(&it.Seq, &it.Title, &it.Status, &it.Blocked, &it.Note, &depStr, &fact, &it.Version); err != nil {
			return nil, err
		}
		it.FactID = fact
		if depStr != "" {
			for _, p := range strings.Split(depStr, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				var v int64
				if _, err := fmt.Sscanf(p, "%d", &v); err == nil {
					it.Depends = append(it.Depends, v)
				}
			}
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkTodoSatisfied 自动推进 M2 todo 依赖闭环（docs §8.10）：某 fact 节点落图后，
// 把本 exploration 内 satisfied_by_fact_id 指向该 fact、且尚未完成（pending/
// in_progress）的 todo 确定性标记为 completed——"意图产出 → 子目标达成"不再依赖
// 模型自觉，而是由系统在 fact 写入侧补丁（纯旁路，调用失败不阻断 fact 写入）。
// 返回被升级的 todo 行数。
func (s *ExplorationStore) MarkTodoSatisfied(ctx context.Context, factID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE todo_items
SET status = 'completed',
    note = COALESCE(note, '') || '[auto] satisfied by fact #' || $2::text
WHERE exploration_id = $1 AND satisfied_by_fact_id = $2
  AND status IN ('pending', 'in_progress')`, s.expID, factID)
	if err != nil {
		return 0, fmt.Errorf("todo auto-satisfy: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// LessonNote is one cross-task lesson (schema §M2-3).
type LessonNote struct {
	ID             int64
	SourceTaskID   sql.NullInt64
	SourceIntentID sql.NullInt64
	Kind           string // blocked | exhausted | waf | lesson | misconfig
	Summary        string
	Detail         map[string]any
	Tags           []string
	CreatedAt      time.Time
}

// LessonCountSince 统计某源 (task,intent) 在 since 内同 kind 的 lesson 条数——
// worker 撞墙自动沉淀（§8.8）的去重限流：同源短时间重复撞墙不重复写经验。
func (d *DB) LessonCountSince(ctx context.Context, kind string, taskID, intentID int64, since time.Duration) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `
SELECT count(*) FROM lesson_notes
WHERE kind=$1 AND source_task_id=$2 AND source_intent_id=$3
  AND created_at > now() - make_interval(secs => $4)`,
		kind, nullInt64(taskID), nullInt64(intentID), int64(since.Seconds())).Scan(&n)
	return n, err
}

// AddLesson records one lesson. detail must be JSON-serializable.
func (d *DB) AddLesson(ctx context.Context, l *LessonNote) (int64, error) {
	detailJSON := []byte("{}")
	if len(l.Detail) > 0 {
		if b, err := json.Marshal(l.Detail); err == nil {
			detailJSON = b
		}
	}
	tags := l.Tags
	if tags == nil {
		tags = []string{}
	}
	src := sql.NullInt64{}
	if l.SourceTaskID.Valid {
		src = l.SourceTaskID
	}
	sii := sql.NullInt64{}
	if l.SourceIntentID.Valid {
		sii = l.SourceIntentID
	}
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO lesson_notes (source_task_id, source_intent_id, kind, summary, detail, tags)
VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		src, sii, l.Kind, l.Summary, detailJSON, tags).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("lesson insert: %w", err)
	}
	return id, nil
}

// ListRecentLessons returns the newest lessons across tasks. excludeTaskID skips
// the current task's own notes (跨任务才叫经验). tag filters optionally (single).
// Tags are read via array_to_string (pgx stdlib doesn't scan arrays).
func (d *DB) ListRecentLessons(ctx context.Context, excludeTaskID int64, tag, kind string, limit int) ([]LessonNote, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	q := `SELECT id, COALESCE(source_task_id,0), COALESCE(source_intent_id,0), kind, summary,
       COALESCE(detail::text,'{}'), array_to_string(tags, ','), created_at
       FROM lesson_notes WHERE 1=1`
	args := []any{}
	if excludeTaskID > 0 {
		args = append(args, excludeTaskID)
		q += fmt.Sprintf(" AND COALESCE(source_task_id,0) <> $%d", len(args))
	}
	if tag != "" {
		args = append(args, tag)
		q += fmt.Sprintf(" AND $%d = ANY(tags)", len(args))
	}
	if kind != "" {
		args = append(args, kind)
		q += fmt.Sprintf(" AND kind = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LessonNote{}
	for rows.Next() {
		var l LessonNote
		var srcID, sii int64
		var detailStr, tagsStr string
		if err := rows.Scan(&l.ID, &srcID, &sii, &l.Kind, &l.Summary, &detailStr, &tagsStr, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.SourceTaskID = sql.NullInt64{Int64: srcID, Valid: srcID > 0}
		l.SourceIntentID = sql.NullInt64{Int64: sii, Valid: sii > 0}
		_ = json.Unmarshal([]byte(detailStr), &l.Detail)
		if tagsStr != "" {
			l.Tags = strings.Split(tagsStr, ",")
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
