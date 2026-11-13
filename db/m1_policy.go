package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/policy"
)

// TaskEgress is one compiled RoE egress policy row for a task (task_egress).
type TaskEgress struct {
	TaskID       int64     `json:"task_id"`
	CompiledFrom string    `json:"compiled_from"`
	AllowDomains []string  `json:"allow_domains"`
	AllowIPs     []string  `json:"allow_ips"`
	AllowCIDRs   []string  `json:"allow_cidrs"`
	AllowPorts   []int     `json:"allow_ports"`
	DenyDefault  bool      `json:"deny_default"`
	Version      int       `json:"version"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// EgressViolation is one out-of-scope egress attempt (egress_violations).
type EgressViolation struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	IntentID  int64     `json:"intent_id,omitempty"`
	Tool      string    `json:"tool"`
	Target    string    `json:"target"`
	Reason    string    `json:"reason"`
	Blocked   bool      `json:"blocked"`
	CreatedAt time.Time `json:"created_at"`
}

// GetTaskPolicy reads a task's operation-policy tier; "" when the task is
// missing (caller treats "" as full).
func (d *DB) GetTaskPolicy(taskID int64) (string, error) {
	var level string
	err := d.QueryRow(`SELECT COALESCE(op_policy,'full') FROM tasks WHERE id=$1`, taskID).Scan(&level)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return level, nil
}

// SetTaskPolicy updates a task's operation-policy tier (validated). Returns
// (false, nil) when the task does not exist.
func (d *DB) SetTaskPolicy(taskID int64, level string) (bool, error) {
	if !policy.IsValid(level) {
		return false, errors.New("op_policy 必须是 passive/active/full")
	}
	res, err := d.Exec(`UPDATE tasks SET op_policy=$1 WHERE id=$2`, level, taskID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// UpsertTaskEgress replaces a task's compiled egress policy (one row per task).
// Array columns are passed as PG array literals (see marshalStringArray) and
// cast explicitly so INET[]/CIDR[] parse the literal. Egress with Version<=0
// is rejected — the version is the compile source of truth.
func (d *DB) UpsertTaskEgress(e *TaskEgress) error {
	if e == nil {
		return errors.New("nil egress")
	}
	if e.Version <= 0 {
		return errors.New("egress version must be > 0")
	}
	_, err := d.Exec(`
INSERT INTO task_egress (task_id, compiled_from, allow_domains, allow_ips, allow_cidrs, allow_ports, deny_default, version, updated_at)
VALUES ($1,$2,CAST($3 AS text[]),CAST($4 AS inet[]),CAST($5 AS cidr[]),CAST($6 AS int[]),$7,$8,now())
ON CONFLICT (task_id) DO UPDATE SET
    compiled_from=EXCLUDED.compiled_from, allow_domains=EXCLUDED.allow_domains,
    allow_ips=EXCLUDED.allow_ips, allow_cidrs=EXCLUDED.allow_cidrs,
    allow_ports=EXCLUDED.allow_ports, deny_default=EXCLUDED.deny_default,
    version=EXCLUDED.version, updated_at=now()`,
		e.TaskID, e.CompiledFrom, marshalStringArray(e.AllowDomains), marshalStringArray(e.AllowIPs),
		marshalStringArray(e.AllowCIDRs), marshalStringArray(intsToStrings(e.AllowPorts)), e.DenyDefault, e.Version)
	return err
}

// GetTaskEgress reads a task's compiled egress policy; nil when absent. Array
// columns are flattened server-side: pgx stdlib does not register TEXT[]/INET[]
// array scanning in this codebase's connection mode, so the query joins the
// array elements with a unit separator (\x1f) and ints with commas.
func (d *DB) GetTaskEgress(taskID int64) (*TaskEgress, error) {
	var e TaskEgress
	var domains, ips, cidrs, portList string
	err := d.QueryRow(`
SELECT task_id, compiled_from,
       array_to_string(allow_domains, E'\x1f'),
       array_to_string(allow_ips, E'\x1f'),
       array_to_string(allow_cidrs, E'\x1f'),
       array_to_string(allow_ports, ','),
       deny_default, version, updated_at
FROM task_egress WHERE task_id=$1`, taskID).
		Scan(&e.TaskID, &e.CompiledFrom, &domains, &ips, &cidrs, &portList, &e.DenyDefault, &e.Version, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.AllowDomains = splitNonEmpty(domains, "\x1f")
	e.AllowIPs = splitNonEmpty(ips, "\x1f")
	e.AllowCIDRs = splitNonEmpty(cidrs, "\x1f")
	for _, p := range splitNonEmpty(portList, ",") {
		if n, err := strconv.Atoi(p); err == nil {
			e.AllowPorts = append(e.AllowPorts, n)
		}
	}
	return &e, nil
}

// splitNonEmpty splits s by sep and drops empty fragments (empty array → []).
func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LogEgressViolation records one out-of-scope egress attempt; returns the new id.
func (d *DB) LogEgressViolation(v *EgressViolation) (int64, error) {
	if v == nil {
		return 0, errors.New("nil violation")
	}
	var intentID any
	if v.IntentID > 0 {
		intentID = v.IntentID
	}
	var id int64
	err := d.QueryRow(`
INSERT INTO egress_violations (task_id, intent_id, tool, target, reason, blocked)
VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		v.TaskID, intentID, v.Tool, v.Target, v.Reason, v.Blocked).Scan(&id)
	return id, err
}

// ListEgressViolations returns a task's recent egress violations (newest first).
func (d *DB) ListEgressViolations(taskID int64, limit int) ([]EgressViolation, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Query(`
SELECT id, task_id, COALESCE(intent_id,0), tool, target, reason, blocked, created_at
FROM egress_violations WHERE task_id=$1
ORDER BY created_at DESC, id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EgressViolation
	for rows.Next() {
		var v EgressViolation
		if err := rows.Scan(&v.ID, &v.TaskID, &v.IntentID, &v.Tool, &v.Target, &v.Reason, &v.Blocked, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func intsToStrings(is []int) []string {
	out := make([]string, len(is))
	for i, v := range is {
		out[i] = fmt.Sprint(v)
	}
	return out
}
