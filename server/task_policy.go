package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/policy"
)

// m1PolicyLevel resolves the current run's operation-policy tier from the
// hook context. Chat / non-task runs, unknown tasks, DB read failures, and
// the full tier all yield ok=false — the M1 gate is then disabled and the
// pre-M1 path runs unchanged (fail-open by design; hard enforcement belongs
// to the sandbox/egress layer, not the in-hook gate).
func (m *Manager) m1PolicyLevel(ctx context.Context) (policy.Level, bool) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 || m.pg == nil {
		return "", false
	}
	lvl, err := m.pg.GetTaskPolicy(ri.TaskID)
	if err != nil || !policy.IsValid(lvl) || lvl == string(policy.Full) {
		return "", false
	}
	return policy.Level(lvl), true
}

// getTaskPolicy reports a task's operation-policy tier (M1).
func (s *Server) getTaskPolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	level, err := s.m.pg.GetTaskPolicy(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"op_policy": level})
}

// setTaskPolicy updates a task's operation-policy tier. The change is written
// to the M0 config audit log (before/after). Egress re-compilation for the new
// tier happens on the next task start / scope change (roe.Compile).
func (s *Server) setTaskPolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		OpPolicy string `json:"op_policy"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	before, _ := s.m.pg.GetTaskPolicy(id)
	changed, err := s.m.pg.SetTaskPolicy(id, req.OpPolicy)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !changed {
		writeErr(w, 404, "task not found")
		return
	}
	s.auditConfig("task.policy_update", "task", t.ID,
		map[string]any{"op_policy": before}, map[string]any{"op_policy": req.OpPolicy})
	writeJSON(w, 200, map[string]any{"op_policy": req.OpPolicy})
}
