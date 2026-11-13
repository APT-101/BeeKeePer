package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/policy"
	"github.com/Autumn-27/artex/roe"
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

// m1EgressCheck is the guard's egress gate (docs §3.3) bound to this manager:
// extracts network targets from the tool call, matches them against the task's
// compiled egress policy (task_egress) and — on an out-of-scope hit — persists
// an egress_violations row, then reports deny/observe for the guard to enforce.
// Non-network calls, missing/uncompiled policy and DB errors fail open here
// (hard containment belongs to the container layer; this boundary is the
// host-mode defense-in-depth).
func (m *Manager) m1EgressCheck(ctx context.Context, tool string, input json.RawMessage) (bool, bool, string) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 || m.pg == nil {
		return false, false, ""
	}
	targets := roe.ExtractTargets(tool, input)
	if len(targets) == 0 {
		return false, false, ""
	}
	e, err := m.pg.GetTaskEgress(ri.TaskID)
	if err != nil || e == nil {
		return false, false, "" // 未编译/读取失败 → 放行（观察期）
	}
	// 匹配层恒严格（DenyDefault=true）：Allow 只回答"是否命中白名单"；
	// 是否阻断由本调用方按任务档位 deny_default 决定（观察模式放行但仍记录）。
	compiled := &roe.Compiled{
		DenyDefault: true,
		Rules:       []roe.EgressRule{{Domains: e.AllowDomains, IPs: e.AllowIPs, CIDRs: e.AllowCIDRs, Ports: intsToUint16(e.AllowPorts)}},
	}
	for _, tgt := range targets {
		allowed, reason := roe.Allow(tgt, compiled)
		if allowed {
			continue
		}
		_, lerr := m.pg.LogEgressViolation(&db.EgressViolation{
			TaskID: ri.TaskID, IntentID: ri.IntentID,
			Tool: tool, Target: tgt, Reason: reason, Blocked: e.DenyDefault,
		})
		if lerr != nil {
			// 落库失败不改变判定（guard 侧事件照发）
			return e.DenyDefault, !e.DenyDefault, reason
		}
		return e.DenyDefault, !e.DenyDefault, reason
	}
	return false, false, ""
}

// refreshTaskEgress (re)compiles a task's egress policy from its current scope
// + company assets and persists it into task_egress (docs §3.3). Called on
// task start and after scope changes; safe to call repeatedly (version bumps).
func (m *Manager) refreshTaskEgress(ctx context.Context, taskID int64) error {
	if m.pg == nil {
		return nil
	}
	store := m.pg.Assets()
	if store == nil {
		return nil
	}
	scope, err := store.ListTaskScope(taskID)
	if err != nil {
		return err
	}
	var assets []db.Asset
	companyIDs := map[int64]bool{}
	for _, s := range scope {
		if s.Kind == "company" && s.CompanyID != nil {
			companyIDs[*s.CompanyID] = true
		}
	}
	for cid := range companyIDs {
		rows, qerr := store.QueryByCompany(cid, "", 0, 0)
		if qerr != nil {
			continue // 公司资产缺失不阻断编译
		}
		for _, a := range rows {
			if a != nil {
				assets = append(assets, *a)
			}
		}
	}
	compiled, _ := roe.Compile(scope, assets)
	rule := roe.EgressRule{}
	if len(compiled.Rules) > 0 {
		rule = compiled.Rules[0]
	}
	return m.pg.UpsertTaskEgress(&db.TaskEgress{
		TaskID: taskID, CompiledFrom: "scope", DenyDefault: true, Version: compiled.Version,
		AllowDomains: rule.Domains, AllowIPs: rule.IPs, AllowCIDRs: rule.CIDRs, AllowPorts: uint16ToInts(rule.Ports),
	})
}

// intsToUint16 converts a port slice for roe matching.
func intsToUint16(in []int) []uint16 {
	out := make([]uint16, len(in))
	for i, p := range in {
		out[i] = uint16(p)
	}
	return out
}

// uint16ToInts converts a port slice back for persistence.
func uint16ToInts(in []uint16) []int {
	out := make([]int, len(in))
	for i, p := range in {
		out[i] = int(p)
	}
	return out
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
