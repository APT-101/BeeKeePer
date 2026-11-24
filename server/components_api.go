package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// =====================================================================
// IoT 固件组件 HTTP API（移植自 ARTEX-IOT 分支）
// 组件与 assets 是并行体系；组件库是全局共享的，task_id 参数用于视角过滤。
// =====================================================================

// componentStore 是组件 handlers 的统一入口（nil = 无 DB，全部 503）。
func (s *Server) componentStore() *db.ComponentStore {
	return s.m.Components()
}

// GET /api/firmware-extracts —— 全部固件解包登记（按 sha256 去重，组件页固件下拉用）。
func (s *Server) firmwareExtracts(w http.ResponseWriter, r *http.Request) {
	if s.m.PG() == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	rows, err := s.m.FirmwareExtracts().ListAllExtracts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	extracts := []map[string]any{}
	for _, f := range rows {
		if f.Sha256 == "" {
			continue
		}
		extracts = append(extracts, map[string]any{
			"sha256":  f.Sha256,
			"name":    f.Name,
			"note":    f.Note,
			"task_id": f.TaskID,
		})
	}
	writeJSON(w, 200, map[string]any{"extracts": extracts})
}

const (
	defaultComponentPageSize = 50
	maxComponentPageSize     = 200
)

// GET /api/components
func (s *Server) listComponents(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query()
	typ := q.Get("type")
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = defaultComponentPageSize
	} else if limit > maxComponentPageSize {
		limit = maxComponentPageSize
	}
	if offset < 0 {
		offset = 0
	}

	components := []*db.Component{}
	var err error
	// total is the full match count ignoring limit/offset. Count first so an offset
	// beyond the last row can return an empty page without an expensive scan.
	total := 0

	// firmware=<sha256> 时按固件归属过滤：拼成 DSL 子句，与 dsl/type/status 同一条路径，
	// 保证 total 和分页口径一致（组件可能在多固件任务里复用，这是唯一能按固件切开的维度）。
	dsl := strings.TrimSpace(q.Get("dsl"))
	if fw := strings.TrimSpace(q.Get("firmware")); fw != "" {
		if !isSha256Hex(fw) {
			writeErr(w, http.StatusBadRequest, "firmware 需要 64 位十六进制 sha256")
			return
		}
		clause := "firmware_sha256==" + fw
		if dsl == "" {
			dsl = clause
		} else {
			dsl = "(" + dsl + ") AND " + clause
		}
	}
	if dsl != "" {
		if err := db.ValidateComponentDSL(dsl); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// task_id scopes the DSL search to a task's components (the task detail
		// "测试组件" search); 0 means the global component view.
		taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
		total, err = as.CountDSL(dsl, typ, q.Get("status"), taskID)
		if err == nil && offset < total {
			components, err = as.QueryDSL(dsl, typ, q.Get("status"), taskID, limit, offset)
		}
	} else {
		taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
		components, total, err = as.ListComponents(db.ComponentFilter{
			Type: typ, Status: q.Get("status"), TaskID: taskID, Limit: limit, Offset: offset,
		})
	}

	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"count":      len(components),
		"total":      total,
		"components": components,
	})
}

// GET /api/components/counts
// isSha256Hex reports whether v is a 64-char lowercase/uppercase hex string.
func isSha256Hex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func (s *Server) componentCounts(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	// by=firmware 时按固件 sha256 汇总（组件页的固件筛选下拉用）。
	if r.URL.Query().Get("by") == "firmware" {
		counts, err := as.FirmwareCounts(taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, counts)
		return
	}
	// by=status 时按挖掘状态汇总（任务详情「组件」页的进度按钮用），默认按类型汇总。
	if r.URL.Query().Get("by") == "status" {
		counts, err := as.StatusCounts(taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, counts)
		return
	}
	counts, err := as.CountsByType(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, counts)
}

// DELETE /api/components
func (s *Server) deleteComponents(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "ids required")
		return
	}
	deleted, err := as.DeleteByIDs(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted})
}

// POST /api/components
func (s *Server) insertComponentsHTTP(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		TaskID         int64               `json:"task_id"`
		Components     []db.ComponentInput `json:"components"`
		Type           string              `json:"type"`
		ComponentName  string              `json:"component_name"`
		Version        string              `json:"version"`
		Vendor         string              `json:"vendor"`
		BinaryPath     string              `json:"binary_path"`
		ConfigPath     string              `json:"config_path"`
		StartedBy      string              `json:"started_by"`
		FirmwareSha256 string              `json:"firmware_sha256"`
		Port           int                 `json:"port"`
		Technologies   []string            `json:"technologies"`
		Notes          string              `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	items := req.Components
	if len(items) == 0 {
		items = []db.ComponentInput{{
			Type: req.Type, Name: req.ComponentName, Version: req.Version,
			Vendor: req.Vendor, BinaryPath: req.BinaryPath, ConfigPath: req.ConfigPath,
			StartedBy: req.StartedBy, FirmwareSha256: req.FirmwareSha256,
			Port: req.Port, Technologies: req.Technologies, Notes: req.Notes,
		}}
	}
	var taskIDs []int64
	if req.TaskID > 0 {
		taskIDs = []int64{req.TaskID}
	}
	inserted, updated, ids, err := as.UpsertComponents(taskIDs, items)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.TaskID > 0 {
		for _, id := range ids {
			_ = as.SetTaskComponentSource(req.TaskID, id, "api", "通过组件 API 登记", nil)
		}
	}
	writeJSON(w, 200, map[string]any{"inserted": inserted, "updated": updated, "ids": ids})
}

// POST /api/components/{id}/status
func (s *Server) setComponentStatusHTTP(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid component id")
		return
	}
	var req struct {
		Status string `json:"status"`
		TaskID int64  `json:"task_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	// 带 task_id 时按任务守卫（与 set_component_status 工具同一口径：只有该任务范围内的
	// 组件才能改状态）；不带则是组件库全局视角。
	taskID := req.TaskID
	if taskID <= 0 {
		taskID, _ = strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	}
	if err := as.SetTaskComponentStatus(taskID, id, req.Status); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": req.Status})
}

// POST /api/components/status —— 批量改状态（组件库多选后用）。
func (s *Server) batchComponentStatus(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		IDs    []int64 `json:"ids"`
		Status string  `json:"status"`
		TaskID int64   `json:"task_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "ids required")
		return
	}
	if len(req.IDs) > 2000 {
		writeErr(w, 400, "一次最多改 2000 个")
		return
	}
	changed, err := as.SetComponentsStatus(req.TaskID, req.IDs, req.Status)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": req.Status, "changed": changed, "requested": len(req.IDs)})
}
