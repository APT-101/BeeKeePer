package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// =====================================================================
// 任务 ↔ 组件挂载 API（IoT 固件审计，移植自 ARTEX-IOT 分支）
// 原 fork 中本文件还包含 save_poc 的 PoC 浏览/下载 handlers——那是 PoC 体系
// 的一部分，本项目没有 save_poc，故不移植。
// =====================================================================

const maxTaskComponentRequestBytes = 512 << 10

func writeTaskComponentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrTaskComponentInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrTaskComponentTaskNotFound), errors.Is(err, db.ErrTaskComponentComponentNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

// POST /api/tasks/{id}/components
// body: {component_ids:[...], source_summary:"…"}（scope 登记已下线，保留拒绝语义）
func (s *Server) attachTaskComponents(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskComponentRequestBytes)
	var request struct {
		ComponentIDs  []int64            `json:"component_ids"`
		SourceSummary string             `json:"source_summary"`
		Scope         companyScopeInputs `json:"scope"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	request.SourceSummary = strings.TrimSpace(request.SourceSummary)
	taskID, _ := parseTaskID(task.ID)
	if request.Scope != nil && len(request.ComponentIDs) > 0 {
		writeErr(w, http.StatusBadRequest, "scope 与 component_ids 不能同时提交")
		return
	}
	if request.Scope != nil {
		writeErr(w, http.StatusBadRequest, "组件不参与网络范围登记：请用 component_ids 挂载组件")
		return
	}
	mutation, err := s.m.Components().AttachComponentsToTask(taskID, request.ComponentIDs, request.SourceSummary)
	if err != nil {
		writeTaskComponentError(w, err)
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, mutation)
}

// DELETE /api/tasks/{id}/components/{componentID}
func (s *Server) detachTaskComponent(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	componentID, ok := pathInt(r, "componentID")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad component id")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	detached, err := s.m.Components().DetachComponentFromTask(taskID, componentID)
	if err != nil {
		writeTaskComponentError(w, err)
		return
	}
	if !detached {
		writeErr(w, http.StatusNotFound, "component is not associated with this task")
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, map[string]any{"detached": componentID})
}

// GET /api/tasks/{id}/intent-components —— 意图锚定的组件（覆盖度/来源展示用）。
func (s *Server) taskIntentComponents(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	components, err := s.m.Components().IntentComponents(taskID)
	if err != nil {
		writeTaskComponentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": components})
}
