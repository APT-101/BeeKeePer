package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// =====================================================================
// 固件上传（IoT 模块，移植自 ARTEX-IOT 并适配本项目）
//
// 固件走独立入口，不和普通附件/工作空间上传混用：文件直接落到
// tasks/<taskID>/firmware/——这是 agent 的 register_extract / locateFirmwareFile
// 约定的固件目录，落对位置解包链路才能找到它。落盘时算 sha256 返回给前端；
// 解包登记（extract_path）不在这里写——由 worker 解包后调 register_extract 登记。
// =====================================================================

// maxFirmwareSize caps one firmware upload.
const maxFirmwareSize = 1 << 30 // 1 GiB

// POST /api/tasks/{id}/firmware   multipart 表单字段 "file"（单文件）
func (s *Server) taskFirmwareUpload(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "任务 id 无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFirmwareSize)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "解析上传失败或超过 1GB 上限: "+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, http.StatusBadRequest, "缺少上传文件（表单字段 file）")
		return
	}
	hdr := files[0]

	dir := filepath.Join(filepath.Clean(s.m.dir), "tasks", t.ID, "firmware")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建固件目录失败: "+err.Error())
		return
	}
	name := sanitizeFilename(filepath.Base(hdr.Filename))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		writeErr(w, http.StatusBadRequest, "非法文件名")
		return
	}

	// 先落临时文件再判重：同名且内容一致 → 复用（删临时）；内容不同 → 文件名插摘要前缀，绝不覆盖。
	tmp := filepath.Join(dir, ".uploading-"+name)
	if err := saveUpload(hdr, tmp); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存固件失败: "+err.Error())
		return
	}
	sum, err := fileSHA256Hex(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "计算 sha256 失败: "+err.Error())
		return
	}
	size := hdr.Size

	dest := filepath.Join(dir, name)
	reused := false
	if _, statErr := os.Stat(dest); statErr == nil {
		if existSum, hErr := fileSHA256Hex(dest); hErr == nil && existSum == sum {
			_ = os.Remove(tmp)
			reused = true
		} else {
			name = digestSuffixName(name, sum)
			dest = filepath.Join(dir, name)
		}
	}
	if !reused {
		if err := os.Rename(tmp, dest); err != nil {
			_ = os.Remove(tmp)
			writeErr(w, http.StatusInternalServerError, "保存固件失败: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":   name,
		"sha256": sum,
		"size":   size,
		"path":   s.wsRel(dest), // 工作空间视角的相对路径（dataDir 起）
		"reused": reused,
	})
}

// digestSuffixName inserts the first 8 hex chars of the digest before the extension:
// RP09.bin → RP09_3f9a1c2d.bin，让同名不同内容的固件并存在同一任务里。
func digestSuffixName(name, sum string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s_%s%s", stem, sum[:8], ext)
}
