package server

// =====================================================================
// staging 附件迁移：建任务前经 scope=staging 上传的 chat 附件落在
// drafts/<draftID>/uploads/，前端把其绝对路径写进任务描述。任务一旦
// 创建，这些文件与任务目录彻底脱钩——任务 306 实测：21MB 固件整轮
// 留在 drafts，agent 靠 fact 912 逐点探测才找到它，extracts/反编译
// 链全程缺位。
//
// migrateStagingAttachments 在 createTask 成功后执行：
//   1. 从描述里提取 drafts/<draftID>/uploads 引用，定位暂存目录；
//   2. 全部文件搬进 tasks/<taskID>/uploads/（uniqueUploadPath 防覆盖），
//      固件类（firmwareLike）同时镜像到 firmware/（mirrorToFirmwareDir）；
//   3. 描述里的 drafts 绝对路径前缀改写为任务 uploads 绝对路径，落库
//      （SetTaskDescription），agent 读到的不再是指向已搬走文件的死路径。
// =====================================================================

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// draftsRefRe 从任务描述里提取 staging 附件目录引用（绝对或相对形式），
// 捕获 draftID（safeChatID 同款约束）。
var draftsRefRe = regexp.MustCompile(`drafts[/\\]([A-Za-z0-9_-]+)[/\\]uploads`)

// migrateStagingAttachments moves pre-creation staging attachments into the task
// workspace and rewrites the description. Returns the (possibly rewritten)
// description; best-effort — failures log and leave the description untouched so
// the agent at least sees the original absolute paths.
func (s *Server) migrateStagingAttachments(taskID string, description string) string {
	ids := draftsRefRe.FindAllStringSubmatch(description, -1)
	if len(ids) == 0 {
		return description
	}
	seen := map[string]bool{}
	var drafts []string
	for _, m := range ids {
		if !seen[m[1]] {
			seen[m[1]] = true
			drafts = append(drafts, m[1])
		}
	}
	taskUploads := filepath.Join(filepath.Clean(s.m.dir), "tasks", taskID, "uploads")
	moved := 0
	for _, draftID := range drafts {
		dir := filepath.Join(filepath.Clean(s.m.dir), "drafts", draftID, "uploads")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // 暂存目录不存在/已清空：描述引用可能是陈旧的，跳过
		}
		if err := os.MkdirAll(taskUploads, 0o755); err != nil {
			continue
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			src := filepath.Join(dir, ent.Name())
			size := int64(0)
			if info, ierr := ent.Info(); ierr == nil {
				size = info.Size()
			}
			dest := uniqueUploadPath(taskUploads, ent.Name())
			if err := os.Rename(src, dest); err != nil {
				continue
			}
			moved++
			// 固件类：镜像到 firmware/（mirrorToFirmwareDir 内含 sha256/去重）
			if firmwareLike(filepath.Base(dest), size) {
				s.mirrorToFirmwareDir(taskID, taskUploads, filepath.Base(dest))
			}
		}
	}
	if moved == 0 {
		return description
	}
	// 描述改写：drafts/<id>/uploads 的绝对路径段 → 任务 uploads 绝对路径。
	// 只替换前缀段（文件名保持原样），替换次序无关（各 draft 前缀互不为前缀）。
	newDesc := description
	for _, draftID := range drafts {
		oldPrefix := filepath.Join(filepath.Clean(s.m.dir), "drafts", draftID, "uploads")
		newPrefix := taskUploads
		newDesc = strings.ReplaceAll(newDesc, oldPrefix, newPrefix)
		// 反斜杠变体（Windows 形态的路径也可能被写进描述）
		newDesc = strings.ReplaceAll(newDesc, strings.ReplaceAll(oldPrefix, "/", "\\"), strings.ReplaceAll(newPrefix, "/", "\\"))
	}
	fmt.Printf("[staging] task %s 迁移暂存附件 %d 个（drafts=%v）\n", taskID, moved, drafts)
	if newDesc != description {
		id, perr := strconv.ParseInt(taskID, 10, 64)
		if perr != nil {
			return description
		}
		if err := s.m.PG().SetTaskDescription(id, newDesc); err != nil {
			fmt.Printf("[staging] task %s 描述改写失败（附件已迁移，路径仍为 drafts）: %v\n", taskID, err)
			return description
		}
	}
	return newDesc
}
