package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// maxChatUpload caps a single chat-attachment upload request (memory + spill).
const maxChatUpload = 512 << 20 // 512 MiB（大 APK/固件包前台直传；MobSF 上传上限 1GB，此处对齐到一半）

// safeChatID guards the {id} path segment against traversal — task ids are numeric,
// session ids are alnum/_/- ; anything with "/" or ".." is rejected.
var safeChatID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// chatAttachment is one uploaded file as the frontend + agent see it. Path is relative
// to the chat's working dir (e.g. "uploads/report.txt"), which is the agent's CWD, so
// it can Read/Bash the file directly; Name/Size drive the UI card.
type chatAttachment struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Abs 是落盘的绝对路径(m.dir 已是绝对)。建任务前暂存(scope=staging)时前端要用它把
	// 提示词写进描述;task/session 走 composeAgentMessage 在后端拼路径,不依赖此字段。
	Abs string `json:"abs,omitempty"`
	// Firmware=true 表示这是固件类附件，已镜像到 tasks/<id>/firmware/（固件链路
	// 约定目录），Sha256 是其摘要。composeAgentMessage 据此给 agent 注入
	// register_extract 指引；非固件附件两字段为空。
	Firmware bool   `json:"firmware,omitempty"`
	Sha256   string `json:"sha256,omitempty"`
	// FirmwareName 是 firmware/ 目录下的实际文件名（同名不同内容时带 digest 后缀）。
	FirmwareName string `json:"firmware_name,omitempty"`
}

// firmwareExtRe 固件/固件包扩展名白名单（厂商升级包几乎都是归档或镜像形态）。
var firmwareExtRe = regexp.MustCompile(`(?i)\.(zip|tar|gz|tgz|bz2|xz|7z|rar|img|bin|fw|pak|rom|cap|ubi|swu|dfu|enc|dat|bin_holder)$`)

// firmwareLike 判定一个 chat 附件是否走固件链路：固件/归档扩展名 + ≥1MiB
// （厂商升级包最小也在 MB 级；小文件误判成本高收益低）。
func firmwareLike(name string, size int64) bool {
	return size >= 1<<20 && firmwareExtRe.MatchString(strings.ToLower(name))
}

// chatUpload implements method-1 file support: it saves one or more files into a chat's
// working dir under uploads/, so the agent opens them with its existing Read/Bash tools
// and the sent message carries their paths. No LLM-layer change, no multimodal.
//
// POST /api/chat/upload?scope=task|session|staging&id=<id>, multipart field "file"
// (repeatable). Returns {attachments:[{name,path,size,abs}]}. Target dir mirrors the
// agent CWD layout:
//
//	scope=task    → <workDir>/tasks/<id>/uploads/
//	scope=session → <workDir>/sessions/<id>/uploads/
//	scope=staging → <workDir>/drafts/<id>/uploads/   (建任务前暂存:任务尚无 ID,
//	                文件先落这里,前端按返回的 abs 绝对路径写进任务描述)
func (s *Server) chatUpload(w http.ResponseWriter, r *http.Request) {
	var sub string
	taskScoped := false
	switch r.URL.Query().Get("scope") {
	case "task":
		sub = "tasks"
		taskScoped = true
	case "session":
		sub = "sessions"
	case "staging":
		sub = "drafts"
	default:
		writeErr(w, 400, "scope 必须是 task / session / staging")
		return
	}
	id := r.URL.Query().Get("id")
	if !safeChatID.MatchString(id) {
		writeErr(w, 400, "非法 id")
		return
	}
	if taskScoped {
		if s.m.ResolveTask(id) == nil {
			writeErr(w, 404, "task not found")
			return
		}
		if !s.engine.beginTaskOperation(id) {
			writeErr(w, http.StatusConflict, "任务正在删除，无法上传附件")
			return
		}
		defer s.engine.decInflight(id)
	}
	dir := filepath.Join(s.m.dir, sub, id, "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "建目录失败: "+err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制: "+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "缺少上传文件(表单字段 file)")
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			continue
		}
		dest := uniqueUploadPath(dir, name)
		if err := saveUpload(hdr, dest); err != nil {
			writeErr(w, 500, "保存失败: "+err.Error())
			return
		}
		base := filepath.Base(dest)
		att := chatAttachment{Name: base, Path: "uploads/" + base, Size: hdr.Size, Abs: dest}
		// 固件类附件（task 作用域）镜像到 tasks/<id>/firmware/ 并算 sha256：
		// firmware/ 是 register_extract / locateFirmwareFile / 反编译链约定的
		// 固件目录，chat 附件此前不入这条链，任务 306 实测 extracts/反编译全程缺位。
		if taskScoped && firmwareLike(base, hdr.Size) {
			if fwName, sha := s.mirrorToFirmwareDir(id, dir, base); fwName != "" {
				att.Firmware = true
				att.Sha256 = sha
				att.FirmwareName = fwName
			}
		}
		out = append(out, att)
	}
	writeJSON(w, 200, map[string]any{"attachments": out})
}

// mirrorToFirmwareDir 把 uploads/ 里的固件附件复制一份到 tasks/<taskID>/firmware/
// （同内容已存在则复用，不同内容按 digest 插摘要后缀并存），返回 firmware 目录下的
// 文件名与 sha256。失败静默返回空——uploads/ 里的原件仍可用，固件链路是增强。
func (s *Server) mirrorToFirmwareDir(taskID, uploadsDir, name string) (string, string) {
	src := filepath.Join(uploadsDir, name)
	sum, err := fileSHA256Hex(src)
	if err != nil || sum == "" {
		return "", ""
	}
	dir := filepath.Join(filepath.Clean(s.m.dir), "tasks", taskID, "firmware")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", ""
	}
	dest := filepath.Join(dir, name)
	if _, statErr := os.Stat(dest); statErr == nil {
		if existSum, hErr := fileSHA256Hex(dest); hErr == nil && existSum == sum {
			return name, sum // 同内容已就位，复用
		}
		name = digestSuffixName(name, sum)
		dest = filepath.Join(dir, name)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", ""
	}
	defer in.Close()
	outF, err := os.Create(dest)
	if err != nil {
		return "", ""
	}
	if _, err := io.Copy(outF, in); err != nil {
		outF.Close()
		_ = os.Remove(dest)
		return "", ""
	}
	if err := outF.Close(); err != nil {
		_ = os.Remove(dest)
		return "", ""
	}
	return name, sum
}

// uniqueUploadPath returns dir/name, or dir/name-1, dir/name-2… when it already exists,
// so re-uploading the same filename never clobbers a prior attachment.
func uniqueUploadPath(dir, name string) string {
	dest := filepath.Join(dir, name)
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		return dest
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, i, ext))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// composeAgentMessage appends an attachment manifest to the user's message so the agent
// knows which files were uploaded and where to Read them. baseDir is the agent's working
// dir (its CWD); we emit ABSOLUTE paths (baseDir + relative) so the agent can Read/Bash
// them unambiguously regardless of how it interprets relative paths.
func composeAgentMessage(msg string, atts []chatAttachment, baseDir string) string {
	if len(atts) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\n\n【用户上传的附件】(绝对路径，需要时用 Read/Bash 查看)：")
	for _, a := range atts {
		fmt.Fprintf(&b, "\n- %s（%s）", filepath.Join(baseDir, a.Path), humanBytes(a.Size))
		if a.Firmware {
			// 固件类附件：给出固件链路的完整指引。任务 306 实测——agent 不了解
			// register_extract 约定时会直接在 uploads 里分析，extracts/组件关联/
			// 反编译链全程缺位。
			fmt.Fprintf(&b,
				"\n  ↑ 这是固件类附件，已同步到固件约定目录 %s（sha256=%s）。"+
					"请按固件审计流程走：解包后调用 register_extract 登记解包根"+
					"（extract_path=解包目录相对任务目录的路径），组件登记与反编译链都依赖该登记。",
				filepath.Join(baseDir, "firmware", a.FirmwareName), a.Sha256)
		}
	}
	return b.String()
}

// userActivityWithAttachments builds the persisted 'user' activity. With attachments,
// Detail holds JSON {text, attachments} so the transcript renders text + attachment
// cards; Summary stays the plain text (the list payload omits Detail, lazy-loaded).
func userActivityWithAttachments(worker, text string, atts []chatAttachment) db.Activity {
	a := db.Activity{Worker: worker, Kind: "user", Summary: text}
	if len(atts) > 0 {
		blob, _ := json.Marshal(map[string]any{"text": text, "attachments": atts})
		a.Detail = string(blob)
	}
	return a
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
