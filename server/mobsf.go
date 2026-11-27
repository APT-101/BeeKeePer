package server

// =====================================================================
// MobSF 静态引擎集成（移动双轨·静态轨）
//
// MobSF 由用户自行部署（docker mobsfsec/mobsf），BeeKeePer 只做 REST
// API 客户端：上传 APK/IPA → 同步扫描 → report_json → 报告落任务目录 +
// 结构化摘要返回给 agent。server 直连 MobSF、不走沙箱（与 IDA 反编译
// 链同模式——外部引擎在宿主/局域网，由 server 调度）。
//
// 配置存 settings 表：mobsf_api_url / mobsf_api_key。未配置时
// mobsf_scan 工具返回"未配置"提示，不影响其它功能。
// =====================================================================

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	mobsfAPIKeySetting  = "mobsf_api_key"
	mobsfAPIURLSetting  = "mobsf_api_url"
	mobsfScanTimeout    = 15 * time.Minute
	mobsfPollInterval   = 5 * time.Second
	mobsfReportMaxBytes = 64 << 20 // report_json 上限（超大报告截断保护）
)

// mobsfConfig reads the two settings; ok=false means MobSF is not configured.
func (m *Manager) mobsfConfig() (baseURL, apiKey string, ok bool) {
	u, okU, _ := m.pg.GetSetting(mobsfAPIURLSetting)
	k, okK, _ := m.pg.GetSetting(mobsfAPIKeySetting)
	baseURL = strings.TrimRight(strings.TrimSpace(u), "/")
	apiKey = strings.TrimSpace(k)
	ok = okU && okK && baseURL != "" && apiKey != ""
	return
}

// GET/POST /api/mobsf/config —— 设置页的 MobSF 接入配置读写（key 写回时脱敏回显）。
func (s *Server) mobsfConfigHTTP(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			APIURL string `json:"api_url"`
			APIKey string `json:"api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, "bad json: "+err.Error())
			return
		}
		if req.APIURL != "" {
			req.APIURL = strings.TrimRight(strings.TrimSpace(req.APIURL), "/")
			if !strings.HasPrefix(req.APIURL, "http://") && !strings.HasPrefix(req.APIURL, "https://") {
				writeErr(w, 400, "api_url 必须以 http(s):// 开头")
				return
			}
			if err := pg.SetSetting(mobsfAPIURLSetting, req.APIURL); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
		}
		if req.APIKey != "" {
			if err := pg.SetSetting(mobsfAPIKeySetting, strings.TrimSpace(req.APIKey)); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
		}
	}
	u, k, ok := s.m.mobsfConfig()
	masked := ""
	if ok && len(k) > 6 {
		masked = k[:3] + "…" + k[len(k)-3:]
	}
	writeJSON(w, 200, map[string]any{"api_url": u, "configured": ok, "api_key_masked": masked})
}

// runMobsfScan executes the full pipeline for one firmware/mobile file already in
// the task workspace: upload to MobSF → wait for scan → fetch report_json →
// persist tasks/<id>/mobsf/<hash>.json. Returns a compact summary for the agent.
func (s *Server) runMobsfScan(ctx context.Context, t *Task, relPath string) (map[string]any, error) {
	baseURL, apiKey, ok := s.m.mobsfConfig()
	if !ok {
		return nil, fmt.Errorf("MobSF 未配置：请在系统设置页填写 MobSF API 地址与 API key")
	}
	rel := filepath.Clean(strings.TrimPrefix(filepath.ToSlash(relPath), "/"))
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("path 必须是任务目录内的相对路径")
	}
	abs := filepath.Join(s.m.dir, "tasks", t.ID, filepath.FromSlash(rel))
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}
	defer f.Close()

	// ① 上传（MobSF 对 APK/IPA 同步扫描后返回 hash；大文件几分钟）
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", filepath.Base(abs))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/upload", body)
	if err != nil {
		return nil, err
	}
	upReq.Header.Set("Authorization", apiKey)
	upReq.Header.Set("Content-Type", mw.FormDataContentType())
	cctx, ccancel := context.WithTimeout(ctx, mobsfScanTimeout)
	defer ccancel()
	upReq = upReq.WithContext(cctx)
	var up struct {
		Hash  string `json:"hash"`
		Error string `json:"error"`
	}
	{
		res, err := http.DefaultClient.Do(upReq)
		if err != nil {
			return nil, fmt.Errorf("MobSF 上传失败: %v", err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, mobsfReportMaxBytes))
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("MobSF 上传被拒（HTTP %d）: %s", res.StatusCode, strings.TrimSpace(string(raw)))
		}
		if err := json.Unmarshal(raw, &up); err != nil || up.Hash == "" {
			return nil, fmt.Errorf("MobSF 上传响应异常: %.200s", string(raw))
		}
	}
	hash := up.Hash
	if up.Error != "" {
		return nil, fmt.Errorf("MobSF 扫描失败: %s", up.Error)
	}

	// ② 触发静态分析（MobSF 4.x 语义：upload 只入库不扫描，/api/v1/scan 才
	// 触发——form body hash + re_scan，同步阻塞至分析完成返回摘要。
	// 缺失此步是此前 report_json 永远 404 "Report not Found" 的根因
	// （MobSF 4.6.9 实测：upload 后 SCAN_LOGS 恒空、PENDING 永挂）。
	// re_scan=1 允许对已入库文件强制重扫；首次扫描用 0 即可。
	scanReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/v1/scan",
		strings.NewReader("hash="+hash+"&re_scan=0"))
	if err != nil {
		return nil, err
	}
	scanReq.Header.Set("Authorization", apiKey)
	scanReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sctx, scancel := context.WithTimeout(ctx, mobsfScanTimeout)
	defer scancel()
	scanReq = scanReq.WithContext(sctx)
	{
		res, err := http.DefaultClient.Do(scanReq)
		if err != nil {
			return nil, fmt.Errorf("MobSF 扫描触发失败: %v", err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, mobsfReportMaxBytes))
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("MobSF 扫描被拒（HTTP %d）: %s", res.StatusCode, strings.TrimSpace(string(raw)))
		}
		// 200 = 同步扫描完成（响应体为静态分析摘要：act_count/api 等）
	}

	// ③ report_json（扫描已完成，正常一次即中；保留短轮询兜底时序）
	// 端点/方法实测校准（MobSF v3.4.5）：POST /api/v1/report_json，
	// hash 走 form body；GET /api/v1/scan_pdf/report_json 在该版本不存在。
	// 轮询窗口 30×10s=5 分钟：MobSF upload 返回 hash 后静态分析异步进行
	// （实测任务 ovaa 5.5MB 扫描约 4-8 分钟），report 未就绪时返回
	// {"report":"Report not Found"} 404——轮询直到报告出现。
	var report map[string]any
	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		if attempt > 0 {
			if sleepCtx(ctx, mobsfPollInterval*2) {
				return nil, fmt.Errorf("cancelled")
			}
		}
		repReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			baseURL+"/api/v1/report_json",
			strings.NewReader("hash="+hash))
		repReq.Header.Set("Authorization", apiKey)
		repReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := http.DefaultClient.Do(repReq)
		if err != nil {
			lastErr = err
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, mobsfReportMaxBytes))
		res.Body.Close()
		if res.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d: %.160s", res.StatusCode, string(raw))
			continue
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return nil, fmt.Errorf("MobSF 报告获取失败: %v", lastErr)
	}

	// ③ 报告落任务目录（agent 可 Read 原始 JSON 做深度分析）
	outDir := filepath.Join(s.m.dir, "tasks", t.ID, "mobsf")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	outPath := filepath.Join(outDir, hash+".json")
	if blob, err := json.MarshalIndent(report, "", "  "); err == nil {
		_ = os.WriteFile(outPath, blob, 0o644)
	}

	// ④ 结构化摘要：sections 清单 + 关键计数，agent 据此决定登记哪些 finding/组件
	return map[string]any{
		"hash":        hash,
		"report_path": s.wsRel(outPath),
		"summary":     mobsfSummary(report),
	}, nil
}

// mobsfSummary extracts the compact counts/lists the agent needs to decide what
// to register, without dragging the whole report into the transcript.
func mobsfSummary(report map[string]any) map[string]any {
	out := map[string]any{}
	if app, ok := report["app_info"].(map[string]any); ok {
		out["app_name"] = app["app_name"]
		out["package_name"] = app["package_name"]
		out["version_name"] = app["version_name"]
	}
	if man, ok := report["manifest_analysis"].(map[string]any); ok {
		if list, ok := man["list"].([]any); ok {
			out["manifest_findings"] = len(list)
		}
	}
	if perms, ok := report["permissions"].(map[string]any); ok {
		out["permissions_count"] = len(perms)
	}
	if code, ok := report["code_analysis"].(map[string]any); ok {
		if list, ok := code["android_api"].([]any); ok {
			out["android_api_hits"] = len(list)
		}
		if hard, ok := code["possible_hardcoded_secrets"].(map[string]any); ok {
			out["hardcoded_secrets"] = len(hard)
		}
	}
	if bins, ok := report["binary_analysis"].([]any); ok {
		out["binary_analysis_hits"] = len(bins)
	}
	// 全量章节键，agent 按需再读报告原文
	keys := make([]string, 0, len(report))
	for k := range report {
		keys = append(keys, k)
	}
	out["report_sections"] = keys
	return out
}

// POST /api/mobsf/test —— 设置页"测试连接"：探 MobSF /api/v1/scans
// （GET 200=连通且 key 有效；401=key 错误；其它/超时=不可达）。
func (s *Server) mobsfTestHTTP(w http.ResponseWriter, r *http.Request) {
	baseURL, apiKey, ok := s.m.mobsfConfig()
	if !ok {
		writeJSON(w, 200, map[string]any{"ok": false, "reason": "未配置（先填写 API 地址与 key 并保存）"})
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet,
		baseURL+"/api/v1/scans", nil)
	req.Header.Set("Authorization", apiKey)
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "reason": "不可达: " + err.Error()})
		return
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 200:
		writeJSON(w, 200, map[string]any{"ok": true, "reason": "连通且 key 有效"})
	case 401:
		writeJSON(w, 200, map[string]any{"ok": false, "reason": "API key 无效或已变更"})
	default:
		writeJSON(w, 200, map[string]any{"ok": false, "reason": fmt.Sprintf("HTTP %d", res.StatusCode)})
	}
}

// POST /api/tasks/{id}/mobsf/scan  body {"path": "uploads/xxx.apk"}
func (s *Server) mobsfScanHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		writeErr(w, 400, "缺少 path（任务目录内相对路径）")
		return
	}
	res, err := s.runMobsfScan(r.Context(), t, req.Path)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// GET /api/tasks/{id}/mobsf/report —— MobSF 报告 GUI 视图（裁剪版）。
// 报告 JSON 可能非常大（ViPlexHandy 19.6MB），全量直传前端不可行：
// 返回应用信息 + 全章节名/条目数 + 关键章节（manifest/code/binary/secrets）
// 的裁剪条目，前端按章节折叠展示。
func (s *Server) mobsfReportViewHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	dir := filepath.Join(s.m.dir, "tasks", t.ID, "mobsf")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		writeErr(w, 404, "任务尚无 MobSF 报告（先发起静态扫描）")
		return
	}
	// 取最新一份报告（按修改时间）
	var latest string
	var latestMod time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err == nil && info.ModTime().After(latestMod) {
			latest, latestMod = filepath.Join(dir, e.Name()), info.ModTime()
		}
	}
	if latest == "" {
		writeErr(w, 404, "任务尚无 MobSF 报告文件")
		return
	}
	raw, err := os.ReadFile(latest)
	if err != nil {
		writeErr(w, 500, "读取报告失败: "+err.Error())
		return
	}
	if len(raw) > mobsfReportMaxBytes {
		writeErr(w, 500, "报告超过展示上限")
		return
	}
	var rep map[string]any
	if err := json.Unmarshal(raw, &rep); err != nil {
		writeErr(w, 500, "报告解析失败: "+err.Error())
		return
	}
	app := map[string]any{}
	for _, k := range []string{"app_name", "package_name", "version_name", "file_name", "size", "md5", "sha256", "min_sdk", "target_sdk", "max_sdk", "main_activity", "app_type"} {
		if v, ok2 := rep[k]; ok2 {
			app[k] = v
		}
	}
	app["hash"] = strings.TrimSuffix(filepath.Base(latest), ".json")

	// 全章节名 + 条目数（数组取 len，标量记作 1）
	type secInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	secs := []secInfo{}
	for _, k := range sortedKeys(rep) {
		n := 0
		switch v := rep[k].(type) {
		case []any:
			n = len(v)
		case map[string]any:
			n = len(v)
		default:
			n = 1
		}
		secs = append(secs, secInfo{Name: k, Count: n})
	}

	// 关键章节裁剪：数组型章节取前 N 条原样返回
	trimArr := func(key string, n int) any {
		v, ok := rep[key]
		if !ok {
			return nil
		}
		if arr, isArr := v.([]any); isArr && len(arr) > n {
			return arr[:n]
		}
		return v
	}
	view := map[string]any{
		"app":      app,
		"sections": secs,
		"details": map[string]any{
			"manifest_analysis": trimArr("manifest_analysis", 60),
			"code_analysis":     trimArr("code_analysis", 120),
			"binary_analysis":   trimArr("binary_analysis", 40),
			"secrets":           trimArr("secrets", 40),
			"permissions":       trimArr("permissions", 120),
			"urls":              trimArr("urls", 40),
			"firebase_urls":     trimArr("firebase_urls", 20),
			"certificate_analysis": trimArr("certificate_analysis", 20),
			"exported_count":    rep["exported_count"],
			"average_cvss":      rep["average_cvss"],
			"appsec":            rep["appsec"],
		},
	}
	writeJSON(w, 200, view)
}

// sortedKeys 返回 map 的 key 有序列表（章节展示顺序稳定）。
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
