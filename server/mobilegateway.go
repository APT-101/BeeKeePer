// Mobile gateway：DroidBridge 设备端（Sentinel droid-apk fork）的反连网关。
// 协议契约见 docs/mobile-m2-gateway.md（source of truth = Sentinel
// packages/web/src/droid-protocol.ts + droid-apk WsClient.kt/DroidService.kt）。
//
// 设备主动 ws(s)://<console>/ws/droid?token=..&deviceId=.. 反连；握手必须先发
// hello 帧（token/deviceId/model/androidVersion/sdkInt/rooted），之后才允许 hb
// 心跳（15s 一帧）。同 deviceId 的新连接会用 4003 换掉旧连接（旧 socket 稍后
// 关闭）。全部命令 JSON 帧，二进制走分片（data/push 的 b64+seq+done），reqId
// 多路复用。
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// mobileBridgeTokenSetting：设置页配置的设备配对令牌（零硬编码）。
const mobileBridgeTokenSetting = "mobile_bridge_token"

// droidConn 是一台已反连设备。
type droidConn struct {
	deviceID       string
	model          string
	androidVersion string
	sdkInt         int
	rooted         bool
	conn           *websocket.Conn
	lastSeen       time.Time
	connectedAt    time.Time
	occupiedBy     string // 占用锁：任务 id（空=未占用）

	mu      sync.Mutex
	pending map[string]chan json.RawMessage // reqId → 响应通道
}

func (d *droidConn) newReqID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "req-" + hex.EncodeToString(b)
}

// sendJSON 向设备发送一帧 JSON 文本。
func (d *droidConn) sendJSON(v any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	d.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return d.conn.WriteMessage(websocket.TextMessage, raw)
}

// call 向设备投递一条命令并等待其 result 帧（reqId 回显多路复用）。
func (d *droidConn) call(ctx context.Context, frame map[string]any, timeout time.Duration) (json.RawMessage, error) {
	reqID := d.newReqID()
	frame["reqId"] = reqID
	ch := make(chan json.RawMessage, 1)
	d.mu.Lock()
	d.pending[reqID] = ch
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.pending, reqID)
		d.mu.Unlock()
	}()
	if err := d.sendJSON(frame); err != nil {
		return nil, fmt.Errorf("发送失败: %v", err)
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("设备响应超时（%s）", timeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("cancelled")
	}
}

// mobileHub 是设备注册表（deviceId → 连接）+ 占用锁。
type mobileHub struct {
	mu      sync.RWMutex
	devices map[string]*droidConn
}

var mobHub = &mobileHub{devices: map[string]*droidConn{}}

// mobileBridgeToken 读设置页配置的配对令牌；未配置返回空（网关拒绝一切连接）。
func (s *Server) mobileBridgeToken() string {
	pg := s.m.PG()
	if pg == nil {
		return ""
	}
	v, _, _ := pg.GetSetting(mobileBridgeTokenSetting)
	return strings.TrimSpace(v)
}

// GET /ws/droid?token=..&deviceId=.. —— 设备反连端点（WebSocket 升级）。
func (s *Server) mobileGatewayWS(w http.ResponseWriter, r *http.Request) {
	token := s.mobileBridgeToken()
	if token == "" {
		http.Error(w, "mobile bridge 未启用：请在设置页配置配对令牌", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	if strings.TrimSpace(q.Get("token")) != token {
		http.Error(w, "token 不匹配", http.StatusUnauthorized)
		return
	}
	deviceID := strings.TrimSpace(q.Get("deviceId"))
	if deviceID == "" {
		http.Error(w, "缺少 deviceId", http.StatusBadRequest)
		return
	}
	up := websocket.Upgrader{}
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := &droidConn{
		deviceID:    deviceID,
		conn:        ws,
		connectedAt: time.Now(),
		lastSeen:    time.Now(),
		pending:     map[string]chan json.RawMessage{},
	}
	// 握手：hello 必须最先到（且 token 帧内一致）；hb 先到按 Sentinel 语义回 4001 关闭。
	ws.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, helloRaw, err := ws.ReadMessage()
	if err != nil {
		ws.Close()
		return
	}
	var hello struct {
		T              string `json:"t"`
		Token          string `json:"token"`
		DeviceID       string `json:"deviceId"`
		Model          string `json:"model"`
		AndroidVersion string `json:"androidVersion"`
		SdkInt         int    `json:"sdkInt"`
		Rooted         bool   `json:"rooted"`
	}
	if err := json.Unmarshal(helloRaw, &hello); err != nil || hello.T != "hello" {
		ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(4001, "handshake: hello frame required"), time.Now().Add(2*time.Second))
		ws.Close()
		return
	}
	if strings.TrimSpace(hello.Token) != token || hello.DeviceID != deviceID {
		ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(4002, "handshake: token/deviceId mismatch"), time.Now().Add(2*time.Second))
		ws.Close()
		return
	}
	conn.model, conn.androidVersion, conn.sdkInt, conn.rooted = hello.Model, hello.AndroidVersion, hello.SdkInt, hello.Rooted

	// 注册：同 deviceId 旧连接用 4003 换新（Sentinel 语义）。
	mobHub.mu.Lock()
	if old, ok := mobHub.devices[deviceID]; ok && old != nil {
		old.mu.Lock()
		for _, ch := range old.pending {
			close(ch)
		}
		old.pending = map[string]chan json.RawMessage{}
		old.mu.Unlock()
		old.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(4003, "replaced by newer connection"), time.Now().Add(2*time.Second))
		old.conn.Close()
	}
	mobHub.devices[deviceID] = conn
	mobHub.mu.Unlock()
	log.Printf("[mobile gateway] 设备 %s 上线（%s / Android %s / root=%v）", deviceID, conn.model, conn.androidVersion, conn.rooted)

	// 读循环：hb → lastSeen；response/data → pending 转发。
	// data 帧（t:"data"，b64 分片+seq+done）按 reqId 聚合：done 到达后解码
	// 落盘到 tasks/<id>/mobile/，并以聚合后的 result 转发给等待者。
	dataBuf := map[string][]byte{} // reqId → 已聚合的原始字节
	for {
		ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		conn.lastSeen = time.Now()
		var probe struct {
			T     string          `json:"t"`
			ReqID string          `json:"reqId"`
			B64   string          `json:"b64"`
			Done  bool            `json:"done"`
		}
		if json.Unmarshal(raw, &probe) != nil {
			continue
		}
		if probe.T == "hb" {
			continue
		}
		if probe.ReqID == "" {
			continue
		}
		conn.mu.Lock()
		if probe.T == "data" {
			// 二进制分片：追加 b64 载荷；done 时解码落盘并把响应换成交付帧。
			if raw64, derr := base64.StdEncoding.DecodeString(probe.B64); derr == nil {
				dataBuf[probe.ReqID] = append(dataBuf[probe.ReqID], raw64...)
			}
			if !probe.Done {
				conn.mu.Unlock()
				continue
			}
			bin := dataBuf[probe.ReqID]
			delete(dataBuf, probe.ReqID)
			// 落盘：tasks/<taskID>/mobile/<reqId>.bin（taskID 从占用/上下文取，
			// 无占用时落 data 目录）。
			dir := s.mobileDropDir(conn.deviceID)
			_ = os.MkdirAll(dir, 0o755)
			out := filepath.Join(dir, probe.ReqID+".bin")
			_ = os.WriteFile(out, bin, 0o644)
			var chunk map[string]any
			_ = json.Unmarshal(raw, &chunk)
			chunk["t"] = "result"
			chunk["ok"] = true
			chunk["file_path"] = out
			chunk["bytes"] = len(bin)
			delete(chunk, "data")
			delete(chunk, "seq")
			fixed, _ := json.Marshal(chunk)
			if ch, ok := conn.pending[probe.ReqID]; ok {
				ch <- json.RawMessage(fixed)
			}
			conn.mu.Unlock()
			continue
		}
		if ch, ok := conn.pending[probe.ReqID]; ok {
			ch <- json.RawMessage(raw)
		}
		conn.mu.Unlock()
	}
	// 下线。
	mobHub.mu.Lock()
	if mobHub.devices[deviceID] == conn {
		delete(mobHub.devices, deviceID)
	}
	mobHub.mu.Unlock()
	ws.Close()
	log.Printf("[mobile gateway] 设备 %s 下线", deviceID)
}

// ---- 管理 API（GUI/LLM 工具层）----

// GET /api/mobile/devices —— 设备列表（在线状态/型号/root/占用）。
func (s *Server) mobileDevicesHTTP(w http.ResponseWriter, r *http.Request) {
	mobHub.mu.RLock()
	defer mobHub.mu.RUnlock()
	list := make([]map[string]any, 0, len(mobHub.devices))
	for id, d := range mobHub.devices {
		list = append(list, map[string]any{
			"deviceId":       id,
			"model":          d.model,
			"androidVersion": d.androidVersion,
			"sdkInt":         d.sdkInt,
			"rooted":         d.rooted,
			"connectedFor":   int(time.Since(d.connectedAt).Seconds()),
			"lastSeenSec":    int(time.Since(d.lastSeen).Seconds()),
			"occupiedBy":     d.occupiedBy,
		})
	}
	writeJSON(w, 200, map[string]any{"devices": list})
}

// POST /api/mobile/devices/{id}/rpc —— 向设备投递一条协议命令并等待 result。
// body 即协议命令（{"t":"exec","cmd":...,"asRoot":true,...}），网关只补 reqId。
func (s *Server) mobileRPCHTTP(w http.ResponseWriter, r *http.Request) {
	mobHub.mu.RLock()
	d := mobHub.devices[r.PathValue("id")]
	mobHub.mu.RUnlock()
	if d == nil {
		writeErr(w, http.StatusNotFound, "设备不在线")
		return
	}
	var frame map[string]any
	if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if frame["t"] == nil {
		writeErr(w, 400, "缺少 t（协议命令类型）")
		return
	}
	timeout := 30 * time.Second
	if v, ok := frame["timeoutMs"].(float64); ok && v > 0 && v < 600000 {
		timeout = time.Duration(v) * time.Millisecond
	}
	resp, err := d.call(r.Context(), frame, timeout)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, json.RawMessage(resp))
}
// mobileDropDir 返回设备产物的落盘目录：设备被任务占用时优先落任务目录
// tasks/<occupied>/mobile/，否则落 <data>/mobile-drops/<deviceId>/。
func (s *Server) mobileDropDir(deviceID string) string {
	mobHub.mu.RLock()
	d := mobHub.devices[deviceID]
	mobHub.mu.RUnlock()
	if d != nil && d.occupiedBy != "" {
		return filepath.Join(s.m.dir, "tasks", d.occupiedBy, "mobile")
	}
	return filepath.Join(s.m.dir, "mobile-drops", deviceID)
}

// mobileFirstDevice 返回当前第一台在线设备的连接（单设备简化；多设备调度 M4）。
func (s *Server) mobileFirstDevice() *droidConn {
	mobHub.mu.RLock()
	defer mobHub.mu.RUnlock()
	for _, d := range mobHub.devices {
		return d
	}
	return nil
}

// mobileToolCall 是 agent 工具层的统一入口：把协议命令投递到在线设备并
// 返回 result 帧（data 分片已由读循环聚合落盘，响应里带 file_path）。
func (s *Server) mobileToolCall(taskID int64, frame map[string]any) (map[string]any, error) {
	d := s.mobileFirstDevice()
	if d == nil {
		return nil, fmt.Errorf("无在线设备：请先在真机启动 DroidBridge 反连")
	}
	// 命令超时：frame.timeoutMs 优先，缺省 30s。
	timeout := 30 * time.Second
	if v, ok := frame["timeoutMs"].(float64); ok && v > 0 && v < 600000 {
		timeout = time.Duration(v) * time.Millisecond
	}
	// 占用登记：任务产出落任务目录（exec 等无产物命令也登记，形成任务-设备关联）。
	if taskID > 0 {
		mobHub.mu.Lock()
		if d.occupiedBy == "" {
			d.occupiedBy = fmt.Sprintf("%d", taskID)
		}
		mobHub.mu.Unlock()
	}
	// push 特殊处理：frame.file 是任务目录内的相对路径，需要 server 读文件
	// 并按 256KB 分片逐帧推送（seq=0 截断，done=true 才有 result 帧）。
	if t, _ := frame["t"].(string); t == "push" {
		return s.mobilePushFile(d, taskID, frame, timeout)
	}
	resp, err := d.call(context.Background(), frame, timeout)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	// 补充产物路径（data 聚合帧带 file_path）。
	if fp, ok := out["file_path"].(string); ok && taskID > 0 {
		out["file_path"] = fp
	}
	return out, nil
}

// mobilePushFile 把任务目录内的文件按 256KB 分片推到设备（droid-protocol push）。
func (s *Server) mobilePushFile(d *droidConn, taskID int64, frame map[string]any, timeout time.Duration) (map[string]any, error) {
	fileRel, _ := frame["file"].(string)
	destPath, _ := frame["destPath"].(string)
	mode, _ := frame["mode"].(string)
	if mode == "" {
		mode = "0700"
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(fileRel), "/"), "./")
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("file 必须是任务目录内的相对路径")
	}
	abs := filepath.Join(s.m.dir, "tasks", fmt.Sprintf("%d", taskID), filepath.FromSlash(rel))
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}
	const chunk = 256 * 1024
	var lastResp json.RawMessage
	if len(data) == 0 {
		// 空文件也要走一次 done 帧。
		resp, err := d.call(context.Background(), map[string]any{
			"t": "push", "destPath": destPath, "path": destPath, "seq": 0.0, "done": true, "b64": "", "mode": mode,
		}, timeout)
		if err != nil {
			return nil, err
		}
		lastResp = resp
	} else {
		total := (len(data) + chunk - 1) / chunk
		for i, off := 0, 0; off < len(data); i, off = i+1, off+chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			isLast := i == total-1
			resp, err := d.call(context.Background(), map[string]any{
				"t": "push", "destPath": destPath, "path": destPath,
				"seq": float64(i), "done": isLast,
				"b64": base64.StdEncoding.EncodeToString(data[off:end]), "mode": mode,
			}, timeout)
			if err != nil {
				return nil, fmt.Errorf("分片 %d/%d 推送失败: %v", i+1, total, err)
			}
			if isLast {
				lastResp = resp
			}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(lastResp, &out); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	return out, nil
}
// GET /api/mobile/file?task=<id>&path=<rel> —— 设备侧拉取任务文件
// （push 大文件的替代通道：18MB APK 走一次 HTTP 下载，而非 73 帧 WS 消息
// ——WS 分片会塞满设备端 OkHttp 的 4MB 发送队列水位导致背压超时）。
// 认证：查询串 token（与反连配对 token 同源）。
func (s *Server) mobileFileHTTP(w http.ResponseWriter, r *http.Request) {
	token := s.mobileBridgeToken()
	if token == "" {
		http.Error(w, "mobile bridge 未启用", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(r.URL.Query().Get("token")) != token {
		http.Error(w, "token 不匹配", http.StatusUnauthorized)
		return
	}
	taskID := strings.TrimSpace(r.URL.Query().Get("task"))
	if _, ok := s.m.Task(taskID); !ok {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}
	rel := strings.TrimPrefix(filepath.ToSlash(r.URL.Query().Get("path")), "/")
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		http.Error(w, "path 非法", http.StatusBadRequest)
		return
	}
	abs := filepath.Join(s.m.dir, "tasks", taskID, filepath.FromSlash(rel))
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		http.Error(w, "open failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	_, _ = io.Copy(w, f)
}
// 路由注册提醒：/api/mobile/file 挂根 mux（见 server.go，精确路径优先于 /api/ 前缀）。
// GET/POST /api/mobile/config —— 设置页的 Bridge 配对配置（GET 读 token 脱敏
// 与在线设备列表；POST regenerate=true 生成新配对 token——旧 token 立即失效，
// 设备需重填）。
func (s *Server) mobileConfigHTTP(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			Regenerate bool `json:"regenerate"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, "bad json: "+err.Error())
			return
		}
		if req.Regenerate {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			newTok := hex.EncodeToString(b)
			if err := pg.SetSetting(mobileBridgeTokenSetting, newTok); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			// token 更换：踢掉全部已连接设备（旧 token 失效），设备需重填后反连。
			mobHub.mu.Lock()
			for _, d := range mobHub.devices {
				d.conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(4002, "token rotated"), time.Now().Add(2*time.Second))
				d.conn.Close()
			}
			mobHub.devices = map[string]*droidConn{}
			mobHub.mu.Unlock()
		}
	}
	tok := s.mobileBridgeToken()
	masked := ""
	if tok != "" && len(tok) > 6 {
		masked = tok[:3] + "…" + tok[len(tok)-3:]
	}
	mobHub.mu.RLock()
	list := make([]map[string]any, 0, len(mobHub.devices))
	for id, d := range mobHub.devices {
		list = append(list, map[string]any{
			"deviceId":       id,
			"model":          d.model,
			"androidVersion": d.androidVersion,
			"rooted":         d.rooted,
			"connectedFor":   int(time.Since(d.connectedAt).Seconds()),
			"occupiedBy":     d.occupiedBy,
		})
	}
	mobHub.mu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"configured":     tok != "",
		"token":          tok, // 明文：设置页是 admin JWT 保护下的配置下发场景，设备端需要完整值填写
		"token_masked":   masked,
		"endpoint":       "/ws/droid",
		"online_devices": list,
	})
}