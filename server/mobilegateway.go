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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
		}
		if json.Unmarshal(raw, &probe) != nil {
			continue
		}
		if probe.T == "hb" {
			continue
		}
		if probe.ReqID != "" {
			conn.mu.Lock()
			if ch, ok := conn.pending[probe.ReqID]; ok {
				ch <- json.RawMessage(raw)
			}
			conn.mu.Unlock()
		}
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