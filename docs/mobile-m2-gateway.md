# M2：mobile gateway 与 DroidBridge 设计（Bridge 反连主力）

状态：设计定稿（2026-11-27），实施分组件推进。
参考实现：Full-Chain-Sentinel-System-main（`~/.go/sentinel-ref/` 解压；本仓库不含其源码，协议契约以下文为准，来源标注到文件）。

## 1. 协议契约（source of truth = Sentinel packages/web/src/droid-protocol.ts + droid-apk WsClient.kt）

- **传输**：设备主动 `ws(s)://<console>:<port>/ws/droid`，**token 走查询串**，`deviceId` 为 UUID（设备首次生成后永久使用）。
- **心跳**：应用层 15s 心跳帧 + OkHttp ping 20s；断线指数退避重连 1s→30s 封顶。
- **帧**：纯 JSON 文本帧；**二进制载荷分片**走 `data`（device→server：截图/文件/pcap）与 `push` 的 `b64`（server→device，`seq`+`done`），单条 WS 消息不承载大二进制（300MB pcap 不允许一条消息）。
- **多路复用**：全部 request/response 带 `reqId` 回显，慢命令不阻塞通道。
- **命令集（server→device `t` 字段）**：
  | t | 关键字段 | 说明 |
  |---|---|---|
  | `exec` | cmd, asRoot, timeoutMs | shell（root 经 su，Magisk 授权）|
  | `pull` | path, maxBytes | 设备文件分片回传（`data` 帧）|
  | `push` | path, seq, done, b64, mode="0700" | 分片写文件（frida-server 推送等；seq=0 截断打开）|
  | `screencap` | — | PNG 截屏（`data` 帧回传）|
  | `logcat` | lines, filter | logcat 尾部 |
  | `packages` | thirdPartyOnly | 包列表 |
  | `capture_start/stop/status` | iface, seconds | tcpdump 抓包（/data/local/tmp/droid-capture.pcap）|
  | `tcp_open`（M2 第二版） | tunnelId, connId | TCP 隧道：本机监听 → WS 透传 → 设备目标端口（frida-cli 直连 frida-server:27042）|
- **root 探测**：`su -c id -u` == 0（重试 3 次×1.5s，超时 10s），结果随 hello 帧一次性上报。

## 2. BeeKeePer mobile gateway（组件①，Go，`server/mobilegateway.go`）

- **端点**：`/ws/droid`（GET 升级 WebSocket；与 :8787 同进程）。认证：查询串 token ↔ settings `mobile_bridge_token`（设置页可配置）比对；不匹配直接断开（配合 TLS 自签 + 后续证书 pin）。
- **设备注册表**：`db/mdevices.go` 新表 `mobile_devices`（device_id uuid、model、android_version、root_available、last_seen、status、occupied_by_task）；hello 上报（型号/Android 版本/root）写入，心跳更新 last_seen，30s 无心跳置 offline。
- **占用锁**：任务通过 API 占用设备（`POST /api/mobile/devices/{id}/occupy|release`）；frida attach/tcpdump 独占——占用中的设备拒绝其它任务路由。
- **命令路由**：LLM 工具层与 GUI 经 `POST /api/mobile/devices/{id}/rpc`（body=协议命令 JSON）投递到已连接设备；`reqId` 由网关生成，设备响应回填（future/promise 模式）；分片 `data` 帧聚合后落 `tasks/<id>/mobile/`。
- **配置（全部走设置页，零硬编码）**：`mobile_bridge_token`（设备配对令牌）、监听端口复用 8787（同进程 WS 升级）。

## 3. DroidBridge 设备端（组件②，fork droid-apk）

- fork `packages/droid-apk`（Kotlin 六文件：WsClient/DroidService/GuardService/Handlers/Prefs/MainActivity）——**协议不改**，仅改：
  - 默认 serverUrl 指向 BeeKeePer（首次启动引导页填写，存 Prefs）
  - token 由 BeeKeePer 设置页生成、扫码/手填配对
- 构建产物：APK（用户真机 root 安装）；GuardService 双进程守护默认开。

## 4. LLM 工具层（组件③，`agent/tools_mobile.go`）

- `mobile_exec` / `mobile_pull` / `mobile_push` / `mobile_screencap` / `mobile_logcat` / `mobile_capture` / `mobile_packages`——统一走任务占用的设备 RPC；**guard/审批链沿用**（危险命令过审批）；产物落 `tasks/<id>/mobile/` 并可 insert_finding/insert_assets 登记。
- 静态发现 → 动态验证编排（M4）：planner 派意图时带静态线索（导出组件/硬编码密钥），worker 用 mobile_exec 实测。

## 5. 实施顺序

1. gateway 骨架（wss + token + 注册表 + 心跳）→ 2. RPC 路由 + 分片聚合 → 3. droid-apk fork 配对联调（adb logcat 对照）→ 4. LLM 工具层 → 5. TCP 隧道（第二版）。
