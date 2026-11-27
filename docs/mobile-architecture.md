# 移动端架构（Android / iOS）：双轨设计

状态：已决策（架构采纳，分期实施）。参考实现：Full-Chain-Sentinel-System（docs/mobile.md · packages/droid-apk · packages/web/ios/README.md）。

## 决策摘要

| 轨道 | 输入 | 宿主 | 来源 |
|---|---|---|---|
| **静态检测** | APK / 砸壳后的 IPA dump | Kali 沙箱内工具链（jadx / apktool / mobsfscan） | BeeKeePer 沙箱模式 + MobSF 静态引擎 |
| **动态测试** | 真机 / 模拟器在线 | 设备池（emulator / adb / bridge 三种 provider） | **采纳 Sentinel 的反连 Bridge 架构** |

划分原则：**纯静态检测不需要设备**（量大管饱，一次扫描全量覆盖）；**运行时行为只有动态才能发现**（运行时解密、真实服务端交互、加密的实际行为、反检测对抗）。

## 为什么动态轨采用 Sentinel 的反连架构

1. **方向正确**：设备主动 wss 反连控制台（NAT 穿越，控制台可公网部署）——与 BeeKeePer"控制面在服务端、动作面在设备"的哲学一致；adb 桥接方向相反（控制面在主机），仅适合同网段。
2. **iOS 没有第二条路**：非越狱/无 Bridge 的 iOS 无法做动态测试；iOS 模拟器不是 iOS（Simulator 跑的是 macOS 进程，App Store IPA 装不上）。
3. **协议成熟度可直接搬**：hello/心跳/watchdog/分片 pull-push/TCP 隧道（设备内网端口透传到 MITM）/HTTPS 流式大文件上传（绕 iOS jetsam），外加 macOS 契约测试与 8P 真机验证清单。
4. **安全设计完整**：强制 wss + 证书指纹 pin 配对（setup 页 probe 叶证书 SHA-256，token 不发给证书不匹配端点）+ 本地控制页只绑 127.0.0.1 + "daemon 只执行收到的命令，审批在控制台侧"——与 BeeKeePer 的 guard/审批 hook 架构天然对齐。

## 静态轨：MobSF 静态引擎（外挂服务，M1 已完成）

- **形态（v1.0.3 实施定稿）**：**用户自行部署完整版 MobSF 服务**（docker 容器，Web UI 可独立使用），BeeKeePer 做**外挂引擎 REST 集成**（`server/mobsf.go`）——与 AI-Infra-Guard 外挂引擎同模式。设置页（系统设置→外挂引擎卡片）配置 API 地址 + key，BeeKeePer 不自带 MobSF 运行时。
- **调用链**：`mobsf_scan` 工具 / `POST /api/tasks/{id}/mobsf/scan` → upload（`POST /api/v1/upload`）→ **scan 触发（`POST /api/v1/scan`，form `hash`+`re_scan`）** → report（`POST /api/v1/report_json`，form `hash`）→ 报告 JSON 落 `tasks/<id>/mobsf/<hash>.json` + 摘要返回 agent。
- **⚠️ MobSF 4.x API 语义变更（排障实录）**：4.x 把「上传」与「扫描」**分离**——`upload` 只入库返回 hash，**`/api/v1/scan` 才触发分析**（3.x 是上传即扫描一体）。缺失 scan 调用会呈现：SCAN_LOGS 恒空、记录永挂 PENDING、report_json 永远 404 "Report not Found"，且 **MobSF 的 Django 对成功的 200 请求不打日志**（日志里只有轮询 404），极易误判为 MobSF 实例问题。已按 MobSF 4.6.9 官方文档补齐（`5998de5`），三真实靶标验证通过。
- **注入 wire（双通道）**：worker（意图执行）在 `agentsForTask` 构造处 wire；main agent（chat 场景）在 MainAgent 加 `SetMobsfScan` + Chat 装配转发，server 侧两处注入。`buildPlannerWorker` 路径的 worker 另行接线——**三处缺一不可**（311/312 曾因漏 wire main 报"未接线"）。
- **前台上传上限**：chat 附件 `maxChatUpload` 512MB（大 APK/固件包前台直传；MobSF 上传上限 1GB）。
- **架构纪律（硬约束）**：**纯静态检测一律走 MobSF 引擎**，agent 是编排者（调 mobsf_scan、读报告、甄别、登记 insert_finding/insert_components），**禁止用 Bash/python/unzip 本地解析 APK 替代**——本地静态分析质量与可复现性不可控，且会让 MobSF 报告体系失真（312 的 Bash 兜底即为反面案例）。MobSF 失败时意图标 blocked 上报，由人修引擎后重排。
- **沙箱内 mobsfscan CLI**：保留为沙箱工具链的一部分（ jadx/apktool 用于动态轨的静态辅助），但**不再是静态审计的执行路径**。
- **产出接入**：manifest 导出组件 → `insert_components`（与固件组件同体系）；code_analysis/binary_analysis/secrets/appsec 高危条目 → 甄别后 `insert_finding`；manifest 分析（权限/allowBackup/debuggable）→ 逐项字节级验证后登记。
- **iOS 静态的前提是砸壳**：App Store IPA 是加密的，MobSF 的 iOS 静态扫描要砸壳后的 dump——而砸壳需要越狱设备（SentinelBridge 的 MachO.swift）。**iOS 的静态与动态是串联的，不是并列的**。
- **M1 验证记录**（MobSF 4.6.9 实例 172.16.80.104:8000）：
  | 靶标 | 大小 | 链路耗时 | 产出 |
  |---|---|---|---|
  | OVAA 1.0.0（18 已知漏洞靶标） | 5.5MB | ~4min | 报告 + WebView 攻击面 finding |
  | MASTG-DEMO-0088（MASTestApp） | 33MB | 4:39 | 17 findings（allowBackup/debuggable 字节级验证） |
  | ViPlexHandy 6.0.4（真实商业 app） | 162MB | ~5min | 17 findings——硬编码 OAuth 凭证（high）、usesCleartextTraffic、CBC/MD5 弱加密、71/84 native 库标记 |

## 动态轨：设备池 + Sentinel 反连

### 设备池：Bridge 反连为主力（2026-11-27 决策调整）

> **架构决策（用户定）**：部署环境多为虚拟机（无嵌套虚拟化，/dev/kvm 不可用），Android emulator/redroid 类模拟器路线**不现实，已移除**。动态轨设备接入以 **Sentinel 设备端 Bridge 反连**为主力——设备（Android 真机/越狱 iOS）主动 wss 反连控制台，NAT 穿越无需公网 IP，天然适配分布式真机。

| provider | 形态 | 复位方式 | 覆盖场景 |
|---|---|---|---|
| `bridge` | **Sentinel 式设备端 Bridge 反连**（DroidBridge：root Android 真机；SentinelBridge：越狱 iOS） | 设备复位钩子（装包/hook 残留清理） | **动态轨主力**：全部动态能力——frida hook、流量、反检测 App、厂商 ROM、TEE/硬件层、iOS |
| `adb` | 真机（USB/网络 adb，同网段直连） | adb uninstall / 手动 | 本地真机调试的快捷通道（降级路径） |

统一接口：**占用锁**（任务独占设备，frida attach/tcpdump 都是独占的）+ **心跳健康** + **复位语义**——Bridge 反连的设备注册表复用同一抽象。

### iOS 的硬边界

- **iOS 模拟器不是 iOS**：Xcode Simulator 跑的是 macOS 进程，App Store IPA（加密 arm64 Mach-O）装不上——**iOS 动态只有越狱真机 + SentinelBridge 一条路**。
- 反模拟器检测：银行/风控类 app 在模拟器上直接拒绝运行——**真机是这类目标的唯一覆盖**。
- 越狱生态碎片化：rootful（iOS 14-15/checkra1n）/ rootless（iOS 15-16/Dopamine）双形态打包；roothide（随机越狱根）不支持——设备选型提前定。

## 静动接力（planner 编排价值）

- **静态发现 → 动态验证**：manifest 导出组件、硬编码 URL/密钥 → planner 生成动态验证意图（这正是引擎"静态线索 → 动态验证"编排的移动端应用）。
- **动态产出 → 静态深化**：动态发现的加密函数/协议 → 反编译源码深挖（同固件审计的反编译链复用）。
- **iOS 砸壳 → 静态输入**：SentinelBridge 砸壳 dump → MobSF 静态引擎扫描。

## 控制台侧落点（BeeKeePer 对应）

| Sentinel 组件 | BeeKeePer 落点 |
|---|---|
| ios-gateway.ts / 设备网关 | server 新增 **mobile gateway**（wss + token + 设备注册表），对齐 engine/task 编排 |
| ios-frida-tool / decrypt-tool / capture-tool / http-log / bundle | 注册为 **LLM 工具**（tools_mobile.go），走现有 guard/审批链 |
| TCP 隧道三件套 | 接入现有 **MITM 代理**（:8788）——设备流量经隧道进录制，与 Web 任务同一套 traffic 分析 |
| DroidBridge/SentinelBridge 设备端 | 新增 `bridges/` 模块 fork 改造（协议层几乎不动） |
| 设备注册表 + token | 扩展**设备占用锁**（Sentinel 没有：它单设备单任务） |
| 证书指纹 pin + token 配对 | 沿用 |

## 安全边界

- 设备端 daemon 只执行收到的命令；**审批在控制台侧**（guard hook 链）。
- 动态任务结束的**设备复位**是必须项：模拟器=快照恢复；真机=复位钩子（卸测试包/清 hook 残留/恢复系统设置）——否则多任务互相污染。
- 公网必须 wss + 证书指纹核对；本地控制页只绑回环。
- pull/push 路径限制在任务工作目录内（控制台工具层校验）。

## 分期实施

1. **M1（静态先行，✅ 已完成）**：外挂 MobSF 服务 REST 集成；移动静态任务（APK/IPA 上传 → 扫描 → finding/组件登记）；Android（OVAA/MASTG/ViPlexHandy）+ iOS（iBugBazaar）双平台验证。
2. **M2（动态 Android，Bridge 主力）**：mobile gateway（wss/token/设备注册表/占用锁）+ DroidBridge 设备端 fork（协议不变）+ LLM 工具层（exec/pull/push/screencap/流量→MITM）。~~模拟器实例池~~（已移除：VM 部署环境无嵌套虚拟化，不现实）。
3. **M3（动态 iOS）**：SentinelBridge fork（rootless 优先）+ 砸壳 dump 喂静态引擎 + iOS 工具层。
4. **M4（串联）**：静态发现→动态验证意图的 planner 编排；设备复位钩子；多设备调度。

## 与现有执行环境声明的关系

本文取代执行环境表中的「Android：本地模拟器 + adb 连接方式（未排期）」与「iOS：未涉及」两行的**架构决策**；实施节奏见分期。adb 降级为本地模拟器/真机调试的快捷通道，不再作为主架构。
