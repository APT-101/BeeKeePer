package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// =====================================================================
// IoT 固件审计：组件登记 / 查询 / 状态 / 解包登记
// （移植自 ARTEX-IOT 分支；assets 与 components 是并行体系，互不替代）
// =====================================================================

// componentInputItem is one element of the insert_components "components" array.
type componentInputItem struct {
	Type           string   `json:"type"`
	ComponentName  string   `json:"component_name"`
	Version        string   `json:"version"`
	Vendor         string   `json:"vendor"`
	BinaryPath     string   `json:"binary_path"`
	ConfigPath     string   `json:"config_path"`
	StartedBy      string   `json:"started_by"`
	FirmwareSha256 string   `json:"firmware_sha256"`
	Port           int      `json:"port"`
	Technologies   []string `json:"technologies"`
	Notes          string   `json:"notes"`
	Status         string   `json:"status"`
}

// componentInputLabel 返回一条待登记组件的简短标识。
func componentInputLabel(item componentInputItem) string {
	name := strings.TrimSpace(item.ComponentName)
	if name == "" {
		return "(未命名组件)"
	}
	if v := strings.TrimSpace(item.Version); v != "" {
		return name + " " + v
	}
	return name
}

// insertComponents is the unified insert_components agent tool.
func (t *ToolSet) insertComponents() actool.CoreTool {
	return writeTool(
		"insert_components",
		"登记固件里的组件（一行 = 一个组件，例如 lighttpd/mosquitto/roscore）。\n"+
			"type 取值：web / mqtt / ros / ssh / telnet / upnp / onvif / rtsp / ftp / other；不确定就填 other。\n"+
			"component_name 必填（可执行名或服务名，如 lighttpd）。version 只在确知时填，不要猜。\n"+
			"可选：vendor 厂商、binary_path 固件内绝对路径、config_path 配置文件、started_by 启动脚本(/etc/init.d/xxx)、\n"+
			"      port 主监听端口、technologies 依赖库/特征、notes 备注（如「busybox telnetd，默认无认证」）。\n"+
			"同一 (firmware_sha256, type, component_name, version) 只会有一行：重复登记会补齐空字段而不是新增。\n"+
			"status 默认 pending（待挖）；开始分析某组件时用 set_component_status 置 running，分析完置 completed。\n"+
			"返回：{inserted, updated, ids}",
		obj(map[string]any{
			"components": map[string]any{
				"type":        "array",
				"description": "批量：[{type, component_name, version?, vendor?, binary_path?, config_path?, started_by?, port?, technologies?, notes?}]",
				"items":       map[string]any{"type": "object"},
			},
			"type":            str("[单条] web/mqtt/ros/ssh/telnet/upnp/onvif/rtsp/ftp/other"),
			"component_name":  str("[单条] 组件名（lighttpd / mosquitto / roscore）"),
			"version":         str("[单条] 版本号，确知才填"),
			"binary_path":     str("[单条] 可执行文件在固件内的绝对路径"),
			"config_path":     str("[单条] 配置文件路径"),
			"started_by":      str("[单条] 启动脚本路径"),
			"vendor":          str("[单条] 厂商/品牌（如 Xiaomi、Realtek）"),
			"port":            intp("[单条] 主监听端口"),
			"technologies":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "[单条] 依赖库/协议栈等特征"},
			"status":          str("[单条] 初始状态 pending/running/completed/ignored，默认 pending"),
			"firmware_sha256": str("[单条] 本组件所属固件的 sha256(64 位十六进制)：登记固件组件时应填本任务解包登记的固件（firmware_extracts 记录的固件本身，不是解包产物）；漏填时系统会在任务仅有唯一固件或同名容器对（X.zip+X.img）时自动补关联"),
			"notes":           str("[单条] 备注"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.comp == nil {
				return actool.Errorf("insert_components 未启用: ComponentStore 未初始化"), nil
			}
			var a struct {
				Items []componentInputItem `json:"components"`
				componentInputItem
				FirmwareSha256 string `json:"firmware_sha256"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			items := a.Items
			if len(items) == 0 {
				items = []componentInputItem{a.componentInputItem}
			}
			if len(items) == 0 {
				return actool.Errorf("components 不能为空"), nil
			}

			// 固件 sha256：单条/批量都可显式指定，否则回落到本任务已登记解包的固件。
			// 只在任务里恰好登记了一个固件时回落：多固件任务无从判断这条组件来自哪个固件，
			// 宁可留空（组件库按 COALESCE(sha,'') 归并），也不能把它标到随便一个固件名下。
			sha := strings.TrimSpace(a.FirmwareSha256)
			if sha == "" && t.taskID > 0 && t.fwx != nil {
				if shas := t.fwx.Sha256sForTask(t.taskID); len(shas) == 1 {
					sha = shas[0]
				}
			}

			var inputs []db.ComponentInput
			for i := range items {
				it := items[i]
				if it.FirmwareSha256 == "" {
					it.FirmwareSha256 = sha
				}
				inputs = append(inputs, db.ComponentInput{
					Type:           it.Type,
					Name:           it.ComponentName,
					Version:        it.Version,
					Vendor:         it.Vendor,
					BinaryPath:     it.BinaryPath,
					ConfigPath:     it.ConfigPath,
					StartedBy:      it.StartedBy,
					FirmwareSha256: it.FirmwareSha256,
					Port:           it.Port,
					Technologies:   it.Technologies,
					Notes:          it.Notes,
					Status:         it.Status,
				})
			}

			// binary_path 校验：按本任务已登记的解包根拼出宿主真实路径，文件不存在就拒绝整批。
			// 只约束 agent；无任务上下文（组件库独立新增 / 空壳 ToolSet）时跳过。
			if err := t.verifyComponentBinaries(inputs); err != nil {
				return actool.Errorf(err.Error()), nil
			}

			var taskIDs []int64
			if t.taskID > 0 {
				taskIDs = []int64{t.taskID}
			}
			inserted, updated, ids, err := t.comp.UpsertComponents(taskIDs, inputs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// 来源链路（与资产工具一致）：把组件锚到本次执行节点（worker=意图节点）
			// 并写任务↔组件来源行。两者都是一次写；失败不影响「组件已入库」这个结果。
			summary := "Agent 通过 insert_components 登记"
			var sourceNodeID *int64
			if t.ownerNode > 0 {
				n := t.ownerNode
				sourceNodeID = &n
				summary = fmt.Sprintf("Worker 意图 #%d 通过 insert_components 登记", t.ownerNode)
			}
			if t.taskID > 0 {
				_ = t.comp.SetTaskComponentSources(t.taskID, ids, "agent", summary, sourceNodeID)
			}
			for _, id := range ids {
				t.anchorOwner(id)
			}
			t.writes.Assets += inserted + updated
			return jsonResult(map[string]any{
				"inserted": inserted,
				"updated":  updated,
				"ids":      ids,
			})
		},
	)
}

// verifyComponentBinaries 校验每条 binary_path：按本任务已登记的解包根拼出宿主真实路径，
// 命中普通文件才算通过（用 Lstat，符号链接不算——链接不是可执行文件本体）；任一条不通过就整批拒绝，
// 并把「拼过哪些路径、解包根有哪些、下一步怎么查」一起回给模型，让它下一轮自己改对。
//
// 只管 agent：人的手工登记（POST /api/components）不走这里；没有任务上下文的 ToolSet
// （组件库独立新增、toolcatalog 里用 nil store 造的空壳）直接跳过，不报错也不 panic。
func (t *ToolSet) verifyComponentBinaries(items []db.ComponentInput) error {
	if t.taskID <= 0 || t.comp == nil || t.comp.DataDir() == "" {
		return nil
	}
	need := false
	for _, it := range items {
		if strings.TrimSpace(it.BinaryPath) != "" {
			need = true
			break
		}
	}
	if !need { // 全部没填路径：组件允许只登记名字
		return nil
	}
	roots := t.firmwareExtractRoots()
	taskDir := filepath.Join(t.comp.DataDir(), "tasks", strconv.FormatInt(t.taskID, 10))
	var fails []string
	for i, it := range items {
		raw := strings.TrimSpace(it.BinaryPath)
		if raw == "" {
			continue
		}
		label := fmt.Sprintf("第 %d 条 %s（type=%s）binary_path=%s", i+1, strings.TrimSpace(it.Name), it.Type, raw)
		container := filepath.ToSlash(raw)
		if !strings.HasPrefix(container, "/") || strings.Contains(container, "..") {
			fails = append(fails, label+" 格式不对：这里要写固件内绝对路径（以 / 开头、不含 ..），不是宿主机路径。")
			continue
		}
		if len(roots) == 0 {
			fails = append(fails, label+" 无法校验：本任务还没有登记解包根。请先解包并调 register_extract 登记解包目录，再重新登记该组件。")
			continue
		}
		var tried []string
		hit := ""
		linkTarget, linkSuggest := "", ""
		for _, root := range roots {
			rootAbs := filepath.Join(taskDir, filepath.FromSlash(strings.TrimPrefix(root, "/")))
			cand := filepath.Join(rootAbs, filepath.FromSlash(strings.TrimPrefix(container, "/")))
			rel, rerr := filepath.Rel(t.comp.DataDir(), cand)
			if rerr != nil {
				rel = cand
			}
			tried = append(tried, filepath.ToSlash(rel))
			// Lstat 不跟随软链：软链本身不是可执行文件本体，不能算通过。
			fi, serr := os.Lstat(cand)
			if serr != nil {
				continue
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				if linkTarget == "" {
					linkTarget = "（读取链接目标失败）"
					if val, lerr := os.Readlink(cand); lerr == nil {
						linkTarget = filepath.ToSlash(val)
					}
				}
				if linkSuggest == "" {
					linkSuggest = symlinkSuggestion(rootAbs, cand)
				}
				continue
			}
			if fi.Mode().IsRegular() {
				hit = cand
				break
			}
		}
		if hit == "" {
			if linkTarget != "" {
				msg := fmt.Sprintf("%s 校验失败：该路径在解包根里是符号链接（-> %s），不算可执行文件本体。", label, linkTarget)
				if linkSuggest != "" {
					msg += fmt.Sprintf("请改登记被指向的真实文件：%s。", linkSuggest)
				} else {
					msg += "链接目标不在解包根里或也不是普通文件：请用 ls -l 确认指向，按真实文件路径登记。"
				}
				fails = append(fails, msg)
				continue
			}
			fails = append(fails, fmt.Sprintf("%s 校验失败：按本任务解包根拼出来的文件都不存在。已尝试：%s。本任务解包根共 %d 个：%s。请先用 Bash 确认真实路径（当前目录即本任务目录，例：find . -name %s -type f），必要时 register_extract 更正解包根，再重新登记。",
				label, strings.Join(tried, "、"), len(roots), strings.Join(roots, "、"), filepath.Base(container)))
		}
	}
	if len(fails) > 0 {
		return fmt.Errorf("%s", strings.Join(fails, "\n"))
	}
	return nil
}

// symlinkSuggestion 把一个落在解包根内的软链解析成「可以登记的真实文件路径」，用于错误提示。
// 固件里的软链常是镜像内绝对路径（/sbin/ubusd）或多级跳转（tbusd -> ubusd -> busybox）：
// 绝对目标按解包根解释，相对目标按链接所在目录解释；最多跟 5 跳，只有最终落到根内的普通文件才给建议。
func symlinkSuggestion(rootAbs, linkPath string) string {
	cur := linkPath
	for hop := 0; hop < 5; hop++ {
		val, err := os.Readlink(cur)
		if err != nil {
			return ""
		}
		var next string
		if filepath.IsAbs(val) {
			next = filepath.Join(rootAbs, filepath.FromSlash(strings.TrimPrefix(filepath.ToSlash(val), "/")))
		} else {
			next = filepath.Join(filepath.Dir(cur), val)
		}
		next = filepath.Clean(next)
		fi, serr := os.Lstat(next)
		if serr != nil {
			return ""
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			cur = next
			continue
		}
		if !fi.Mode().IsRegular() {
			return ""
		}
		rel, rerr := filepath.Rel(rootAbs, next)
		if rerr != nil || strings.HasPrefix(filepath.ToSlash(rel), "..") {
			return ""
		}
		return "/" + filepath.ToSlash(rel)
	}
	return ""
}

// firmwareExtractRoots 取本任务登记的解包根（firmware_extracts.extract_path）。
// 这些值由 worker 写入，仍按不可信处理：空、绝对路径、含 .. 的一律跳过
// （与 server 侧反编译导出的过滤规则一致）。
func (t *ToolSet) firmwareExtractRoots() []string {
	if t.fwx == nil {
		return nil
	}
	return t.fwx.RootsForTask(t.taskID)
}

// listComponents lets an agent query the component table.
func (t *ToolSet) listComponents() actool.CoreTool {
	return readTool(
		"list_components",
		"查询组件库：DSL 表达式搜索，或按 id/ids 直取；支持分页。只返回本任务范围内的组件。\n"+
			"DSL：field=value 模糊(ILIKE) | field==value 精确 | field!=value 排除 | 数字字段支持 > >= < <= | 裸词=全文模糊；AND/OR 组合(AND 优先级高)，可用括号分组。组件类型用独立 type 参数，不写进 DSL。\n"+
			"未传 id/ids 时 dsl 必须非空（不允许无条件全量查询）。\n"+
			"可用字段：component_name(组件名)、version、vendor、binary_path、config_path、started_by、status(pending|running|completed|ignored)、firmware_sha256、technology(数组，=模糊 ==精确)、port(整数)。\n"+
			"示例：status==pending AND type==web ；component_name=lighttpd ；port==1883",
		obj(map[string]any{
			"dsl":    str(`DSL 查询表达式（语法/字段见工具描述）。未传 id/ids 时必须非空。`),
			"type":   str("组件类型过滤：web|mqtt|ros|ssh|telnet|upnp|onvif|rtsp|ftp|other（独立字段，可与 dsl 叠加；单独 type 不足以查询，仍需 dsl）"),
			"id":     intp("直接按单个组件 id 取（可选，与 dsl/type 互斥）"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "直接按多个组件 id 取（可选，与 dsl/type 互斥）"},
			"limit":  intp("返回上限，默认 10（可选）"),
			"offset": intp("分页偏移，默认 0（可选）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.comp == nil {
				return actool.Errorf("list_components 未启用: ComponentStore 未初始化"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var components []*db.Component
			var err error
			switch {
			case a.ID > 0:
				components, err = t.comp.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				components, err = t.comp.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				components, err = t.comp.QueryDSLInScope(a.DSL, a.Type, "", t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("未传 id/ids 时 dsl 不能为空：不允许无条件查询全部组件，请提供查询条件"), nil
			}
			if err != nil {
				return actool.Errorf("DSL 错误: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":      len(components),
				"components": components,
			})
		},
	)
}

// setComponentStatus marks a component's mining progress so 覆盖度 reflects reality.
func (t *ToolSet) setComponentStatus() actool.CoreTool {
	return writeTool(
		"set_component_status",
		"更新组件挖掘状态（本任务范围内的组件才能改）。\n"+
			"status 取值：pending(待挖，登记后的默认值) / running(正在挖) / completed(已挖完，计入覆盖度分子) / ignored(不挖，不计入分母)。\n"+
			"开始分析某个组件时置 running；这条组件在本任务里挖完（该看的入口都看过）置 completed；判定不值得挖置 ignored。\n"+
			"支持 ids 批量，或 id 单个。返回 {updated, errors}",
		obj(map[string]any{
			"id":     intp("[单个] 组件 id（来自 insert_components / list_components）"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[批量] 组件 id 列表"},
			"status": str("pending|running|completed|ignored"),
		}, "status"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.comp == nil {
				return actool.Errorf("set_component_status 未启用: ComponentStore 未初始化"), nil
			}
			var a struct {
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Status string  `json:"status"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ids := a.IDs
			if a.ID > 0 {
				ids = append(ids, a.ID)
			}
			if len(ids) == 0 {
				return actool.Errorf("id 或 ids 至少给一个"), nil
			}
			var errs []string
			updated := 0
			for _, id := range ids {
				if err := t.comp.SetTaskComponentStatus(t.taskID, id, a.Status); err != nil {
					errs = append(errs, fmt.Sprintf("%d: %v", id, err))
					continue
				}
				updated++
			}
			return jsonResult(map[string]any{"updated": updated, "errors": errs})
		},
	)
}

// registerExtract 让真正解包的那个 worker 把根目录登记到本任务的固件解包登记上。
// 上传时不写这一列，第一次解包后才回填；之后所有意图复用同一路径，不再重复解包。
func (t *ToolSet) registerExtract() actool.CoreTool {
	return writeTool(
		"register_extract",
		"解包完成后调用：把解包得到的根目录登记到本任务（固件解包登记 extract_path），"+
			"之后其它意图复用这个路径，不用再解一遍。\n"+
			"path：解包得到的根目录，可以就在 firmware/ 下（例如 firmware/rootfs）；只接受本任务目录内的路径。\n"+
			"firmware：可选，固件文件名或 64 位 sha256；任务里有多份固件时必须指定。\n"+
			"note：可选，解包器与主命令（例如 sasquatch -d rootfs R6220.bin），便于复现。\n"+
			"返回：{extract_path(相对), abs_path, firmware:{value,sha256}, extract_id, entries, already, previous}",
		obj(map[string]any{
			"path":     str("解包得到的根目录（相对任务目录或绝对路径，必须落在本任务目录内）"),
			"firmware": str("可选：固件文件名或 64 位 sha256；多份固件时必填"),
			"note":     str("可选：解包器与主命令，便于复现"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path     string `json:"path"`
				Firmware string `json:"firmware"`
				Note     string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.fwx == nil {
				return actool.Errorf("register_extract 未启用: FirmwareExtractStore 未初始化"), nil
			}
			dataDir := t.fwx.DataDir()
			if t.taskID <= 0 || dataDir == "" {
				return actool.Errorf("register_extract 需要任务上下文与数据目录"), nil
			}
			taskDir := filepath.Join(dataDir, "tasks", strconv.FormatInt(t.taskID, 10))
			raw := strings.TrimSpace(a.Path)
			if raw == "" {
				return actool.Errorf("path 不能为空：填解包得到的根目录"), nil
			}
			abs := raw
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(taskDir, raw)
			}
			// 软链逃逸防护：两侧都取真实路径后再比前缀。
			real, err := filepath.EvalSymlinks(filepath.Clean(abs))
			if err != nil {
				return actool.Errorf(fmt.Sprintf("路径不存在或无法解析: %v", err)), nil
			}
			base := taskDir
			if b, err := filepath.EvalSymlinks(taskDir); err == nil {
				base = b
			}
			rel, err := filepath.Rel(base, real)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return actool.Errorf("path 必须在本任务目录内（" + base + "）"), nil
			}
			st, err := os.Stat(real)
			if err != nil || !st.IsDir() {
				return actool.Errorf("path 不是已存在的目录"), nil
			}
			// 完整性判定用递归文件数，不用顶级条目数：合法 rootfs（OpenWrt squashfs
			// 解包形态）顶级只有 etc/lib/tmp/usr/www 这类少量目录，文件都在子目录里，
			// 顶级计数会把完整 rootfs 误判成半成品。
			files := 0
			walkErr := filepath.WalkDir(real, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil // 无权限子树跳过，不阻断登记
				}
				if !d.IsDir() {
					files++
				}
				return nil
			})
			if walkErr != nil {
				return actool.Errorf("遍历目录失败: " + walkErr.Error()), nil
			}
			if files < 20 {
				return actool.Errorf(fmt.Sprintf("目录里递归只有 %d 个文件，看起来是半成品；确认解包完整后再登记", files)), nil
			}

			fwName, fwSha, err := t.locateFirmwareFile(filepath.Join(taskDir, "firmware"), a.Firmware, real)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			note := strings.TrimSpace(a.Note)
			fe, prev, err := t.fwx.SetFirmwareExtract(t.taskID, fwSha, fwName, filepath.ToSlash(rel), note)
			if err != nil {
				return actool.Errorf("登记失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ok":           true,
				"extract_path": fe.ExtractPath,
				"abs_path":     real,
				"firmware":     map[string]any{"value": fe.Name, "sha256": fe.Sha256},
				"extract_id":   fe.ID,
				"entries":      files,
				"already":      prev == fe.ExtractPath,
				"previous":     prev,
			})
		})
}

// locateFirmwareFile 找到本次解包对应的固件文件，返回 (文件名, sha256)。
// skip 是刚登记的解包目录本身——它可能就在 firmware/ 下，枚举时必须排除。
func (t *ToolSet) locateFirmwareFile(fwDir, spec, skip string) (string, string, error) {
	spec = strings.TrimSpace(spec)
	// 显式文件名：直接取，不猜。
	if spec != "" && !looksLikeSha256(spec) {
		if strings.ContainsAny(spec, `/\`) {
			return "", "", fmt.Errorf("firmware 只接受文件名或 sha256，不要带路径")
		}
		p := filepath.Join(fwDir, spec)
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return "", "", fmt.Errorf("firmware/ 下找不到固件文件 %s", spec)
		}
		sum, err := sha256File(p)
		if err != nil {
			return "", "", fmt.Errorf("计算固件摘要失败: %v", err)
		}
		return spec, sum, nil
	}
	// 其余情况：只看 firmware/ 下的常规文件（跳过目录，解包产物可能就在里面）。
	ents, err := os.ReadDir(fwDir)
	if err != nil {
		return "", "", fmt.Errorf("读不到固件目录 firmware/：%v", err)
	}
	type cand struct{ name, path string }
	var cands []cand
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(fwDir, e.Name())
		if skip != "" && p == skip {
			continue
		}
		if st, err := e.Info(); err != nil || !st.Mode().IsRegular() {
			continue
		}
		cands = append(cands, cand{e.Name(), p})
	}
	if len(cands) == 0 {
		return "", "", fmt.Errorf("firmware/ 下没有固件文件，无法登记解包产物")
	}
	// 指定了 sha：逐一比对。
	if spec != "" {
		for _, c := range cands {
			if sum, err := sha256File(c.path); err == nil && strings.EqualFold(sum, spec) {
				return c.name, sum, nil
			}
		}
		return "", "", fmt.Errorf("firmware/ 下没有摘要为 %s 的固件", spec)
	}
	// 没指定：恰好一份就直接用；多份则用已登记解包的固件名收敛。
	if len(cands) > 1 {
		known := map[string]bool{}
		if t.fwx != nil {
			if fws, err := t.fwx.ListTaskExtracts(t.taskID); err == nil {
				for _, f := range fws {
					if f.Name != "" {
						known[f.Name] = true
					}
				}
			}
		}
		var only []cand
		for _, c := range cands {
			if known[c.name] {
				only = append(only, c)
			}
		}
		if len(only) != 1 {
			names := make([]string, 0, len(cands))
			for _, c := range cands {
				names = append(names, c.name)
			}
			return "", "", fmt.Errorf("firmware/ 下有多份固件，请用 firmware 参数指定：%s", strings.Join(names, ", "))
		}
		cands = only
	}
	sum, err := sha256File(cands[0].path)
	if err != nil {
		return "", "", fmt.Errorf("计算固件摘要失败: %v", err)
	}
	return cands[0].name, sum, nil
}

// looksLikeSha256 判断是否 64 位十六进制摘要。
func looksLikeSha256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sha256File 流式计算文件摘要（跳过目录/非普通文件）。
func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// mobsfScan 把任务目录内的 APK/IPA/固件包交给 MobSF 静态引擎（REST API）做
// 全量静态扫描。server 通过 SetMobsfScan 注入实现（nil = 未配置/未 wire）；
// 上传与报告轮询由 server 直连 MobSF 完成，不经沙箱（与 IDA 反编译链同模式）。
// 返回摘要（app 包名/版本、manifest 与代码分析计数、报告 JSON 落盘路径），
// agent 据此用 insert_finding / insert_components 登记结构化结果。
func (t *ToolSet) mobsfScan() actool.CoreTool {
	return writeTool(
		"mobsf_scan",
		"把本任务目录内的 APK/IPA/固件包交给 MobSF 静态引擎做全量静态扫描（上传→等待扫描→取完整报告）。\n"+
			"path：目标文件相对任务目录的路径（例如 uploads/app.apk 或 firmware/app.apk）。\n"+
			"返回：{hash, report_path(报告 JSON 落盘路径), summary:{app_name, package_name, version_name, "+
			"manifest_findings, permissions_count, android_api_hits, hardcoded_secrets, report_sections}}。\n"+
			"扫描完成后：manifest 分析里的导出组件用 insert_components 登记（firmware_sha256 填本任务的包 sha），"+
			"代码分析高危条目用 insert_finding 落 finding，完整报告 JSON 可用 Read 直接读取。",
		obj(map[string]any{
			"path": str("目标文件相对任务目录的路径（uploads/app.apk、firmware/app.ipa 等）"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.mobsfScanFn == nil {
				return actool.Errorf("mobsf_scan 未启用：系统设置页未配置 MobSF API 地址与 key，或本运行未接线"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("mobsf_scan 需要任务上下文"), nil
			}
			raw := strings.TrimSpace(a.Path)
			if raw == "" {
				return actool.Errorf("path 不能为空：填目标文件相对任务目录的路径"), nil
			}
			res, err := t.mobsfScanFn(t.taskID, raw)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		},
	)
}
