// tools_mobile.go：M2 动态轨的 agent 工具层——通过 mobile gateway 操作
// 反连的 Android 真机（Sentinel DroidBridge 协议）。工具面设计参考
// agent-droid-bridge（MCP/adb）的清单，传输走自家 Bridge 反连。
// server 通过 SetMobileFn 注入实现（nil = 无在线设备/未接线），与 mobsf
// 同模式；产物（截图/抓包/拉取文件）由网关聚合落 tasks/<id>/mobile/。
package agent

import (
	"context"
	"encoding/json"
	"fmt"

	actool "github.com/Autumn-27/norma/tool"
)

// mobileFrame 即协议命令帧（网关补 reqId），工具层只关心命令语义与
// result 帧字段（ok/code/stdout/file_path/bytes 等）。
type mobileFrame = map[string]any

func (t *ToolSet) mobileTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.mobileExecTool(),
		t.mobilePackagesTool(),
		t.mobileLogcatTool(),
		t.mobileScreencapTool(),
		t.mobilePullTool(),
		t.mobilePushTool(),
	}
}

func (t *ToolSet) mobileExecTool() actool.CoreTool {
	return writeTool(
		"mobile_exec",
		"在反连的 Android 真机上执行 shell 命令（asRoot=true 时经 su，Magisk 授权）。\n"+
			"典型用途：动态验证静态线索（读配置/启动组件/查看文件）、运行 frida 脚本、安装/启动应用。\n"+
			"返回：{ok, code, stdout, stderr}。前置：真机已启动 DroidBridge 反连。",
		obj(map[string]any{
			"cmd":       str("要执行的 shell 命令（绝对路径调用更可靠）"),
			"asRoot":    map[string]any{"type": "boolean", "description": "是否以 root 执行（默认 false）"},
			"timeoutMs": intp("超时毫秒（默认 30000，上限 600000）"),
		}, "cmd"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.mobileFn == nil {
				return actool.Errorf("mobile_exec 未启用：无在线设备或未接线"), nil
			}
			var a struct {
				Cmd       string  `json:"cmd"`
				AsRoot    bool    `json:"asRoot"`
				TimeoutMs float64 `json:"timeoutMs"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.Cmd == "" {
				return actool.Errorf("cmd 不能为空"), nil
			}
			res, err := t.mobileFn(t.taskID, map[string]any{
				"t": "exec", "cmd": a.Cmd, "asRoot": a.AsRoot, "timeoutMs": a.TimeoutMs,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		},
	)
}

func (t *ToolSet) mobilePackagesTool() actool.CoreTool {
	return writeTool(
		"mobile_packages",
		"列出反连设备上已安装的应用包名（thirdPartyOnly=true 只列第三方应用）。",
		obj(map[string]any{
			"thirdPartyOnly": map[string]any{"type": "boolean", "description": "只列第三方应用（默认 true）"},
		}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if t.mobileFn == nil {
				return actool.Errorf("mobile_packages 未启用：无在线设备"), nil
			}
			res, err := t.mobileFn(t.taskID, map[string]any{"t": "packages", "thirdPartyOnly": true})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		},
	)
}

func (t *ToolSet) mobileLogcatTool() actool.CoreTool {
	return writeTool(
		"mobile_logcat",
		"取设备 logcat 尾部（可按关键词过滤）——观察应用崩溃/安全日志/运行时行为。",
		obj(map[string]any{
			"lines":  intp("取尾部多少行（默认 200）"),
			"filter": str("关键词过滤（可空）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.mobileFn == nil {
				return actool.Errorf("mobile_logcat 未启用：无在线设备"), nil
			}
			var a struct {
				Lines  float64 `json:"lines"`
				Filter string  `json:"filter"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Lines <= 0 {
				a.Lines = 200
			}
			frame := mobileFrame{"t": "logcat", "lines": a.Lines}
			if a.Filter != "" {
				frame["filter"] = a.Filter
			}
			res, err := t.mobileFn(t.taskID, frame)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		},
	)
}

func (t *ToolSet) mobileScreencapTool() actool.CoreTool {
	return writeTool(
		"mobile_screencap",
		"对反连设备全屏截图（PNG）。产物由网关聚合落 tasks/<id>/mobile/，返回 file_path——作为 finding 证据或人工核查。",
		obj(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if t.mobileFn == nil {
				return actool.Errorf("mobile_screencap 未启用：无在线设备"), nil
			}
			res, err := t.mobileFn(t.taskID, map[string]any{"t": "screencap"})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if fp, ok := res["file_path"].(string); ok && fp != "" {
				if m, ok2 := res["summary"].(string); !ok2 || m == "" {
					res["summary"] = fmt.Sprintf("截图已保存: %s", fp)
				}
			}
			return jsonResult(res)
		},
	)
}

func (t *ToolSet) mobilePullTool() actool.CoreTool {
	return writeTool(
		"mobile_pull",
		"把设备上的文件拉回任务目录（分片回传）——提取配置/数据库/证书/APK 等证据。",
		obj(map[string]any{
			"path":     str("设备上的文件绝对路径（如 /data/data/<pkg>/databases/x.db）"),
			"maxBytes": intp("回传字节上限（默认 32MB）"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.mobileFn == nil {
				return actool.Errorf("mobile_pull 未启用：无在线设备"), nil
			}
			var a struct {
				Path     string  `json:"path"`
				MaxBytes float64 `json:"maxBytes"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.Path == "" {
				return actool.Errorf("path 不能为空"), nil
			}
			mb := a.MaxBytes
			if mb <= 0 {
				mb = 32 * 1024 * 1024
			}
			res, err := t.mobileFn(t.taskID, map[string]any{
				"t": "pull", "path": a.Path, "maxBytes": mb,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if fp, ok := res["file_path"].(string); ok && fp != "" {
				res["summary"] = "文件已拉回: " + fp
			}
			return jsonResult(res)
		},
	)
}

func (t *ToolSet) mobilePushTool() actool.CoreTool {
	return writeTool(
		"mobile_push",
		"把任务目录里的文件推到设备（分片上传）——推送 frida-server/测试 APK/脚本等。",
		obj(map[string]any{
			"file":     str("任务目录内的相对路径（如 uploads/frida-server）"),
			"destPath": str("设备上的目标绝对路径（如 /data/local/tmp/frida-server）"),
			"mode":     str("权限（默认 0700；可执行文件用 0755）"),
		}, "file", "destPath"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.mobileFn == nil {
				return actool.Errorf("mobile_push 未启用：无在线设备"), nil
			}
			var a struct {
				File     string `json:"file"`
				DestPath string `json:"destPath"`
				Mode     string `json:"mode"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.File == "" || a.DestPath == "" {
				return actool.Errorf("file 与 destPath 不能为空"), nil
			}
			mode := a.Mode
			if mode == "" {
				mode = "0700"
			}
			res, err := t.mobileFn(t.taskID, map[string]any{
				"t": "push", "file": a.File, "destPath": a.DestPath, "mode": mode,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			res["summary"] = "文件已推送: " + a.DestPath
			return jsonResult(res)
		},
	)
}
