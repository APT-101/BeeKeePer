// M2-4 上下文构成清单（docs §3.5 落地，agent 包内实现）：
// planner 每轮在 user 输入末尾渲染一份"上下文构成清单"——本轮喂了哪些块
// （态势/待办/跨任务经验/cold digest…），每块 token 估算、是否被折叠、可在
// 何处展开。目的是决策可解释性：planner 与人都能看出本轮依据什么做规划，
// 以及被 digest 压缩掉的部分重不重要（重要就 expand_digest 展开）。
package agent

import (
	"fmt"
	"strings"
)

// ContextBlock describes one piece of context injected into the current round.
type ContextBlock struct {
	Name     string // graph_overview / todos / lessons / cold_digest / …
	Tokens   int    // 估算（启发式，非精确；见 estimateTokens）
	Foldable bool   // 可折叠（有 lazy-expand 对应物）
	Folded   bool   // 当前以折叠形式呈现
	Note     string // 一句话说明块的内容/何时展开
}

// estimateTokens 是启发式 token 估算：中英混合文本按 len/3 计（汉字约 1
// token、英文约 4 字符 1 token，取折中），纯展示用途，不用于精确预算。
func estimateTokens(s string) int {
	n := len(s)
	if n <= 0 {
		return 0
	}
	t := n / 3
	if n%3 != 0 {
		t++
	}
	if t < 1 {
		t = 1
	}
	return t
}

// renderContextManifest 把上下文构成清单渲染成 user 提示块（空列表返回空串）。
func renderContextManifest(blocks []ContextBlock) string {
	if len(blocks) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【上下文构成清单（本轮喂给你的内容，供你判断是否需要展开/补充）】：\n")
	total := 0
	for _, bl := range blocks {
		total += bl.Tokens
		mark := ""
		if bl.Foldable {
			mark = "（可展开）"
			if bl.Folded {
				mark = "（已折叠，用 expand_digest 展开）"
			}
		}
		b.WriteString(fmt.Sprintf("  • %s：约 %d tokens%s %s\n", bl.Name, bl.Tokens, mark, bl.Note))
	}
	b.WriteString(fmt.Sprintf("  合计约 %d tokens（均为估算值；被折叠或未喂的细节不代表已丢失，需要时用对应工具取回）。", total))
	return b.String()
}

// composePlannerManifest 组装 planner 轮次的构成清单。situational 已包含
// renderGraphOverview 的全文；todoText/lessonText 是已渲染的跨唤醒待办与
// 跨任务经验文本（空串跳过）；digestCount/coveredCount 来自 cold-digest
// 概览（0 表示未启用或无折叠）。
func composePlannerManifest(situational, todoText, lessonText string, digestCount, coveredCount int) string {
	blocks := []ContextBlock{}
	if situational != "" {
		blocks = append(blocks, ContextBlock{
			Name:   "graph_overview（本任务态势）",
			Tokens: estimateTokens(situational), Note: "任务/资产/意图/事实/目标概览 + 本轮触发信号；需要单点细节用 node_detail(id)。",
		})
	}
	if todoText != "" {
		blocks = append(blocks, ContextBlock{
			Name: "planner_todos（跨唤醒规划待办）", Tokens: estimateTokens(todoText),
			Note: "上一轮你写下的串行链/待办；用 TodoWrite 更新。",
		})
	}
	if lessonText != "" {
		blocks = append(blocks, ContextBlock{
			Name: "lesson_notes（跨任务经验）", Tokens: estimateTokens(lessonText),
			Note: "启发式参考，须与当前任务现象核对后采信。",
		})
	}
	factors := ""
	if digestCount > 0 {
		factors = fmt.Sprintf("（%d 个 digest 折叠了 %d 条冷节点）", digestCount, coveredCount)
	}
	blocks = append(blocks, ContextBlock{
		Name: "cold_digest（冷区压缩）" + factors, Tokens: 0,
		Foldable: true, Folded: digestCount > 0,
		Note: "折叠不等于丢失，expand_digest(id) 取成员、node_detail(id) 取细节。",
	})
	return renderContextManifest(blocks)
}
