// M3 planner 决策卡数据层（docs §8.5）：把探索图里的 planner 决策痕迹
// （意图 + 依据 reason + 目标判定）与 todo_items 快照（M2-1）聚合成决策卡可
// 读的结构。数据本身全部来自既有探索图，本文件只做投影，不落任何新表。
package db

import (
	"encoding/json"
	"time"
)

// DecisionIntent 是 planner 派发的一条意图及其决策依据（决策卡一行）。
// Reason 来自 add_intent 的 reason 字段（M3 新增，可审计）；旧节点为空。
type DecisionIntent struct {
	ID        int64     `json:"id"`
	Summary   string    `json:"summary"`
	Reason    string    `json:"reason"`
	State     string    `json:"state"` // open | running | done | blocked | cancelled
	Priority  int       `json:"priority"`
	CreatedAt time.Time `json:"created_at"`
}

// DecisionGoal 是目标判定的一行（text + 判定状态 met/open）。
type DecisionGoal struct {
	ID        int64     `json:"id"`
	Text      string    `json:"text"`
	VulnClass string    `json:"vulnclass,omitempty"`
	State     string    `json:"state"` // open | met (prove_goal 后)
	CreatedAt time.Time `json:"created_at"`
}

// TaskExplorationID 返回任务绑定的探索 id（tasks.exploration_id，1:1 唯一）。
func (d *DB) TaskExplorationID(taskID int64) (int64, error) {
	var expID int64
	err := d.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, taskID).Scan(&expID)
	return expID, err
}

// DecisionIntents 返回本探索的全部意图（新→旧），投影 summary/reason 等。
func (s *ExplorationStore) DecisionIntents() ([]DecisionIntent, error) {
	nodes, err := s.ListByKind(KindIntent, 1000)
	if err != nil {
		return nil, err
	}
	out := make([]DecisionIntent, 0, len(nodes))
	for _, n := range nodes {
		var p struct {
			Summary string `json:"summary"`
			Reason  string `json:"reason"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		out = append(out, DecisionIntent{
			ID: n.ID, Summary: p.Summary, Reason: p.Reason,
			State: n.State, Priority: n.Priority, CreatedAt: n.CreatedAt,
		})
	}
	return out, nil
}

// DecisionGoals 返回本探索的全部目标及其判定状态。
func (s *ExplorationStore) DecisionGoals() ([]DecisionGoal, error) {
	nodes, err := s.ListByKind(KindGoal, 500)
	if err != nil {
		return nil, err
	}
	out := make([]DecisionGoal, 0, len(nodes))
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		out = append(out, DecisionGoal{
			ID: n.ID, Text: p.Text, VulnClass: p.VulnClass,
			State: n.State, CreatedAt: n.CreatedAt,
		})
	}
	return out, nil
}
