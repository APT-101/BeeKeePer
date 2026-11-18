package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/roe"
)

// egressSame drives refreshTaskEgress idempotence: an unchanged scope must not
// rewrite task_egress nor tear down the cached sandbox container (Bash 前每次
// refresh 必须零开销）；any delta — deny-default toggle, one allow-list, order —
// must be detected as change.
func TestEgressSame(t *testing.T) {
	base := &db.TaskEgress{
		TaskID: 7, CompiledFrom: "scope", DenyDefault: true,
		AllowDomains: []string{"a.example.com", "b.example.com"},
		AllowIPs:     []string{"10.0.0.5"},
		AllowCIDRs:   []string{"192.168.8.0/24"},
		AllowPorts:   []int{443, 8443},
	}
	rule := roe.EgressRule{
		Domains: []string{"a.example.com", "b.example.com"},
		IPs:     []string{"10.0.0.5"},
		CIDRs:   []string{"192.168.8.0/24"},
		Ports:   []uint16{443, 8443},
	}
	if !egressSame(base, rule) {
		t.Error("identical row+rule must be same")
	}

	cases := []struct {
		name   string
		mutate func(e *db.TaskEgress)
	}{
		{"nil row", func(e *db.TaskEgress) {}},
		{"deny-default off", func(e *db.TaskEgress) { e.DenyDefault = false }},
		{"extra domain", func(e *db.TaskEgress) { e.AllowDomains = append(e.AllowDomains, "c.example.com") }},
		{"missing ip", func(e *db.TaskEgress) { e.AllowIPs = nil }},
		{"cidr drift", func(e *db.TaskEgress) { e.AllowCIDRs = []string{"172.16.0.0/16"} }},
		{"port drift", func(e *db.TaskEgress) { e.AllowPorts = []int{443} }},
		{"domain order", func(e *db.TaskEgress) { e.AllowDomains = []string{"b.example.com", "a.example.com"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := *base
			tc.mutate(&row)
			if tc.mutate == nil {
				row = db.TaskEgress{}
			}
			if tc.name == "nil row" {
				if egressSame(nil, rule) {
					t.Error("nil row must be treated as change")
				}
				return
			}
			if egressSame(&row, rule) {
				t.Error("mutated row must be treated as change: " + tc.name)
			}
		})
	}
}