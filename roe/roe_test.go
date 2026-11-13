package roe

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestCompileFromScope(t *testing.T) {
	scope := []db.TaskScope{
		{Kind: "root_domain", Domain: "example.com"},
		{Kind: "subdomain", Domain: "api.example.com"},
		{Kind: "ip", Net: "10.0.0.5"},
		{Kind: "cidr", Net: "192.168.1.0/24"},
		{Kind: "cidr", Net: "10.1.2.3"},          // bare IP → /32
		{Kind: "keyword", Value: "pentest-corp"}, // not expressible → warning
		{Kind: "company"},                        // resolved by caller into companyAssets
	}
	compiled, warns := Compile(scope, []db.Asset{
		{Type: "root_domain", Domain: "corp.example.net"},
		{Type: "ip", IP: "203.0.113.9"},
		{Type: "cidr", CSegment: "198.51.100.0/24"},
	})
	if compiled == nil || len(compiled.Rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	found := false
	for _, w := range warns {
		if w == "scope kind keyword not expressible as egress rule" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected keyword scope warning, got %v", warns)
	}
	// duplicate root_domain appears once
	if len(compiled.Rules[0].Domains) != 3 { // example.com, api.example.com, corp.example.net
		t.Errorf("expected 3 domains, got %v", compiled.Rules[0].Domains)
	}
}

func TestAllowMatching(t *testing.T) {
	compiled, _ := Compile([]db.TaskScope{
		{Kind: "root_domain", Domain: "example.com"},
		{Kind: "ip", Net: "10.0.0.5"},
		{Kind: "cidr", Net: "192.168.1.0/24"},
	}, nil)
	cases := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example.com:443", true},
		{"example.org", false},
		{"abc-example.com", false}, // 后缀必须 . 分隔
		{"10.0.0.5", true},
		{"10.0.0.5:8080", true},
		{"10.0.0.6", false},
		{"192.168.1.77", true},
		{"192.168.2.1", false},
	}
	for _, tc := range cases {
		got, reason := Allow(tc.target, compiled)
		if got != tc.want {
			t.Errorf("Allow(%q) = %v (reason=%q), want %v", tc.target, got, reason, tc.want)
		}
	}
}

func TestParseHost(t *testing.T) {
	h := ParseHost("example.com:8443")
	if h.Name != "example.com" || h.Port != 8443 {
		t.Errorf("ParseHost(example.com:8443) = %+v", h)
	}
	h = ParseHost("10.0.0.5")
	if h.Name != "10.0.0.5" || h.Port != 0 {
		t.Errorf("ParseHost(10.0.0.5) = %+v", h)
	}
	if h2 := ParseHost("[2001:db8::1]:53"); h2.Name != "2001:db8::1" || h2.Port != 53 {
		t.Errorf("ParseHost(v6) = %+v", h2)
	}
}

func TestAllowObserveMode(t *testing.T) {
	compiled, _ := Compile(nil, nil)
	compiled.DenyDefault = false // 观察模式：范围外只记录不阻断
	got, _ := Allow("evil.com", compiled)
	if !got {
		t.Error("observe mode must allow (log-only)")
	}
}

func TestAllowEmptyRulesDeny(t *testing.T) {
	got, _ := Allow("anything.com", nil)
	if got {
		t.Error("nil policy must deny by default")
	}
}
