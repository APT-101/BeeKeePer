package roe

import (
	"encoding/json"
	"reflect"
	"testing"
)

func cmdTool(input string) json.RawMessage {
	return json.RawMessage(`{"command":` + mustQuote(input) + `}`)
}

func mustQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestExtractTargetsBash(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"curl -s http://evil.com/vuln", []string{"evil.com"}},
		{"curl -X POST -d a=1 https://api.example.com:8443/login", []string{"api.example.com:8443"}},
		{"wget http://10.0.0.5/a", []string{"10.0.0.5"}},
		{"curl httpbin.org:8080/path", []string{"httpbin.org:8080"}},
		{"ssh -p 2222 root@10.0.0.9", []string{"10.0.0.9"}},
		{"ssh jump.example.com", []string{"jump.example.com"}},
		{"nc -zv 192.168.1.10 80", []string{"192.168.1.10"}},
		{"ping -c 3 example.org", []string{"example.org"}},
		{"dig +short A api.example.com", []string{"api.example.com"}},
		{"openssl s_client -connect db.example.com:5432", []string{"db.example.com:5432"}},
		{"echo hello world", nil},
		{"cat /etc/hosts", nil},
		{"ls -la /tmp", nil},
		{"curl -s http://a.com/x http://b.com:8080/y", []string{"a.com", "b.com:8080"}},
	}
	for _, tc := range cases {
		got := ExtractTargets("Bash", cmdTool(tc.cmd))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ExtractTargets(Bash, %q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestExtractTargetsWebFetch(t *testing.T) {
	got := ExtractTargets("WebFetch", json.RawMessage(`{"url":"https://sup.example.com/dir"}`))
	if !reflect.DeepEqual(got, []string{"sup.example.com"}) {
		t.Errorf("WebFetch = %v", got)
	}
	got = ExtractTargets("fetch_url", json.RawMessage(`{"url":"http://10.0.0.7:9000/x"}`))
	if !reflect.DeepEqual(got, []string{"10.0.0.7:9000"}) {
		t.Errorf("fetch_url = %v", got)
	}
	if got := ExtractTargets("fetch_url", json.RawMessage(`{"url":"data:text/plain,x"}`)); got != nil {
		t.Errorf("data: URL must be ignored, got %v", got)
	}
	// web_search 无网络目标（query 不是可执行目标）
	if got := ExtractTargets("web_search", json.RawMessage(`{"query":"example.com"}`)); got != nil {
		t.Errorf("web_search must yield nothing, got %v", got)
	}
}

func TestExtractTargetsNonNetwork(t *testing.T) {
	for _, tool := range []string{"Read", "Write", "report_finding", "add_task_scope", "list_assets"} {
		if got := ExtractTargets(tool, json.RawMessage(`{"path":"/x"}`)); got != nil {
			t.Errorf("%s must not extract targets, got %v", tool, got)
		}
	}
	if got := ExtractTargets("Bash", json.RawMessage(`{"command":123}`)); got != nil {
		t.Errorf("non-string input must be ignored, got %v", got)
	}
}
