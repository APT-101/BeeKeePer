package db

import (
	"testing"
)

// skipNoPG skips when the test environment has no PostgreSQL configured.
func skipNoPG(t *testing.T) {
	t.Helper()
	if _, _, err := DSN(); err != nil {
		t.Skip("no PostgreSQL configured (ARTEX_PG_DSN / config.json)")
	}
}

func TestTaskPolicyRoundTrip(t *testing.T) {
	skipNoPG(t)
	d, err := Open(mustTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tk := createScratchTask(t, d)

	level, err := d.GetTaskPolicy(tk.ID)
	if err != nil || level != "full" {
		t.Fatalf("default policy = %q, err=%v (want full)", level, err)
	}
	changed, err := d.SetTaskPolicy(tk.ID, "passive")
	if err != nil || !changed {
		t.Fatalf("SetTaskPolicy = %v, err=%v", changed, err)
	}
	level, _ = d.GetTaskPolicy(tk.ID)
	if level != "passive" {
		t.Fatalf("policy after update = %q, want passive", level)
	}
	if _, err := d.SetTaskPolicy(tk.ID, "bogus"); err == nil {
		t.Fatal("invalid tier must be rejected")
	}
}

func TestTaskEgressRoundTrip(t *testing.T) {
	skipNoPG(t)
	d, err := Open(mustTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tk := createScratchTask(t, d)

	e := &TaskEgress{
		TaskID:       tk.ID,
		CompiledFrom: "scope",
		AllowDomains: []string{"example.com", "*.corp.example.net"},
		AllowIPs:     []string{"10.0.0.5", "203.0.113.9"},
		AllowCIDRs:   []string{"192.168.1.0/24"},
		AllowPorts:   []int{80, 443, 8443},
		DenyDefault:  true,
		Version:      1,
	}
	if err := d.UpsertTaskEgress(e); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetTaskEgress(tk.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTaskEgress = %v, err=%v", got, err)
	}
	if len(got.AllowDomains) != 2 || got.AllowDomains[0] != "example.com" {
		t.Errorf("domains = %v", got.AllowDomains)
	}
	if len(got.AllowIPs) != 2 || got.AllowIPs[1] != "203.0.113.9" {
		t.Errorf("ips = %v", got.AllowIPs)
	}
	if len(got.AllowCIDRs) != 1 || got.AllowCIDRs[0] != "192.168.1.0/24" {
		t.Errorf("cidrs = %v", got.AllowCIDRs)
	}
	if len(got.AllowPorts) != 3 || got.AllowPorts[2] != 8443 {
		t.Errorf("ports = %v", got.AllowPorts)
	}
	if !got.DenyDefault || got.Version != 1 {
		t.Errorf("meta = deny=%v version=%d", got.DenyDefault, got.Version)
	}

	id, err := d.LogEgressViolation(&EgressViolation{
		TaskID: tk.ID, IntentID: 5, Tool: "curl", Target: "evil.example.net", Reason: "outside scope", Blocked: true,
	})
	if err != nil || id <= 0 {
		t.Fatalf("LogEgressViolation = %d, err=%v", id, err)
	}
	viols, err := d.ListEgressViolations(tk.ID, 10)
	if err != nil || len(viols) != 1 {
		t.Fatalf("ListEgressViolations = %d rows, err=%v", len(viols), err)
	}
	if viols[0].Tool != "curl" || !viols[0].Blocked || viols[0].IntentID != 5 {
		t.Errorf("violation row = %+v", viols[0])
	}
}

// mustTestDSN returns the DSN, skipping is handled by skipNoPG.
func mustTestDSN(t *testing.T) string {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Fatal(err)
	}
	return dsn
}

// createScratchTask inserts a minimal task row for policy/egress tests.
func createScratchTask(t *testing.T, d *DB) *Task {
	t.Helper()
	tk, err := d.CreateTask("m1-scratch", "t", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, tk.ID)
		_, _ = d.Exec(`DELETE FROM egress_violations WHERE task_id=$1`, tk.ID)
	})
	return tk
}

// MustGetTask fetches a task or fails the test.
func MustGetTask(t *testing.T, d *DB, id int64) *Task {
	t.Helper()
	tk, err := d.GetTask(id)
	if err != nil || tk == nil {
		t.Fatalf("GetTask(%d) = %v, err=%v", id, tk, err)
	}
	return tk
}
