package db

import (
	"encoding/json"
)

// LogConfigChange records one configuration mutation (M0 config audit:
// "who changed what at which point"). before/after are JSON-encoded into the
// row; pass nil when only one side is known (or for deletes).
func (d *DB) LogConfigChange(actor, action, resourceType, resourceID string, before, after any) error {
	b, err := jb(before)
	if err != nil {
		return err
	}
	a, err := jb(after)
	if err != nil {
		return err
	}
	_, err = d.Exec(`INSERT INTO config_audit_log(actor, action, resource_type, resource_id, before, after)
VALUES ($1, $2, $3, NULLIF($4,''), $5, $6)`,
		actor, action, resourceType, resourceID, json.RawMessage(b), json.RawMessage(a))
	return err
}

// jb marshals v to JSON bytes; nil → `{}`. Reuses json.RawMessage for params so
// pgx encodes it as JSONB rather than bytea (same trick as AppendActivity).
func jb(v any) ([]byte, error) {
	if v == nil {
		return []byte(`{}`), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return []byte(`{}`), nil
	}
	return b, nil
}
