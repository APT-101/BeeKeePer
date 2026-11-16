// M3 凭证保险库的 db 层（docs §8.5）：credential_vault 存取与取用审计。
// 密文字段 secret_enc 由 server 侧加密（AES-GCM 主密钥 dataDir/vault.key），
// 这里只做字节搬运，不接触明文。
package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrCredentialNotFound 在按名取凭据不存在时返回。
var ErrCredentialNotFound = errors.New("credential not found")

// Credential 是保险库一行（secret 为密文，调用方负责加解密）。
type Credential struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Host      string    `json:"host,omitempty"`
	Username  string    `json:"username,omitempty"`
	Secret    []byte    `json:"-"` // AES-GCM 密文 (nonce||ciphertext)
	Notes     string    `json:"notes,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PutCredential 幂等写入（name 存在则 UPDATE，否则 INSERT）。secret 必须已是密文。
func (d *DB) PutCredential(ctx context.Context, c *Credential) (int64, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM credential_vault WHERE name=$1`, c.Name).Scan(&id)
	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx, `
UPDATE credential_vault
SET kind=$2, host=$3, username=$4, secret_enc=$5, notes=$6, updated_at=now()
WHERE id=$1`, id, c.Kind, nulls(c.Host), nulls(c.Username), c.Secret, c.Notes); err != nil {
			return 0, err
		}
	case errors.Is(err, sql.ErrNoRows): // 无行 → INSERT
		if err := tx.QueryRowContext(ctx, `
INSERT INTO credential_vault (name, kind, host, username, secret_enc, notes, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			c.Name, c.Kind, nulls(c.Host), nulls(c.Username), c.Secret, c.Notes, c.CreatedBy).Scan(&id); err != nil {
			return 0, err
		}
	default:
		return 0, err
	}
	return id, tx.Commit()
}

// GetCredential 按名取一条（密文原样返回）。
func (d *DB) GetCredential(ctx context.Context, name string) (*Credential, error) {
	var c Credential
	var host, user, notes, by sql.NullString
	err := d.QueryRowContext(ctx, `
SELECT id, name, kind, host, username, secret_enc, notes, created_by, created_at, updated_at
FROM credential_vault WHERE name=$1`, name).
		Scan(&c.ID, &c.Name, &c.Kind, &host, &user, &c.Secret, &notes, &by, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Host, c.Username, c.Notes, c.CreatedBy = host.String, user.String, notes.String, by.String
	return &c, nil
}

// ListCredentials 返回全部凭据的元数据（**不含密文**）。
func (d *DB) ListCredentials(ctx context.Context) ([]Credential, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id, name, kind, host, username, notes, created_by, created_at, updated_at
FROM credential_vault ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var c Credential
		var host, user, notes, by sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &host, &user, &notes, &by, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Host, c.Username, c.Notes, c.CreatedBy = host.String, user.String, notes.String, by.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCredential 按 id 删（级联清取用审计）。
func (d *DB) DeleteCredential(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM credential_vault WHERE id=$1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

// LogCredentialAccess 记录一次凭据取用（agent get_credential 落下）。
func (d *DB) LogCredentialAccess(ctx context.Context, credentialID, taskID, intentID int64, worker, toolUseID string) error {
	_, err := d.ExecContext(ctx, `
INSERT INTO credential_access_log (credential_id, task_id, intent_id, worker, tool_use_id)
VALUES ($1,$2,$3,$4,$5)`,
		credentialID, nullInt64(taskID), nullInt64(intentID),
		strings.TrimSpace(worker), strings.TrimSpace(toolUseID))
	return err
}

// ListCredentialAccess 返回某凭据的取用审计（新→旧）。
func (d *DB) ListCredentialAccess(ctx context.Context, credentialID int64, limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `
SELECT COALESCE(task_id,0), COALESCE(intent_id,0), worker, tool_use_id, at
FROM credential_access_log WHERE credential_id=$1
ORDER BY at DESC LIMIT $2`, credentialID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var taskID, intentID int64
		var worker, toolUse string
		var at time.Time
		if err := rows.Scan(&taskID, &intentID, &worker, &toolUse, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"task_id": taskID, "intent_id": intentID,
			"worker": worker, "tool_use_id": toolUse, "at": at,
		})
	}
	return out, rows.Err()
}

// nullInt64 映射 0 → NULL。
func nullInt64(v int64) any {
	if v <= 0 {
		return nil
	}
	return v
}
