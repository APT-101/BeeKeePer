package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// =====================================================================
// firmware_extracts：固件解包登记（IoT 模块）
// =====================================================================
//
// 一行 = 一次固件解包登记：哪个任务的哪份固件（sha256）解到了任务目录下
// 的哪个相对路径。worker 解包完成后经 register_extract 工具写入；之后：
//   - 其它意图复用同一路径，不再重复解包；
//   - insert_components 的 binary_path 校验按这些解包根拼宿主真实路径；
//   - 反编译（IDA 无头导出）按解包根把固件内路径解析成宿主路径。
//
// 刻意独立成表而非扩展 task_scope：task_scope 的 kind 会参与 egress 编译，
// 固件解包路径与网络出网白名单语义无关，混入只会增加耦合。

// FirmwareExtract is one row of the firmware_extracts table.
type FirmwareExtract struct {
	ID          int64     `json:"id"`
	TaskID      int64     `json:"task_id"`
	Name        string    `json:"firmware_name"`
	Sha256      string    `json:"firmware_sha256"`
	ExtractPath string    `json:"extract_path"` // 相对任务目录，正斜杠
	Note        string    `json:"note,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const firmwareExtractCols = `id, task_id, firmware_name, firmware_sha256, extract_path, note, created_by, created_at, updated_at`

func scanFirmwareExtract(sc interface{ Scan(...any) error }) (*FirmwareExtract, error) {
	var f FirmwareExtract
	if err := sc.Scan(&f.ID, &f.TaskID, &f.Name, &f.Sha256, &f.ExtractPath, &f.Note,
		&f.CreatedBy, &f.CreatedAt, &f.UpdatedAt); err != nil {
		return nil, err
	}
	return &f, nil
}

// FirmwareExtractStore operates on the firmware_extracts table.
type FirmwareExtractStore struct {
	db *DB
	tx *sql.Tx
}

// FirmwareExtracts returns the firmware-extract store.
func (d *DB) FirmwareExtracts() *FirmwareExtractStore { return &FirmwareExtractStore{db: d} }

// DataDir 返回数据根目录（经 DB 回填）；空串 = 未装配。
func (s *FirmwareExtractStore) DataDir() string { return s.db.DataDir() }

// WithTx returns a tx-bound view for task-deletion transactions.
func (s *FirmwareExtractStore) WithTx(tx *sql.Tx) *FirmwareExtractStore {
	return &FirmwareExtractStore{db: s.db, tx: tx}
}

func (s *FirmwareExtractStore) q() interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	Exec(string, ...any) (sql.Result, error)
} {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

// SetFirmwareExtract upserts the extract registration for one firmware of a task
// (UNIQUE (task_id, firmware_sha256)). Returns the row and the previously
// registered path (empty on first registration).
func (s *FirmwareExtractStore) SetFirmwareExtract(taskID int64, sha, name, extractPath, note string) (*FirmwareExtract, string, error) {
	if taskID <= 0 {
		return nil, "", errors.New("task_id 必填")
	}
	sha = strings.ToLower(strings.TrimSpace(sha))
	extractPath = strings.Trim(strings.ReplaceAll(strings.TrimSpace(extractPath), "\\", "/"), "/")
	if extractPath == "" || strings.HasPrefix(extractPath, "/") || strings.Contains(extractPath, "..") {
		return nil, "", errors.New("extract_path 必须是任务目录内的相对路径")
	}
	var prev string
	if err := s.q().QueryRow(
		`SELECT COALESCE(extract_path,'') FROM firmware_extracts WHERE task_id=$1 AND firmware_sha256=$2`,
		taskID, sha).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	row := s.q().QueryRow(`
INSERT INTO firmware_extracts (task_id, firmware_name, firmware_sha256, extract_path, note)
VALUES ($1, NULLIF($2,''), NULLIF($3,''), $4, $5)
ON CONFLICT (task_id, firmware_sha256) DO UPDATE SET
    firmware_name = COALESCE(NULLIF(EXCLUDED.firmware_name,''), firmware_extracts.firmware_name),
    extract_path  = EXCLUDED.extract_path,
    note          = CASE WHEN EXCLUDED.note <> '' THEN EXCLUDED.note ELSE firmware_extracts.note END,
    updated_at    = now()
RETURNING `+firmwareExtractCols, taskID, name, sha, extractPath, note)
	f, err := scanFirmwareExtract(row)
	if err != nil {
		return nil, "", err
	}
	return f, prev, nil
}

// ListTaskExtracts lists all extract registrations of one task, newest first.
func (s *FirmwareExtractStore) ListTaskExtracts(taskID int64) ([]*FirmwareExtract, error) {
	rows, err := s.q().Query(
		`SELECT `+firmwareExtractCols+` FROM firmware_extracts WHERE task_id=$1 ORDER BY updated_at DESC, id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FirmwareExtract
	for rows.Next() {
		f, err := scanFirmwareExtract(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListAllExtracts 返回全部解包登记，按 sha256 去重（同一固件多任务解包只留最新一条）。
// 组件库页的固件筛选下拉用：sha256 → 固件文件名 + 备注。
func (s *FirmwareExtractStore) ListAllExtracts() ([]*FirmwareExtract, error) {
	rows, err := s.q().Query(`SELECT ` + firmwareExtractCols + ` FROM firmware_extracts
WHERE id IN (SELECT MAX(id) FROM firmware_extracts GROUP BY firmware_sha256)
ORDER BY updated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FirmwareExtract
	for rows.Next() {
		f, err := scanFirmwareExtract(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RootsForTask returns the validated extract roots of a task (relative, no
// leading /, no ".."): agent-supplied values are still treated as untrusted.
func (s *FirmwareExtractStore) RootsForTask(taskID int64) []string {
	extracts, err := s.ListTaskExtracts(taskID)
	if err != nil {
		return nil
	}
	var roots []string
	for _, f := range extracts {
		p := strings.TrimSpace(f.ExtractPath)
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			continue
		}
		roots = append(roots, p)
	}
	return roots
}

// Sha256sForTask returns the distinct registered firmware sha256s of a task.
func (s *FirmwareExtractStore) Sha256sForTask(taskID int64) []string {
	extracts, err := s.ListTaskExtracts(taskID)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range extracts {
		sha := strings.ToLower(strings.TrimSpace(f.Sha256))
		if sha == "" || seen[sha] {
			continue
		}
		seen[sha] = true
		out = append(out, sha)
	}
	return out
}

// DeleteByTask removes all extract registrations of a task (task deletion path).
func (s *FirmwareExtractStore) DeleteByTask(q interface {
	Exec(string, ...any) (sql.Result, error)
}, taskID int64) error {
	_, err := q.Exec(`DELETE FROM firmware_extracts WHERE task_id=$1`, taskID)
	return err
}
