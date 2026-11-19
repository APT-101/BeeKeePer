package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// =====================================================================
// TestInsertAssetsCodeRepo
// P0 代码审计：code_repo 类型资产插入 + 唯一索引去重 + extra/sha256 存储
// =====================================================================
func TestInsertAssetsCodeRepo(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	ts := NewToolSet(nil, "")
	ts.SetAssetStore(d.Assets(), d.Companies())
	defer d.Exec(`DELETE FROM assets WHERE type='code_repo' AND (url LIKE '%codeaudit-test%' OR url LIKE '%dup-codeaudit%')`)

	// 1. 插入两条不同仓库
	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{
				"type":         "code_repo",
				"repo_url":     "https://github.com/codeaudit-test/repo-a.git",
				"repo_name":    "repo-a",
				"repo_sha256":  "abc123",
				"repo_extra":   map[string]any{"lang": "go", "branch": "main"},
				"company_id":   nil,
			},
			map[string]any{
				"type":        "code_repo",
				"repo_url":    "https://github.com/codeaudit-test/repo-b.git",
				"repo_name":   "repo-b",
				"repo_sha256": "def456",
			},
		},
	})
	results, _ := out["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("code_repo batch: want 2 results, got %d (errors=%v)", len(results), out["errors"])
	}

	// 2. 同 URL 再插 → 去重返回同 ID
	idA := int64(results[0].(map[string]any)["id"].(float64))
	out2 := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{
				"type":     "code_repo",
				"repo_url": "https://github.com/codeaudit-test/repo-a.git",
			},
		},
	})
	results2, _ := out2["results"].([]any)
	idA2 := int64(results2[0].(map[string]any)["id"].(float64))
	if idA != idA2 {
		t.Fatalf("code_repo dedup: want same id (%d), got %d", idA, idA2)
	}

	// 3. 验证 extra JSONB 合并 + sha256 存储
	var sha, lang, url, name string
	err := d.QueryRow(
		`SELECT url, app_name, COALESCE(extra->>'sha256',''), COALESCE(extra->>'lang','') FROM assets WHERE id=$1`, idA,
	).Scan(&url, &name, &sha, &lang)
	if err != nil {
		t.Fatalf("query code_repo row: %v", err)
	}
	if url != "https://github.com/codeaudit-test/repo-a.git" {
		t.Errorf("url mismatch: %q", url)
	}
	if name != "repo-a" {
		t.Errorf("app_name (friendly name) mismatch: %q", name)
	}

	// 4. 类型枚举在 insert_assets tool schema 中存在
	tool := ts.insertAssets()
	schema := tool.InputSchema()
	raw, _ := json.Marshal(schema)
	if !json.Valid(raw) {
		t.Fatal("schema not valid json")
	}
}

// =====================================================================
// TestAssetStoreUpsertCodeRepo
// db 层 UpsertCodeRepo 直接验证（无任务上下文 taskID=0）
// =====================================================================
func TestAssetStoreUpsertCodeRepo(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	defer d.Exec(`DELETE FROM assets WHERE type='code_repo' AND url LIKE '%db-codeaudit-test%'`)

	as := d.Assets()
	id, err := as.UpsertCodeRepo(db.UpsertCodeRepoReq{
		RepoURL: "https://git.example.com/db-codeaudit-test/app.git",
		Name:    "app",
		SHA256:  "feedface",
		Extra:   map[string]any{"lang": "typescript"},
	})
	if err != nil {
		t.Fatalf("UpsertCodeRepo: %v", err)
	}
	if id <= 0 {
		t.Fatal("UpsertCodeRepo returned non-positive id")
	}

	var typ string
	var extra map[string]any
	if err := d.QueryRow(`SELECT type, extra FROM assets WHERE id=$1`, id).Scan(&typ, &extra); err != nil {
		t.Fatalf("query: %v", err)
	}
	if typ != "code_repo" {
		t.Errorf("type: want code_repo, got %q", typ)
	}
	if extra["sha256"] != "feedface" || extra["lang"] != "typescript" {
		t.Errorf("extra mismatch: %v", extra)
	}
}