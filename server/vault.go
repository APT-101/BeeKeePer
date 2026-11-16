// M3 凭证保险库的 server 侧（docs §8.5）：
//   - AES-256-GCM 主密钥管理：密钥文件 dataDir/vault.key（0600），首访生成。
//     明文只出现在 REST 写/显式读与 agent get_credential 的瞬时结果里；
//   - REST：PUT/GET(列表)/GET{name}[?with_secret]/DELETE/GET{id}/access；
//   - agent 工具：list_credentials（元数据）、get_credential（任务上下文内取用，
//     解密返回并落取用审计 credential_access_log；防复述警告）。
package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// ---- AES-256-GCM 主密钥 ----

var vaultKeyOnce sync.Once
var vaultKeyVal []byte
var vaultKeyErr error

// vaultKey 返回 dataDir/vault.key 里的 32 字节主密钥，不存在则生成（0600）。
// 懒加载一次并缓存；dataDir 切换（测试/多实例共享同一 dataDir）需保持一致。
func (s *Server) vaultKey() ([]byte, error) {
	vaultKeyOnce.Do(func() {
		path := filepath.Join(s.m.dir, "vault.key")
		b, err := os.ReadFile(path)
		if err == nil && len(b) == 32 {
			vaultKeyVal = b
			return
		}
		k := make([]byte, 32)
		if _, rerr := io.ReadFull(rand.Reader, k); rerr != nil {
			vaultKeyErr = fmt.Errorf("vault key generate: %w", rerr)
			return
		}
		if werr := os.WriteFile(path, k, 0o600); werr != nil {
			vaultKeyErr = fmt.Errorf("vault key write: %w", werr)
			return
		}
		vaultKeyVal = k
	})
	return vaultKeyVal, vaultKeyErr
}

// encVaultSecret 加密明文 → nonce||ciphertext。
func encVaultSecret(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decVaultSecret 解密 nonce||ciphertext，密钥错误/数据损坏返回 error。
func decVaultSecret(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("vault: sealed too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt: %w", err)
	}
	return pt, nil
}

// ---- REST handlers ----

// PUT /api/vault/credentials — 明文一次性写入（服务端立即加密落库）。
func (s *Server) vaultPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Host      string `json:"host"`
		Username  string `json:"username"`
		Secret    string `json:"secret"`
		Notes     string `json:"notes"`
		CreatedBy string `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || in.Secret == "" {
		writeErr(w, 400, "name 与 secret 为必填")
		return
	}
	if in.Kind == "" {
		in.Kind = "other"
	}
	if !oneOf(in.Kind, "ssh", "login", "api_key", "token", "other") {
		writeErr(w, 400, "kind 必须是 ssh/login/api_key/token/other")
		return
	}
	key, err := s.vaultKey()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	sealed, err := encVaultSecret(key, []byte(in.Secret))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	id, err := s.m.pg.PutCredential(r.Context(), &db.Credential{
		Name: name, Kind: in.Kind, Host: in.Host, Username: in.Username,
		Secret: sealed, Notes: in.Notes, CreatedBy: in.CreatedBy,
	})
	if err != nil {
		log.Printf("[vault] put %s: %v", name, err)
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[vault] 凭据 %q(#%d) 写入（密文落库）", name, id)
	writeJSON(w, 200, map[string]any{"id": id, "name": name})
}

// GET /api/vault/credentials — 元数据列表（不含密文）。
func (s *Server) vaultList(w http.ResponseWriter, r *http.Request) {
	items, err := s.m.pg.ListCredentials(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

// GET /api/vault/credentials/{name} — 元数据；?with_secret=1 时显式返回明文。
func (s *Server) vaultGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.m.pg.GetCredential(r.Context(), r.PathValue("name"))
	if errors.Is(err, db.ErrCredentialNotFound) {
		writeErr(w, 404, "credential not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	withSecret := r.URL.Query().Get("with_secret") == "1"
	out := map[string]any{
		"id": c.ID, "name": c.Name, "kind": c.Kind,
		"host": c.Host, "username": c.Username,
		"notes": c.Notes, "created_by": c.CreatedBy,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
	}
	if withSecret {
		key, kerr := s.vaultKey()
		if kerr != nil {
			writeErr(w, 500, kerr.Error())
			return
		}
		pt, derr := decVaultSecret(key, c.Secret)
		if derr != nil {
			writeErr(w, 500, derr.Error())
			return
		}
		out["secret"] = string(pt)
	}
	writeJSON(w, 200, out)
}

// DELETE /api/vault/credentials/{id}
func (s *Server) vaultDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	if err := s.m.pg.DeleteCredential(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrCredentialNotFound) {
			writeErr(w, 404, "credential not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// GET /api/vault/credentials/{id}/access — 取用审计。
func (s *Server) vaultAccess(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 50)
	items, err := s.m.pg.ListCredentialAccess(r.Context(), id, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

// ---- agent 工具（orchestration 装配） ----

// toolListCredentials — 元数据清单（无密文），供 agent 了解可用的授权凭据。
func (s *Server) toolListCredentials() actool.CoreTool {
	return roTool("list_credentials",
		"列出保险库里可用的授权凭据（仅元数据：name/kind/host/username，绝不包含密文）。"+
			"凭据由授权方预先录入；任务需要认证/登录时据此选择合适凭据，再用 get_credential 取用。",
		objSchema(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			items, err := s.m.pg.ListCredentials(ctx)
			if err != nil {
				return actool.Errorf("list_credentials 失败：" + err.Error()), nil
			}
			type brief struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
				Host string `json:"host,omitempty"`
				User string `json:"username,omitempty"`
			}
			out := make([]brief, 0, len(items))
			for _, c := range items {
				out = append(out, brief{Name: c.Name, Kind: c.Kind, Host: c.Host, User: c.Username})
			}
			return actool.Text("保险库凭据（元数据）：" + jsonSafe(out)), nil
		})
}

// toolGetCredential — 任务上下文内取用凭据：解密返回明文 + 落取用审计。
// 仅限任务运行（RunInfo.TaskID>0）；chat/管理会话拒绝。
func (s *Server) toolGetCredential() actool.CoreTool {
	run := func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(in, &p); err != nil {
			return actool.Errorf("get_credential 参数解析失败: " + err.Error()), nil
		}
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			return actool.Errorf("get_credential: name 必填（list_credentials 查可用凭据名）"), nil
		}
		ri := agent.RunInfoFrom(ctx)
		if ri.TaskID <= 0 {
			return actool.Errorf("get_credential 仅限任务运行上下文中使用"), nil
		}
		c, err := s.m.pg.GetCredential(ctx, p.Name)
		if errors.Is(err, db.ErrCredentialNotFound) {
			return actool.Errorf("get_credential: 凭据 " + p.Name + " 不存在（可用 list_credentials 查看）"), nil
		}
		if err != nil {
			return actool.Errorf("get_credential 读取失败: " + err.Error()), nil
		}
		key, kerr := s.vaultKey()
		if kerr != nil {
			return actool.Errorf("get_credential 密钥不可用"), nil
		}
		pt, derr := decVaultSecret(key, c.Secret)
		if derr != nil {
			return actool.Errorf("get_credential 解密失败（密钥与写入时不一致？）"), nil
		}
		// 落取用审计（明文不进审计）。
		worker, toolUse := "", ""
		if tc != nil {
			worker, toolUse = tc.AgentID, tc.ToolUseID
		}
		if aerr := s.m.pg.LogCredentialAccess(ctx, c.ID, ri.TaskID, ri.IntentID, worker, toolUse); aerr != nil {
			log.Printf("[vault] audit log fail cred=%d: %v", c.ID, aerr)
		}
		kindHint := ""
		switch c.Kind {
		case "ssh":
			kindHint = "SSH 登录凭据"
		case "login":
			kindHint = "Web/服务登录凭据"
		case "api_key":
			kindHint = "API 密钥"
		case "token":
			kindHint = "Bearer/访问令牌"
		}
		userLine := ""
		if c.Username != "" {
			userLine = " 用户名/密钥名：" + c.Username
		}
		return actool.Text(fmt.Sprintf("凭据获取成功（%s%s，host=%s）：%s\n"+
			"【安全底线】这是授权凭据：直接用于目标认证（注入命令/认证头），"+
			"【禁止】在总结、事实记录(fact)、发现(finding)、消息或任何输出里复述凭据明文；"+
			"本次取用已记录审计。", kindHint, userLine, c.Host, string(pt))), nil
	}
	return actool.Build(actool.Spec{
		Name: "get_credential",
		Description: "按名取用保险库里的授权凭据（登录/SSH/API 密钥等），返回明文用于目标认证。仅在任务运行中可用。" +
			"取用即落审计；**严禁在任何输出里复述凭据明文**。凭据名先 list_credentials 查。",
		Schema: objSchema(map[string]any{"name": strParam("凭据名（list_credentials 可见）")}, "name"),
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: run,
	})
}

// jsonSafe 把结构转 JSON 字符串（工具结果用）。
func jsonSafe(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
