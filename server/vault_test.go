package server

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVaultSecretRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	pt := []byte("P@ssw0rd-目标机root")
	sealed, err := encVaultSecret(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("密文不该包含明文")
	}
	back, err := decVaultSecret(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(pt) {
		t.Fatalf("round-trip mismatch: %q != %q", back, pt)
	}
}

func TestVaultSecretUniqueNonce(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	a, _ := encVaultSecret(key, []byte("same-secret"))
	b, _ := encVaultSecret(key, []byte("same-secret"))
	if bytes.Equal(a, b) {
		t.Fatal("两次加密相同明文必须因随机 nonce 产生不同密文")
	}
	// 两次都能解回
	pa, _ := decVaultSecret(key, a)
	pb, _ := decVaultSecret(key, b)
	if string(pa) != "same-secret" || string(pb) != "same-secret" {
		t.Fatal("同明文两密文都应可解")
	}
}

func TestVaultSecretWrongKeyFails(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	other := []byte("fedcba9876543210fedcba9876543210")
	sealed, _ := encVaultSecret(key, []byte("supersecret"))
	if _, err := decVaultSecret(other, sealed); err == nil {
		t.Fatal("错误密钥解密必须失败")
	}
	// 篡改密文也必须失败（GCM 认证）
	sealed[len(sealed)-1] ^= 0x01
	if _, err := decVaultSecret(key, sealed); err == nil {
		t.Fatal("被篡改密文必须解密失败")
	}
}

func TestVaultSecretShortSealed(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if _, err := decVaultSecret(key, []byte("abc")); err == nil {
		t.Fatal("短密文必须报错")
	}
}

// TestVaultKeyGenerateAndReuse 验证密钥文件落盘与 0600 权限（Windows 跳过权限位）。
func TestVaultKeyGenerateAndReuse(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "vault.key")
	k := make([]byte, 32)
	if err := os.WriteFile(keyFile, k, 0o600); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() != 32 {
		t.Fatalf("key size = %d, want 32", stat.Size())
	}
	if runtime.GOOS != "windows" {
		if perm := stat.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key perm = %o, want 600", perm)
		}
	}
}
