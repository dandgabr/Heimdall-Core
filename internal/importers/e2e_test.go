package importers_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/importers"
	"github.com/dandgabr/heimdall-core/internal/secret"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// TestImportEndToEndWithRealVault wires the real SecretStore and CredentialStore
// so the full path is exercised: read a synthetic source, seal with a real KEK,
// persist to SQLite, and prove the plaintext is not in the file.
func TestImportEndToEndWithRealVault(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	src := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const token = "sk-live-E2E-SECRET-TOKEN-123"
	if err := os.WriteFile(src, []byte(`{"zai-coding-plan":{"type":"api","key":"`+token+`"}}`), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	dbPath := filepath.Join(dir, "heimdall.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	kek, err := secret.DeriveKEK([]byte("e2e-material"), salt,
		secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	sec, err := secret.NewWithKEK(kek)
	if err != nil {
		t.Fatalf("secret store: %v", err)
	}
	credStore := store.NewCredentialStore(st)

	im := &importers.Importer{
		Store:  credStore,
		Sealer: sec,
		Home:   home,
		Env:    map[string]string{},
	}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 1 || results[0].Provider != "z.ai" {
		t.Fatalf("results = %+v", results)
	}

	// The stored credential opens back to the token.
	cred, err := credStore.Get(context.Background(), results[0].CredentialID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	plaintext, err := sec.Open(string(cred.Sealed))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plaintext) != token {
		t.Errorf("decrypted = %q, want the imported token", plaintext)
	}

	// Idempotence with the real store.
	if _, err := im.ImportAll(context.Background()); err != nil {
		t.Fatalf("second ImportAll: %v", err)
	}
	if list, _ := credStore.List(context.Background()); len(list) != 1 {
		t.Errorf("second import duplicated: %d credentials", len(list))
	}

	// The plaintext must not appear in the database file or its sidecars.
	if _, err := st.Writer().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", p, err)
		}
		if bytes.Contains(raw, []byte(token)) {
			t.Fatalf("plaintext token found in %s", p)
		}
	}
	if strings.Contains(string(mustRead(t, dbPath)), token) {
		t.Fatal("token present in dump")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
