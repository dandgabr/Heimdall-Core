package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/store"
)

// writeClientKeyConfig writes a minimal valid config in an isolated temp dir and
// returns its path.
func writeClientKeyConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfg
}

// TestClientKeyCreateListRevoke is the CLI acceptance test (ADR-SEC-06 §2):
// create prints the key once, list shows only metadata, revoke stops it. The
// plaintext must not appear in list output.
func TestClientKeyCreateListRevoke(t *testing.T) {
	cfg := writeClientKeyConfig(t)

	// create
	var createOut strings.Builder
	if code := executeToWithStdout(&createOut, []string{"client-key", "create", "--label", "editor", "--config", cfg}); code != 0 {
		t.Fatalf("create exit = %d, out = %s", code, createOut.String())
	}
	lines := strings.Split(strings.TrimSpace(createOut.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("create output = %q, want metadata line + key line", createOut.String())
	}
	if !strings.Contains(lines[0], "label=editor") {
		t.Fatalf("metadata line = %q", lines[0])
	}
	plaintext := strings.TrimSpace(lines[len(lines)-1])
	if !strings.HasPrefix(plaintext, "hmd_live_") {
		t.Fatalf("key line = %q, want hmd_live_ prefix", plaintext)
	}
	// The id is the first tab-separated field of the metadata line.
	id := strings.Split(lines[0], "\t")[0]

	// list: id/label/state only, never the key.
	var listOut strings.Builder
	if code := executeToWithStdout(&listOut, []string{"client-key", "list", "--config", cfg}); code != 0 {
		t.Fatalf("list exit = %d, out = %s", code, listOut.String())
	}
	if !strings.Contains(listOut.String(), id) || !strings.Contains(listOut.String(), "label=editor") {
		t.Fatalf("list output = %q", listOut.String())
	}
	if strings.Contains(listOut.String(), plaintext) {
		t.Fatal("list output leaked the plaintext key")
	}
	if !strings.Contains(listOut.String(), "active") {
		t.Fatalf("list output = %q, want active state", listOut.String())
	}

	// revoke
	var revokeOut strings.Builder
	if code := executeToWithStdout(&revokeOut, []string{"client-key", "revoke", id, "--config", cfg}); code != 0 {
		t.Fatalf("revoke exit = %d, out = %s", code, revokeOut.String())
	}

	// list after revoke shows the revoked state.
	var list2 strings.Builder
	if code := executeToWithStdout(&list2, []string{"client-key", "list", "--config", cfg}); code != 0 {
		t.Fatalf("list2 exit = %d", code)
	}
	if !strings.Contains(list2.String(), "revoked") {
		t.Fatalf("list2 output = %q, want revoked state", list2.String())
	}

	// revoking an unknown id fails.
	var missing strings.Builder
	if code := executeToWithStdout(&missing, []string{"client-key", "revoke", "does-not-exist", "--config", cfg}); code == 0 {
		t.Fatal("revoking an unknown id exited 0")
	}
	_ = missing
}

// TestClientKeyCreateRequiresNoArgsButLabelOptional covers the default label
// (empty is allowed) and the create/list round-trip with no label.
func TestClientKeyCreateDefaultLabel(t *testing.T) {
	cfg := writeClientKeyConfig(t)
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"client-key", "create", "--config", cfg}); code != 0 {
		t.Fatalf("create exit = %d", code)
	}
	var list strings.Builder
	if code := executeToWithStdout(&list, []string{"client-key", "list", "--config", cfg}); code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if !strings.Contains(list.String(), "label=") {
		t.Fatalf("list = %q", list.String())
	}
}

// TestClientKeyRevokeNeedsArg covers the cobra arg-count validation.
func TestClientKeyRevokeNeedsArg(t *testing.T) {
	cfg := writeClientKeyConfig(t)
	if code := executeToWithStdout(&strings.Builder{}, []string{"client-key", "revoke", "--config", cfg}); code == 0 {
		t.Fatal("revoke without an id exited 0")
	}
}

// TestClientKeyCommandsBadConfig covers the buildReadOnly-error branch of each
// subcommand: an unreadable explicit config fails closed.
func TestClientKeyCommandsBadConfig(t *testing.T) {
	bad := "/nonexistent/heimdall.toml"
	for _, args := range [][]string{
		{"client-key", "create", "--config", bad},
		{"client-key", "list", "--config", bad},
		{"client-key", "revoke", "id", "--config", bad},
	} {
		if code := executeToWithStdout(&strings.Builder{}, args); code == 0 {
			t.Errorf("%v exited 0 on a missing config", args)
		}
	}
}

// TestClientKeyWriteErrorBranches covers the output-write failure branches of
// create/list/revoke.
func TestClientKeyWriteErrorBranches(t *testing.T) {
	cfg := writeClientKeyConfig(t)
	// Seed one key so list has a row to write.
	if code := executeToWithStdout(&strings.Builder{}, []string{"client-key", "create", "--config", cfg}); code != 0 {
		t.Fatalf("seed create failed")
	}
	for _, args := range [][]string{
		{"client-key", "create", "--config", cfg},
		{"client-key", "list", "--config", cfg},
	} {
		if code := executeWith(&strings.Builder{}, failingWriter{}, args); code == 0 {
			t.Errorf("%v exited 0 when the output write failed", args)
		}
	}
}

// TestClientKeyStoreErrorBranches covers the store-error branches of create and
// list by dropping the client_keys table (the read/write then fails).
func TestClientKeyStoreErrorBranches(t *testing.T) {
	cfg := writeClientKeyConfig(t)
	// Ensure the vault exists first.
	if code := executeToWithStdout(&strings.Builder{}, []string{"client-key", "list", "--config", cfg}); code != 0 {
		t.Fatalf("initial list failed")
	}
	st, err := store.Open(readStorePath(cfg))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.Writer().Exec(`DROP TABLE client_keys`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	_ = st.Close()

	for _, args := range [][]string{
		{"client-key", "create", "--config", cfg},
		{"client-key", "list", "--config", cfg},
	} {
		if code := executeToWithStdout(&strings.Builder{}, args); code == 0 {
			t.Errorf("%v exited 0 without the client_keys table", args)
		}
	}
}
