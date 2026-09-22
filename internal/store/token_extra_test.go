package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteTokenFileMkdirError covers the directory-creation failure branch.
func TestWriteTokenFileMkdirError(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The parent "directory" is a file, so MkdirAll fails.
	if err := WriteTokenFile(filepath.Join(file, "token"), "t"); err == nil {
		t.Fatal("token file under a file path accepted")
	}
}

// TestWriteTokenFileTempError covers the CreateTemp failure: the parent exists
// as a regular file (MkdirAll is skipped for "." only), so use a path whose dir
// is a file. This is the same shape as above but exercises the temp branch when
// MkdirAll is skipped.
func TestWriteTokenFileBareNameUsesCwd(t *testing.T) {
	dir := t.TempDir()
	// A bare name uses dir "."; run it in a temp cwd so we do not litter.
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	if err := WriteTokenFile("management-token", "token-value"); err != nil {
		t.Fatalf("WriteTokenFile(bare): %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "management-token"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(body)) != "token-value" {
		t.Errorf("token file = %q", body)
	}
}

// TestEnsureManagementTokenHashSecondCall covers the already-present branch.
func TestEnsureManagementTokenHashSecondCall(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	if _, created, err := st.EnsureManagementTokenHash(); err != nil || !created {
		t.Fatalf("first = created=%v err=%v", created, err)
	}
	token, created, err := st.EnsureManagementTokenHash()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if created || token != "" {
		t.Errorf("second call = %q, %v; want empty, false", token, created)
	}
}

// TestRotateManagementTokenChangesHash covers rotate producing a different hash.
func TestRotateManagementTokenChangesHash(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	first, _, err := st.EnsureManagementTokenHash()
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	second, created, err := st.RotateManagementToken()
	if err != nil || !created {
		t.Fatalf("rotate = created=%v err=%v", created, err)
	}
	if first == second {
		t.Error("rotate returned the same token")
	}
	if !st.VerifyManagementToken(second) {
		t.Error("new token does not verify")
	}
	if st.VerifyManagementToken(first) {
		t.Error("old token still verifies")
	}
}

// TestMigrateLegacyTokenRemovesPlaintext covers migrateLegacyToken's success and
// idempotence.
func TestMigrateLegacyTokenRemovesPlaintext(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	if err := st.SetMeta(ManagementTokenKey, "legacy-plaintext"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := st.migrateLegacyToken(); err != nil {
		t.Fatalf("migrateLegacyToken: %v", err)
	}
	if _, found, _ := st.GetMeta(ManagementTokenKey); found {
		t.Error("legacy token survived")
	}
	// A second call on an absent row is a no-op.
	if err := st.migrateLegacyToken(); err != nil {
		t.Fatalf("second migrateLegacyToken: %v", err)
	}
}

// TestDefaultTokenFilePathFallback covers the no-XDG branch by clearing it.
func TestDefaultTokenFilePathFallback(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	got := DefaultTokenFilePath()
	if !strings.Contains(got, "management-token") {
		t.Errorf("DefaultTokenFilePath = %q", got)
	}
}

// TestGetMetaError covers GetMeta's error branch by dropping the meta table.
func TestGetMetaError(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	if _, err := st.write.Exec(`DROP TABLE meta`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, _, err := st.GetMeta("anything"); err == nil {
		t.Fatal("GetMeta succeeded without the meta table")
	}
}

// TestOpenRejectsNonRegularPath covers ensurePermissions' non-regular branch
// through the public Open.
func TestOpenRejectsNonRegularPath(t *testing.T) {
	base := t.TempDir()
	// A FIFO is neither a regular file nor a directory.
	fifo := filepath.Join(base, "fifo.db")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	if _, err := Open(fifo); err == nil {
		t.Fatal("FIFO accepted as a database")
	}
}
