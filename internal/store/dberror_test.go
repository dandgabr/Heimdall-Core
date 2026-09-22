package store

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// closedStore returns an open store whose pools are already closed, so every
// subsequent DB call returns "database is closed". That is how the otherwise
// unreachable SQL-error branches become testable.
func closedStore(t *testing.T) *Store {
	t.Helper()
	st, _, _ := newTestVault(t, tempDB(t), "material")
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return st
}

// failingRand always fails, to exercise the token entropy branch.
type failingRand struct{}

func (failingRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func withFailingRand(t *testing.T, fn func()) {
	t.Helper()
	old := randReader
	randReader = failingRand{}
	t.Cleanup(func() { randReader = old })
	fn()
	randReader = old
}

func TestNewManagementTokenEntropyError(t *testing.T) {
	withFailingRand(t, func() {
		if _, err := newManagementToken(); err == nil {
			t.Fatal("newManagementToken succeeded without entropy")
		}
	})
}

// TestRotateManagementTokenEntropyError covers RotateManagementToken's
// newManagementToken error branch.
func TestRotateManagementTokenEntropyError(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	withFailingRand(t, func() {
		if _, _, err := st.RotateManagementToken(); err == nil {
			t.Fatal("RotateManagementToken succeeded without entropy")
		}
	})
}

// TestDBErrorBranches drives the SQL-error paths of the token/meta helpers by
// operating on a closed store.
func TestDBErrorBranches(t *testing.T) {
	st := closedStore(t)

	if _, _, err := st.GetMeta("k"); err == nil {
		t.Error("GetMeta on a closed store succeeded")
	}
	if err := st.SetMeta("k", "v"); err == nil {
		t.Error("SetMeta on a closed store succeeded")
	}
	if _, err := st.SetMetaIfAbsent("k", "v"); err == nil {
		t.Error("SetMetaIfAbsent on a closed store succeeded")
	}
	if _, _, err := st.EnsureManagementTokenHash(); err == nil {
		t.Error("EnsureManagementTokenHash on a closed store succeeded")
	}
	if _, err := st.HasManagementToken(); err == nil {
		t.Error("HasManagementToken on a closed store succeeded")
	}
	if err := st.migrateLegacyToken(); err == nil {
		t.Error("migrateLegacyToken on a closed store succeeded")
	}
	if _, err := st.schemaVersion(); err == nil {
		t.Error("schemaVersion on a closed store succeeded")
	}
	if err := st.migrateFrom(migrationsFS); err == nil {
		t.Error("migrateFrom on a closed store succeeded")
	}
}

// TestVerifyManagementTokenErrorsClosedStore covers the fail-closed result when
// the read fails.
func TestVerifyManagementTokenErrorsClosedStore(t *testing.T) {
	st := closedStore(t)
	if st.VerifyManagementToken("anything") {
		t.Error("verify succeeded on a closed store")
	}
}

// TestCloseIsIdempotentOnBothPools covers Close's error-join branches by closing
// twice.
func TestCloseIsIdempotentOnBothPools(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	if err := st.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// Second close must be safe. database/sql returns nil for an already-closed
	// pool, so this asserts the documented behaviour rather than tolerating any
	// outcome.
	if err := st.Close(); err != nil {
		t.Fatalf("second Close returned %v, want nil", err)
	}
}

// TestDefaultTokenFilePathNoHome covers the branch where UserHomeDir fails
// (HOME unset), so the bare "management-token" fallback is returned.
func TestDefaultTokenFilePathNoHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")
	got := DefaultTokenFilePath()
	if got != "management-token" {
		t.Errorf("DefaultTokenFilePath with no HOME = %q, want management-token", got)
	}
	// os.UserHomeDir reports an error when HOME is unset; confirm the premise.
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this environment resolves a home directory without HOME")
	}
}

// TestWriteTokenFileRealSuccess is a non-seam happy path, to guard against the
// seams masking a real-behaviour regression.
func TestWriteTokenFileRealSuccess(t *testing.T) {
	path := tempDB(t) + "-token"
	if err := WriteTokenFile(path, "real-token"); err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}
	body, err := readFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(body)) != "real-token" {
		t.Errorf("body = %q", body)
	}
}
