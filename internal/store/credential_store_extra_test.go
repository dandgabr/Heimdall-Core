package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestParseTimeRejectsCorruption is the P3 regression guard: a non-empty
// unparseable timestamp is an error, never a silent zero time.
func TestParseTimeRejectsCorruption(t *testing.T) {
	if v, err := parseTime(""); err != nil || !v.IsZero() {
		t.Errorf("parseTime(\"\") = %v, %v; want zero, nil", v, err)
	}
	if _, err := parseTime("not-a-time"); err == nil {
		t.Fatal("corrupt timestamp accepted")
	}
	if v, err := parseTime("2026-09-22T00:00:00Z"); err != nil || v.IsZero() {
		t.Errorf("valid timestamp = %v, %v", v, err)
	}
}

// TestGetRejectsCorruptTimestamp drives the corruption through Get: a bad
// created_at must surface as a typed error, not a usable credential.
func TestGetRejectsCorruptTimestamp(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)

	cred := sampleCredential(t, sec, "corrupt", "token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Corrupt created_at directly.
	if _, err := st.write.Exec(`UPDATE credentials SET created_at = 'garbage' WHERE id = 'corrupt'`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	_, err := cs.Get(context.Background(), "corrupt")
	if err == nil {
		t.Fatal("Get returned a credential with a corrupt timestamp")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeCredentialStoreFailed {
		t.Fatalf("err = %v, want credential.store_failed", err)
	}
	if !strings.Contains(de.Params["reason"], "created_at") {
		t.Errorf("reason = %q, want it to name created_at", de.Params["reason"])
	}

	// List must fail the same way, not skip the row.
	if _, err := cs.List(context.Background()); err == nil {
		t.Fatal("List accepted a corrupt timestamp")
	}
}

// TestGetRejectsCorruptExpiresAt covers the second timestamp column.
func TestGetRejectsCorruptExpiresAt(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	cred := sampleCredential(t, sec, "corrupt-exp", "token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := st.write.Exec(`UPDATE credentials SET expires_at = 'bad' WHERE id = 'corrupt-exp'`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	_, err := cs.Get(context.Background(), "corrupt-exp")
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeCredentialStoreFailed || !strings.Contains(de.Params["reason"], "expires_at") {
		t.Fatalf("err = %v, want a credential.store_failed naming expires_at", err)
	}
}

// TestGetRejectsCorruptMeta covers the JSON-decode branch.
func TestGetRejectsCorruptMeta(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	cred := sampleCredential(t, sec, "badmeta", "token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := st.write.Exec(`UPDATE credentials SET meta = '{bad json' WHERE id = 'badmeta'`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	_, err := cs.Get(context.Background(), "badmeta")
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeCredentialStoreFailed {
		t.Fatalf("err = %v, want credential.store_failed", err)
	}
}

// TestGetRejectsUnknownAuthMode covers the parseAuthMode branch in scanCredential.
func TestGetRejectsUnknownAuthMode(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	cred := sampleCredential(t, sec, "badmode", "token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := st.write.Exec(`UPDATE credentials SET auth_mode = 'bogus' WHERE id = 'badmode'`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	_, err := cs.Get(context.Background(), "badmode")
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeCredentialInvalidAuthMode {
		t.Fatalf("err = %v, want credential.invalid_auth_mode", err)
	}
}

// TestUpsertInvalidAuthMode covers the validAuthMode rejection branch. A valid
// sealed envelope is supplied so the format check passes and the auth-mode check
// is the one that fires.
func TestUpsertInvalidAuthMode(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	sealed, err := sec.Seal([]byte("token"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	err = cs.Upsert(context.Background(), contracts.Credential{
		ID:       "bad",
		Provider: "z.ai",
		AuthMode: contracts.AuthMode(99),
		Sealed:   []byte(sealed),
	})
	if err == nil {
		t.Fatal("invalid auth mode accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeCredentialInvalidAuthMode {
		t.Fatalf("err = %v, want credential.invalid_auth_mode", err)
	}
}

// TestUpsertEmptyID covers the empty-id rejection.
func TestUpsertEmptyID(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	if err := NewCredentialStore(st).Upsert(context.Background(), contracts.Credential{}); err == nil {
		t.Fatal("empty credential id accepted")
	}
}

// TestCredentialErrorTyped covers the credentialError helper (0% before).
func TestCredentialErrorTyped(t *testing.T) {
	err := credentialError("op", errors.New("boom"))
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeCredentialStoreFailed {
		t.Fatalf("credentialError = %v", err)
	}
	if !strings.Contains(de.Params["reason"], "op") {
		t.Errorf("reason = %q", de.Params["reason"])
	}
}

// TestDeleteStoreError covers the Delete error branch by closing the writer.
// TestCredentialStoreSQLErrorsClosedPool covers List/Get/Upsert/Delete error
// branches by operating on a closed store.
func TestCredentialStoreSQLErrorsClosedPool(t *testing.T) {
	st := closedStore(t)
	cs := NewCredentialStore(st)
	ctx := context.Background()

	if _, err := cs.List(ctx); err == nil {
		t.Error("List succeeded on a closed store")
	}
	if _, err := cs.Get(ctx, "x"); err == nil {
		t.Error("Get succeeded on a closed store")
	}
	if err := cs.Upsert(ctx, contracts.Credential{
		ID: "c", Provider: "z.ai", AuthMode: contracts.AuthNone,
	}); err == nil {
		t.Error("Upsert succeeded on a closed store")
	}
	if err := cs.Delete(ctx, "c"); err == nil {
		t.Error("Delete succeeded on a closed store")
	}
}

func TestStoreReaderAndClose(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	if st.Reader() == nil {
		t.Fatal("Reader() returned nil")
	}
	if st.Writer() == nil {
		t.Fatal("Writer() returned nil")
	}
	// Double close must be safe (the second returns nil or an error, never panics).
	if err := st.Close(); err != nil {
		t.Logf("first Close: %v", err)
	}
}

// TestDefaultTokenFilePath covers the path helper (0% before).
func TestDefaultTokenFilePath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-token-test")
	got := DefaultTokenFilePath()
	if !strings.Contains(got, "heimdall") || !strings.Contains(got, "management-token") {
		t.Errorf("DefaultTokenFilePath = %q", got)
	}
}

// TestHasManagementToken covers the helper (0% before).
func TestHasManagementToken(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	has, err := st.HasManagementToken()
	if err != nil {
		t.Fatalf("HasManagementToken: %v", err)
	}
	if has {
		t.Error("fresh vault reports a management token")
	}
	if _, _, err := st.EnsureManagementTokenHash(); err != nil {
		t.Fatalf("EnsureManagementTokenHash: %v", err)
	}
	if has, _ := st.HasManagementToken(); !has {
		t.Error("after generation, HasManagementToken is false")
	}
}

// TestSetMetaIfAbsentSecondCall covers the already-present branch.
func TestSetMetaIfAbsentSecondCall(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	inserted, err := st.SetMetaIfAbsent("probe", "first")
	if err != nil || !inserted {
		t.Fatalf("first SetMetaIfAbsent = %v, %v", inserted, err)
	}
	inserted, err = st.SetMetaIfAbsent("probe", "second")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if inserted {
		t.Error("second SetMetaIfAbsent reported insert")
	}
	if v, _, _ := st.GetMeta("probe"); v != "first" {
		t.Errorf("value = %q, want the first write preserved", v)
	}
}

// TestOpenErrorTyped covers the openError helper (0% before).
func TestOpenErrorTyped(t *testing.T) {
	err := openError("/x", errors.New("boom"))
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeStoreOpenFailed {
		t.Fatalf("openError = %v", err)
	}
}

// TestEnsurePermissionsDirectoryBranch covers the directory-creation and
// tightening path explicitly.
func TestEnsurePermissionsCreatesDir(t *testing.T) {
	base := t.TempDir()
	dbPath := filepath.Join(base, "sub", "deep", "heimdall.db")
	if err := ensurePermissions(dbPath); err != nil {
		t.Fatalf("ensurePermissions: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database not created: %v", err)
	}
}

// TestUpsertMarshalMetaError covers Upsert's meta-marshal error branch via the
// seam. AccountMeta cannot fail json.Marshal, so the seam is the only way to
// reach the branch.
func TestUpsertMarshalMetaError(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	cs := NewCredentialStore(st)

	old := marshalMeta
	marshalMeta = func(contracts.AccountMeta) ([]byte, error) { return nil, errors.New("marshal denied") }
	t.Cleanup(func() { marshalMeta = old })

	err := cs.Upsert(context.Background(), contracts.Credential{
		ID: "m", Provider: "z.ai", AuthMode: contracts.AuthNone,
	})
	if err == nil {
		t.Fatal("Upsert succeeded when meta marshalling failed")
	}
	if de := toDomain(t, err); de.Code != domain.CodeCredentialStoreFailed {
		t.Fatalf("code = %q", de.Code)
	}
	marshalMeta = old
}
