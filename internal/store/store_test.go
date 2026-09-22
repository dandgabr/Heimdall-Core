package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

func TestOpenCreatesSchemaAndMeta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	version, found, err := s.GetMeta(SchemaVersionKey)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if !found {
		t.Fatal("schema_version not recorded in meta")
	}
	if version == "" {
		t.Fatal("schema_version is empty")
	}

	// The meta table must be usable, proving 0001_init ran.
	if err := s.SetMeta("probe", "ok"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	got, found, err := s.GetMeta("probe")
	if err != nil || !found || got != "ok" {
		t.Fatalf("GetMeta probe = %q,%v,%v", got, found, err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	first, _, _ := s.GetMeta(SchemaVersionKey)
	if err := s.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	second, _, _ := s.GetMeta(SchemaVersionKey)
	if first != second {
		t.Errorf("schema_version changed on re-run: %q -> %q", first, second)
	}
}

func TestOpenCreatesFileAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != VaultFileMode {
		t.Errorf("created file mode = %#o, want %#o", mode, VaultFileMode)
	}
}

// TestOpenCreateCloseReopen is the P0-1 regression guard: the first boot used to
// let SQLite create the file under the umask (0644) and the second boot refused
// to start. Creating at 0600 makes the cycle succeed.
func TestOpenCreateCloseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")

	for boot := 1; boot <= 3; boot++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("boot %d: Open: %v", boot, err)
		}
		if got := s.Path(); got != path {
			t.Fatalf("boot %d: path = %q", boot, got)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("boot %d: Close: %v", boot, err)
		}
	}
}

func TestOpenRejectsWorldReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s.Close()

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err = Open(path)
	if err == nil {
		t.Fatal("expected refusal to open a group/world-readable database")
	}
	de, ok := err.(*domain.DomainError)
	if !ok {
		t.Fatalf("error type = %T, want *domain.DomainError", err)
	}
	if de.Code != domain.CodeStoreVaultPermissions {
		t.Fatalf("code = %q, want %q", de.Code, domain.CodeStoreVaultPermissions)
	}
}

// TestPermissiveVaultMessageIsActionable is the P2 regression guard: when the
// vault is 0644 the operator must see the path, the offending mode and the
// corrective command — not the bare store.open_failed code.
func TestPermissiveVaultMessageIsActionable(t *testing.T) {
	bundle := i18n.MustNew()

	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, openErr := Open(path)
	if openErr == nil {
		t.Fatal("expected refusal for a 0644 vault")
	}

	message := bundle.FormatDomainError(openErr, "en")
	for _, want := range []string{path, "0644", "0600", "chmod 600"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q missing %q", message, want)
		}
	}
	if strings.Contains(message, domain.CodeStoreOpenFailed) {
		t.Errorf("message still shows the generic code: %q", message)
	}

	// The fail-closed behaviour is unchanged: the vault was not repaired in
	// place, it was refused.
	if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm() != 0o644 {
		t.Errorf("store modified the vault mode to %#o instead of failing closed", info.Mode().Perm())
	}
}

func TestOpenRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.db")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected refusal when the database path is a directory")
	}
}

func TestManagementTokenHashedAndVerified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	token, created, err := s.EnsureManagementTokenHash()
	if err != nil {
		t.Fatalf("EnsureManagementTokenHash: %v", err)
	}
	if !created {
		t.Fatal("first call must create the token")
	}
	// 32 bytes hex-encoded = 64 chars = 256 bits.
	if len(token) != 2*ManagementTokenBytes {
		t.Errorf("token length = %d, want %d", len(token), 2*ManagementTokenBytes)
	}

	// The database must hold only the hash, never the recoverable secret.
	stored, found, err := s.GetMeta(ManagementTokenHashKey)
	if err != nil || !found {
		t.Fatalf("token hash not stored: %v", err)
	}
	if stored == token {
		t.Fatal("plaintext token persisted in the database")
	}
	if stored != HashManagementToken(token) {
		t.Errorf("stored hash = %q, want SHA-256 of the token", stored)
	}

	// Legacy plaintext row must be gone.
	if _, found, _ := s.GetMeta(ManagementTokenKey); found {
		t.Error("legacy plaintext token row still present")
	}

	// Second boot must not hand back the plaintext.
	again, created, err := s.EnsureManagementTokenHash()
	if err != nil {
		t.Fatalf("second EnsureManagementTokenHash: %v", err)
	}
	if created || again != "" {
		t.Error("second call must not return a token")
	}

	if !s.VerifyManagementToken(token) {
		t.Error("valid token rejected")
	}
	if s.VerifyManagementToken("wrong") {
		t.Error("invalid token accepted")
	}
	if s.VerifyManagementToken("") {
		t.Error("empty token accepted")
	}
}

func TestRotateManagementTokenInvalidatesPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	first, _, err := s.EnsureManagementTokenHash()
	if err != nil {
		t.Fatalf("EnsureManagementTokenHash: %v", err)
	}
	second, created, err := s.RotateManagementToken()
	if err != nil {
		t.Fatalf("RotateManagementToken: %v", err)
	}
	if !created {
		t.Fatal("rotate must create a new token")
	}
	if second == first {
		t.Fatal("rotate returned the same token")
	}
	if s.VerifyManagementToken(first) {
		t.Error("previous token still valid after rotation")
	}
	if !s.VerifyManagementToken(second) {
		t.Error("new token rejected after rotation")
	}
}

func TestMigrateLegacyPlaintextToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Simulate an early F0 database that stored the token in plaintext.
	if err := s.SetMeta(ManagementTokenKey, "deadbeef-plaintext"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if _, created, err := s.EnsureManagementTokenHash(); err != nil || !created {
		t.Fatalf("EnsureManagementTokenHash: %v created=%v", err, created)
	}
	if _, found, _ := s.GetMeta(ManagementTokenKey); found {
		t.Error("legacy plaintext token survived migration")
	}
}

func TestWriteTokenFileMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "management-token")

	if err := WriteTokenFile(path, "sometoken123"); err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != TokenFileMode {
		t.Errorf("token file mode = %#o, want %#o", mode, TokenFileMode)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "sometoken123\n" {
		t.Errorf("token file body = %q", body)
	}

	// A rewrite (rotation) must keep 0600.
	if err := WriteTokenFile(path, "rotated"); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat after rewrite: %v", err)
	}
	if mode := info.Mode().Perm(); mode != TokenFileMode {
		t.Errorf("token file mode after rotation = %#o, want %#o", mode, TokenFileMode)
	}
}

func TestWriterIsSingleConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if got := s.Writer().Stats().MaxOpenConnections; got != 1 {
		t.Errorf("writer MaxOpenConnections = %d, want 1", got)
	}
}
