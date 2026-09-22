package secret

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// errMeta is a MetaStore that can be told to fail on each operation.
type errMeta struct {
	getErr      error
	setErr      error
	ifAbsentErr error
	// present controls whether GetMeta reports a value.
	present bool
	value   string
	// inserted controls what SetMetaIfAbsent reports.
	inserted bool
}

func (m *errMeta) GetMeta(string) (string, bool, error) {
	if m.getErr != nil {
		return "", false, m.getErr
	}
	return m.value, m.present, nil
}

func (m *errMeta) SetMeta(string, string) error { return m.setErr }

func (m *errMeta) SetMetaIfAbsent(string, string) (bool, error) {
	if m.ifAbsentErr != nil {
		return false, m.ifAbsentErr
	}
	return m.inserted, nil
}

// TestReadSaltErrors covers readSalt's get-error and malformed-value branches.
func TestReadSaltErrors(t *testing.T) {
	// A get error surfaces as a typed KDF failure.
	if _, _, err := readSalt(&errMeta{getErr: errors.New("db down")}); err == nil {
		t.Fatal("get error swallowed")
	}
	// A malformed stored value is an error, not a regeneration.
	if _, _, err := readSalt(&errMeta{present: true, value: "not-base64!!"}); err == nil {
		t.Fatal("malformed salt accepted")
	}
	// A wrong-length value is an error.
	short := base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, _, err := readSalt(&errMeta{present: true, value: short}); err == nil {
		t.Fatal("short salt accepted")
	}
	// An absent row is not an error.
	if _, found, err := readSalt(&errMeta{}); err != nil || found {
		t.Fatalf("absent row = found=%v err=%v", found, err)
	}
	// An empty string is treated as absent.
	if _, found, err := readSalt(&errMeta{present: true, value: ""}); err != nil || found {
		t.Fatalf("empty value = found=%v err=%v", found, err)
	}
}

// TestLoadOrCreateSaltReadError covers the initial read error branch.
func TestLoadOrCreateSaltReadError(t *testing.T) {
	if _, err := LoadOrCreateSalt(&errMeta{getErr: errors.New("db down")}); err == nil {
		t.Fatal("read error swallowed")
	}
}

// TestLoadOrCreateSaltInsertError covers the SetMetaIfAbsent error branch.
func TestLoadOrCreateSaltInsertError(t *testing.T) {
	if _, err := LoadOrCreateSalt(&errMeta{ifAbsentErr: errors.New("disk full")}); err == nil {
		t.Fatal("insert error swallowed")
	}
}

// TestLoadOrCreateSaltLoserRereads covers the conflict path: another writer won,
// so the loser re-reads and returns the persisted value. The FIRST read reports
// the salt absent (this caller saw a fresh vault), SetMetaIfAbsent reports the
// conflict, and the SECOND read returns the winner's value.
func TestLoadOrCreateSaltLoserRereads(t *testing.T) {
	winner := bytes.Repeat([]byte{0xAB}, SaltSize)
	encoded := base64.RawStdEncoding.EncodeToString(winner)

	m := &sequencedMeta{reads: []readResult{
		{found: false},
		{found: true, value: encoded},
	}}
	salt, err := LoadOrCreateSalt(m)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	if !bytes.Equal(salt, winner) {
		t.Errorf("loser salt = %x, want the winner's", salt)
	}
}

// TestLoadOrCreateSaltLoserRereadError covers the loser's re-read error branch:
// this caller lost the insert race AND the subsequent read fails.
func TestLoadOrCreateSaltLoserRereadError(t *testing.T) {
	// First GetMeta (initial read) reports absent; SetMetaIfAbsent reports a
	// conflict; the second GetMeta errors.
	m := &sequencedMeta{reads: []readResult{{found: false}, {err: errors.New("db down")}}}
	if _, err := LoadOrCreateSalt(m); err == nil {
		t.Fatal("loser re-read error swallowed")
	}
}

// readResult is one canned GetMeta outcome.
type readResult struct {
	found bool
	value string
	err   error
}

// sequencedMeta returns canned results for successive GetMeta calls and reports
// a conflict (inserted=false) for SetMetaIfAbsent.
type sequencedMeta struct {
	reads []readResult
	n     int
}

func (m *sequencedMeta) GetMeta(string) (string, bool, error) {
	if m.n >= len(m.reads) {
		return "", false, nil
	}
	r := m.reads[m.n]
	m.n++
	return r.value, r.found, r.err
}
func (m *sequencedMeta) SetMeta(string, string) error                 { return nil }
func (m *sequencedMeta) SetMetaIfAbsent(string, string) (bool, error) { return false, nil }

// TestLoadOrCreateSaltVanished covers the "row disappeared" fail-closed branch.
func TestLoadOrCreateSaltVanished(t *testing.T) {
	// inserted=false then GetMeta reports absent: the vault is inconsistent.
	m := &errMeta{inserted: false, present: false}
	_, err := LoadOrCreateSalt(m)
	if err == nil {
		t.Fatal("vanished salt accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretKDFFailed {
		t.Fatalf("err = %v, want secret.kdf_failed", err)
	}
}

// TestDefaultKeyFilePathFallback covers the no-XDG branch.
func TestDefaultKeyFilePathFallback(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	got := DefaultKeyFilePath()
	if !strings.Contains(got, "master-key") {
		t.Errorf("DefaultKeyFilePath = %q", got)
	}
}

// TestResolveKEKSystemdDirMissingCredential covers the "dir set, credential
// absent" not-configured branch.
func TestResolveKEKSystemdDirMissingCredential(t *testing.T) {
	c := Custody{
		CredentialsDir: t.TempDir(), // empty dir
		Salt:           bytes.Repeat([]byte{1}, SaltSize),
		Params:         testParams,
		Env:            map[string]string{},
	}
	// With no other layer configured the chain must fail closed.
	if _, _, err := c.ResolveKEK(); err == nil {
		t.Fatal("empty credentials dir accepted")
	}
}

// TestCustodySystemdCredentialViaEnv covers the CREDENTIALS_DIRECTORY env
// branch (CredentialsDir empty).
func TestCustodySystemdCredentialViaEnv(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir+"/heimdall-master-key", "env-cred-material"); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := Custody{
		Salt:   bytes.Repeat([]byte{1}, SaltSize),
		Params: testParams,
		Env:    map[string]string{"CREDENTIALS_DIRECTORY": dir},
	}
	_, source, err := c.ResolveKEK()
	if err != nil {
		t.Fatalf("ResolveKEK via CREDENTIALS_DIRECTORY: %v", err)
	}
	if source != SourceSystemdCredential {
		t.Errorf("source = %q", source)
	}
}

// TestResolveKEKPropagatesLayerErrors covers the fatal-error branch of each
// configured layer: a layer that IS configured but fails must stop the chain,
// never fall through to a weaker one.
func TestResolveKEKPropagatesLayerErrors(t *testing.T) {
	// Layer 1: a systemd credential that is present but empty is fatal.
	credDir := t.TempDir()
	if err := writeFile(credDir+"/heimdall-master-key", ""); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := Custody{
		Salt:           bytes.Repeat([]byte{1}, SaltSize),
		Params:         testParams,
		CredentialsDir: credDir,
		Env:            map[string]string{},
	}
	if _, _, err := c.ResolveKEK(); err == nil {
		t.Error("empty systemd credential did not stop the chain")
	}

	// Layer 3: a permissive key file is fatal, not skipped.
	keyPath := t.TempDir() + "/key"
	if err := writeFileMode(keyPath, "material", 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2 := Custody{
		Salt:        bytes.Repeat([]byte{1}, SaltSize),
		Params:      testParams,
		KeyFilePath: keyPath,
		Env:         map[string]string{},
	}
	if _, _, err := c2.ResolveKEK(); err == nil {
		t.Error("permissive key file did not stop the chain")
	}
}

// TestResolveKEKInvalidParamsAndSalt covers the early validation branches.
func TestResolveKEKInvalidParamsAndSalt(t *testing.T) {
	if _, _, err := (Custody{Params: KDFParams{}}).ResolveKEK(); err == nil {
		t.Error("zeroed params accepted")
	}
	c := Custody{Salt: bytes.Repeat([]byte{1}, 4), Params: testParams}
	if _, _, err := c.ResolveKEK(); err == nil {
		t.Error("short salt accepted")
	}
}

// TestNewWithCustodyLoggerDefault covers the Logger-nil fallback inside New.
func TestNewWithCustodyLoggerDefault(t *testing.T) {
	c := Custody{
		Salt:             bytes.Repeat([]byte{1}, SaltSize),
		AllowEnvOverride: true,
		MasterKeyEnv:     "HEIMDALL_NEW_TEST_KEY",
		Env:              map[string]string{"HEIMDALL_NEW_TEST_KEY": "material"},
	}
	s, err := New(Options{Salt: c.Salt, Params: testParams, Custody: c})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil")
	}
}

// TestNewSaltLength covers NewSalt.
func TestNewSaltLength(t *testing.T) {
	s, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if len(s) != SaltSize {
		t.Errorf("salt length = %d, want %d", len(s), SaltSize)
	}
}

// TestNewGCDirectly covers newGCM's success and error branches.
func TestNewGCDirectly(t *testing.T) {
	if _, err := newGCM(bytes.Repeat([]byte{1}, KEKSize)); err != nil {
		t.Fatalf("newGCM with a valid key: %v", err)
	}
	// An invalid AES key length is rejected.
	if _, err := newGCM([]byte("short")); err == nil {
		t.Fatal("newGCM accepted an invalid key length")
	}
}

// writeFileMode writes content with an explicit mode, for the permissive-file
// test.
func writeFileMode(path, content string, mode os.FileMode) error {
	return os.WriteFile(path, []byte(content), mode)
}

// badBlock is a cipher.Block whose BlockSize is not 16, so cipher.NewGCM rejects
// it. It reaches the newGCM guard that a real AES block cannot.
type badBlock struct{}

func (badBlock) BlockSize() int          { return 32 }
func (badBlock) Encrypt(dst, src []byte) {}
func (badBlock) Decrypt(dst, src []byte) {}

// TestNewGCMBlockSizeGuard covers newGCM's cipher.NewGCM error branch via the
// newAESBlock seam.
func TestNewGCMBlockSizeGuard(t *testing.T) {
	old := newAESBlock
	newAESBlock = func([]byte) (cipher.Block, error) { return badBlock{}, nil }
	t.Cleanup(func() { newAESBlock = old })

	_, err := newGCM(bytes.Repeat([]byte{1}, KEKSize))
	if err == nil {
		t.Fatal("newGCM accepted a non-16-byte block")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretKDFFailed {
		t.Fatalf("err = %v, want secret.kdf_failed", err)
	}
	newAESBlock = old
}

// TestNewGCMInvalidKey covers newGCM's aes.NewCipher error branch.
func TestNewGCMInvalidKey(t *testing.T) {
	if _, err := newGCM([]byte("short")); err == nil {
		t.Fatal("newGCM accepted an invalid key length")
	}
}
