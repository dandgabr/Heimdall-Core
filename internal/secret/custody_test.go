package secret

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

func TestDeriveKEKIsDeterministicAndSaltSensitive(t *testing.T) {
	saltA := bytes.Repeat([]byte{0x01}, SaltSize)
	saltB := bytes.Repeat([]byte{0x02}, SaltSize)

	kek1, err := DeriveKEK([]byte("passphrase"), saltA, testParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	kek2, err := DeriveKEK([]byte("passphrase"), saltA, testParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if !bytes.Equal(kek1, kek2) {
		t.Error("same material+salt must derive the same key")
	}

	// Same passphrase, different salt -> different key. This is acceptance
	// criterion 4: two vaults with the same passphrase do not share a key.
	kek3, err := DeriveKEK([]byte("passphrase"), saltB, testParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if bytes.Equal(kek1, kek3) {
		t.Error("different salts derived the same key; per-installation salt is not effective")
	}
	if len(kek1) != KEKSize {
		t.Errorf("KEK length = %d, want %d", len(kek1), KEKSize)
	}
}

func TestDeriveKEKRejectsEmptyMaterial(t *testing.T) {
	_, err := DeriveKEK(nil, bytes.Repeat([]byte{1}, SaltSize), testParams)
	if err == nil {
		t.Fatal("empty material accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigSecretMissing {
		t.Fatalf("err = %v, want config.secret_missing", err)
	}
}

func TestDeriveKEKRejectsBadParamsAndSalt(t *testing.T) {
	if _, err := DeriveKEK([]byte("x"), bytes.Repeat([]byte{1}, 4), testParams); err == nil {
		t.Error("short salt accepted")
	}
	badParams := testParams
	badParams.KeyLen = 16
	if _, err := DeriveKEK([]byte("x"), bytes.Repeat([]byte{1}, SaltSize), badParams); err == nil {
		t.Error("16-byte key length accepted")
	}
	zeroParams := KDFParams{}
	if _, err := DeriveKEK([]byte("x"), bytes.Repeat([]byte{1}, SaltSize), zeroParams); err == nil {
		t.Error("zeroed params accepted")
	}
}

func TestLoadOrCreateSaltPersistsPerVault(t *testing.T) {
	metaA := newMemMeta()
	metaB := newMemMeta()

	saltA, err := LoadOrCreateSalt(metaA)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt A: %v", err)
	}
	saltA2, err := LoadOrCreateSalt(metaA)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt A (again): %v", err)
	}
	if !bytes.Equal(saltA, saltA2) {
		t.Error("salt changed on the second load; it must be persisted")
	}

	saltB, err := LoadOrCreateSalt(metaB)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt B: %v", err)
	}
	if bytes.Equal(saltA, saltB) {
		t.Error("two vaults produced the same salt")
	}
	if len(saltA) != SaltSize {
		t.Errorf("salt length = %d, want %d", len(saltA), SaltSize)
	}
}

// TestLoadOrCreateSaltConcurrent is the P1-3 regression guard: N goroutines
// racing on a fresh vault must produce exactly ONE persisted salt, and every
// caller must read that same value. Before the atomic insert-if-absent, the
// losers derived a KEK from a salt that was then overwritten.
func TestLoadOrCreateSaltConcurrent(t *testing.T) {
	for run := 0; run < 20; run++ {
		meta := newMemMeta()
		const goroutines = 16

		results := make([][]byte, goroutines)
		errs := make([]error, goroutines)
		var wg sync.WaitGroup
		start := make(chan struct{})

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start // release together to maximise the race window
				results[idx], errs[idx] = LoadOrCreateSalt(meta)
			}(i)
		}
		close(start)
		wg.Wait()

		var first []byte
		for i, err := range errs {
			if err != nil {
				t.Fatalf("run %d goroutine %d: %v", run, i, err)
			}
			if len(results[i]) != SaltSize {
				t.Fatalf("run %d goroutine %d: salt length %d", run, i, len(results[i]))
			}
			if first == nil {
				first = results[i]
				continue
			}
			if !bytes.Equal(first, results[i]) {
				t.Fatalf("run %d: goroutines read different salts; TOCTOU not closed", run)
			}
		}

		// Exactly one row persisted, matching what every caller read.
		stored, found, err := meta.GetMeta(SaltMetaKey)
		if err != nil || !found {
			t.Fatalf("run %d: salt not persisted: %v", run, err)
		}
		decoded, _ := base64.RawStdEncoding.DecodeString(stored)
		if !bytes.Equal(decoded, first) {
			t.Fatalf("run %d: persisted salt differs from the value callers read", run)
		}
	}
}

// --- custody chain ---

func TestCustodyKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master-key")
	if err := os.WriteFile(keyPath, []byte("file-material\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	c := Custody{
		Salt:        bytes.Repeat([]byte{0x07}, SaltSize),
		Params:      testParams,
		KeyFilePath: keyPath,
		Env:         map[string]string{},
	}
	kek, source, err := c.ResolveKEK()
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if source != SourceKeyFile {
		t.Errorf("source = %q, want %q", source, SourceKeyFile)
	}
	if len(kek) != KEKSize {
		t.Errorf("kek length = %d", len(kek))
	}

	// The derived key must match a direct derivation from the trimmed file
	// content: the trailing newline is not part of the material.
	want, _ := DeriveKEK([]byte("file-material"), c.Salt, testParams)
	if !bytes.Equal(kek, want) {
		t.Error("key file derivation did not trim the trailing newline")
	}
}

func TestCustodyRejectsPermissiveKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master-key")
	if err := os.WriteFile(keyPath, []byte("material"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := Custody{
		Salt:        bytes.Repeat([]byte{0x07}, SaltSize),
		Params:      testParams,
		KeyFilePath: keyPath,
		Env:         map[string]string{},
	}
	_, _, err := c.ResolveKEK()
	if err == nil {
		t.Fatal("a 0644 key file was accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretKeyfileFailed {
		t.Fatalf("err = %v, want secret.keyfile_failed", err)
	}
}

// TestCustodySystemdCredentialWins proves layer order: the systemd credential is
// used even when a key file is also configured.
func TestCustodySystemdCredentialWins(t *testing.T) {
	credDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(credDir, "heimdall-master-key"), []byte("tpm-material"), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "master-key")
	if err := os.WriteFile(keyPath, []byte("file-material"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	c := Custody{
		Salt:           bytes.Repeat([]byte{0x07}, SaltSize),
		Params:         testParams,
		CredentialsDir: credDir,
		KeyFilePath:    keyPath,
		Env:            map[string]string{},
	}
	_, source, err := c.ResolveKEK()
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if source != SourceSystemdCredential {
		t.Errorf("source = %q, want %q (systemd layer must win)", source, SourceSystemdCredential)
	}
}

func TestCustodyEnvOverrideRequiresOptIn(t *testing.T) {
	base := Custody{
		Salt:   bytes.Repeat([]byte{0x07}, SaltSize),
		Params: testParams,
		Env:    map[string]string{"HEIMDALL_MASTER_KEY": "env-material"},
	}

	// Without opt-in the env layer is skipped and the chain fails closed.
	_, _, err := base.ResolveKEK()
	if err == nil {
		t.Fatal("env value used without AllowEnvOverride")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigSecretMissing {
		t.Fatalf("err = %v, want config.secret_missing", err)
	}

	// With opt-in it is used, and the warning never contains the value.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	withEnv := base
	withEnv.AllowEnvOverride = true
	withEnv.Logger = logger
	kek, source, err := withEnv.ResolveKEK()
	if err != nil {
		t.Fatalf("ResolveKEK with override: %v", err)
	}
	if source != SourceEnvOverride || len(kek) != KEKSize {
		t.Errorf("source = %q, kek len = %d", source, len(kek))
	}
	if strings.Contains(buf.String(), "env-material") {
		t.Fatalf("log leaked the master key: %s", buf.String())
	}
}

// TestCustodyMissingKeyFailsClosed is acceptance criterion 4 from the brief:
// no key anywhere -> config.secret_missing and New refuses.
func TestCustodyMissingKeyFailsClosed(t *testing.T) {
	_, _, err := Custody{
		Salt:   bytes.Repeat([]byte{0x07}, SaltSize),
		Params: testParams,
		Env:    map[string]string{},
	}.ResolveKEK()
	if err == nil {
		t.Fatal("ResolveKEK succeeded with no custody layer configured")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigSecretMissing {
		t.Fatalf("err = %v, want config.secret_missing", err)
	}

	// And the Store constructor propagates the refusal.
	if _, err := New(Options{
		Salt:    bytes.Repeat([]byte{0x07}, SaltSize),
		Params:  testParams,
		Custody: Custody{Env: map[string]string{}},
	}); err == nil {
		t.Fatal("New succeeded without a key")
	}
}

func TestNewRejectsBadSalt(t *testing.T) {
	_, err := New(Options{
		Salt:    bytes.Repeat([]byte{0x07}, 4),
		Params:  testParams,
		Custody: Custody{Env: map[string]string{}},
	})
	if err == nil {
		t.Fatal("New accepted a 4-byte salt")
	}
}

// --- recovery ---

func TestRecoveryRoundTrip(t *testing.T) {
	kek := testKEK(t)
	passphrase := []byte("correct horse battery staple")

	blob, err := WrapKEKForRecovery(kek, passphrase, testParams)
	if err != nil {
		t.Fatalf("WrapKEKForRecovery: %v", err)
	}
	if !strings.HasPrefix(blob, "enc:recovery:") {
		t.Fatalf("blob %q lacks the recovery prefix", blob)
	}

	recovered, err := UnwrapKEKFromRecovery(blob, passphrase, testParams)
	if err != nil {
		t.Fatalf("UnwrapKEKFromRecovery: %v", err)
	}
	if !bytes.Equal(recovered, kek) {
		t.Error("recovered KEK differs from the original")
	}
}

func TestRecoveryWrongPassphraseFails(t *testing.T) {
	kek := testKEK(t)
	blob, err := WrapKEKForRecovery(kek, []byte("right"), testParams)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := UnwrapKEKFromRecovery(blob, []byte("wrong"), testParams)
	if err == nil {
		t.Fatalf("wrong passphrase recovered a key: %x", got)
	}
	if got != nil {
		t.Error("failure must return nil, never partial key material")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretRecoveryFailed {
		t.Fatalf("err = %v, want secret.recovery_failed", err)
	}
}

func TestRecoveryRejectsMalformedAndEmpty(t *testing.T) {
	kek := testKEK(t)
	if _, err := WrapKEKForRecovery(kek, nil, testParams); err == nil {
		t.Error("empty recovery passphrase accepted")
	}
	if _, err := UnwrapKEKFromRecovery("garbage", []byte("x"), testParams); err == nil {
		t.Error("malformed blob accepted")
	}
	if _, err := UnwrapKEKFromRecovery("enc:recovery:a:b:c:d", []byte("x"), testParams); err == nil {
		t.Error("malformed base64 accepted")
	}
}

// --- Store wrapper ---

func TestStoreRotateTo(t *testing.T) {
	kek := testKEK(t)
	store, err := NewWithKEK(kek)
	if err != nil {
		t.Fatalf("NewWithKEK: %v", err)
	}

	sample, err := store.Seal([]byte("existing-record"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	newKEK, _ := DeriveKEK([]byte("next"), bytes.Repeat([]byte{0x44}, SaltSize), testParams)
	next, err := store.RotateTo(newKEK, sample)
	if err != nil {
		t.Fatalf("RotateTo: %v", err)
	}
	if next == nil {
		t.Fatal("RotateTo returned a nil store")
	}

	// The returned store must read the re-wrapped sample.
	if _, err := next.Open(rewrapForTest(t, kek, newKEK, sample)); err != nil {
		t.Fatalf("new store cannot read the rotated sample: %v", err)
	}
}

func TestStoreRotateToRejectsUnreadableSample(t *testing.T) {
	kek := testKEK(t)
	store, _ := NewWithKEK(kek)
	// A sample sealed under a DIFFERENT key: the current store cannot read it,
	// so rotation must refuse before mutating anything.
	otherKEK, _ := DeriveKEK([]byte("other"), bytes.Repeat([]byte{0x55}, SaltSize), testParams)
	foreign, _ := Seal(otherKEK, []byte("foreign"))

	newKEK, _ := DeriveKEK([]byte("next"), bytes.Repeat([]byte{0x44}, SaltSize), testParams)
	if _, err := store.RotateTo(newKEK, foreign); err == nil {
		t.Fatal("RotateTo accepted a sample it cannot decrypt")
	}
}

func TestStoreSealOpenRefusesWhenNil(t *testing.T) {
	var s *Store
	if _, err := s.Seal([]byte("x")); err == nil {
		t.Error("nil store sealed")
	}
	if _, err := s.Open("enc:v1:a:b:c"); err == nil {
		t.Error("nil store opened")
	}
}

// rewrapForTest re-wraps a sample so a test can read it with the new store.
func rewrapForTest(t *testing.T, oldKEK, newKEK []byte, sample string) string {
	t.Helper()
	out, err := Rewrap(oldKEK, newKEK, sample)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	return out
}

// memMeta is an in-memory MetaStore for KDF tests. It is mutex-guarded so the
// concurrency test exercises the real atomicity contract.
type memMeta struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemMeta() *memMeta { return &memMeta{m: map[string]string{}} }

func (m *memMeta) GetMeta(key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.m[key]
	return v, ok, nil
}

func (m *memMeta) SetMeta(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key] = value
	return nil
}

// SetMetaIfAbsent mirrors the SQLite ON CONFLICT DO NOTHING semantics under a
// lock, so the KDF concurrency test is meaningful.
func (m *memMeta) SetMetaIfAbsent(key, value string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.m[key]; exists {
		return false, nil
	}
	m.m[key] = value
	return true, nil
}
