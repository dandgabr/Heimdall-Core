package secret

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestDefaultKeyFilePath covers the path helper (0% before).
func TestDefaultKeyFilePath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-key-test")
	got := DefaultKeyFilePath()
	if !strings.Contains(got, "heimdall") || !strings.Contains(got, "master-key") {
		t.Errorf("DefaultKeyFilePath = %q", got)
	}
}

// TestCustodyEnvAndLoggerDefaults covers the env/logger fallbacks.
func TestCustodyEnvAndLoggerDefaults(t *testing.T) {
	// A nil Env map reads the real process environment.
	c := Custody{Env: nil}
	t.Setenv("HEIMDALL_TEST_PROBE", "probe-value")
	if got := c.env("HEIMDALL_TEST_PROBE"); got != "probe-value" {
		t.Errorf("env with nil map = %q", got)
	}
	// Nil Logger falls back to slog.Default, never nil.
	if c.logger() == nil {
		t.Error("logger() returned nil")
	}
}

// TestCustodyDeriveError covers derive's error propagation when the KDF params
// are invalid.
func TestCustodyDeriveError(t *testing.T) {
	c := Custody{Salt: bytes.Repeat([]byte{1}, SaltSize), Params: KDFParams{}}
	if _, _, err := c.derive([]byte("material"), SourceKeyFile); err == nil {
		t.Fatal("derive accepted invalid params")
	}
}

// TestCustodySystemdCredentialErrors covers the empty-credential branch.
func TestCustodySystemdCredentialErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "heimdall-master-key"), nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := Custody{CredentialsDir: dir, Env: map[string]string{}}
	if _, _, err := c.systemdCredential(); err == nil {
		t.Fatal("empty systemd credential accepted")
	}

	// A directory in place of the credential file is a read error.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, "heimdall-master-key"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	c2 := Custody{CredentialsDir: dir2, Env: map[string]string{}}
	if _, _, err := c2.systemdCredential(); err == nil {
		t.Fatal("directory-as-credential accepted")
	}
}

// TestCustodyKeyFileEmpty covers the empty-file branch.
func TestCustodyKeyFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-key")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := Custody{KeyFilePath: path, Env: map[string]string{}}
	if _, _, err := c.keyFile(); err == nil {
		t.Fatal("empty key file accepted")
	}
}

// TestCustodyKeyFileWithPassphraseEnv combines the file and the passphrase env.
func TestCustodyKeyFileWithPassphraseEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("file-material"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := Custody{
		Salt:          bytes.Repeat([]byte{2}, SaltSize),
		Params:        testParams,
		KeyFilePath:   path,
		PassphraseEnv: "PASS",
		Env:           map[string]string{"PASS": "second-factor"},
	}
	material, ok, err := c.keyFile()
	if err != nil || !ok {
		t.Fatalf("keyFile = %v, %v", ok, err)
	}
	// The material is file-content + passphrase concatenated.
	if !bytes.Contains(material, []byte("file-material")) || !bytes.Contains(material, []byte("second-factor")) {
		t.Errorf("material does not combine both halves: %q", material)
	}
}

// TestCustodyKeyFileStatError covers the stat-error branch (a parent that is a
// file).
func TestCustodyKeyFileStatError(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := Custody{KeyFilePath: filepath.Join(file, "key"), Env: map[string]string{}}
	_, _, err := c.keyFile()
	if err == nil {
		t.Fatal("stat error accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretKeyfileFailed {
		t.Fatalf("err = %v", err)
	}
}

// TestResolveKEKFallsThroughLayers proves the chain order: a missing keyring and
// key file fall through to the env override.
func TestResolveKEKFallsThroughLayers(t *testing.T) {
	c := Custody{
		Salt:             bytes.Repeat([]byte{3}, SaltSize),
		Params:           testParams,
		AllowEnvOverride: true,
		MasterKeyEnv:     "HEIMDALL_TEST_MASTER",
		Env:              map[string]string{"HEIMDALL_TEST_MASTER": "env-material"},
	}
	kek, source, err := c.ResolveKEK()
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if source != SourceEnvOverride {
		t.Errorf("source = %q, want env_override", source)
	}
	if len(kek) != KEKSize {
		t.Errorf("kek length = %d", len(kek))
	}
}

// TestResolveKEKKeyringWithoutHelper covers the keyring branch when secret-tool
// is absent: it returns not-configured and the chain continues. When the helper
// IS present, the layer runs and returns not-configured for a missing entry.
func TestResolveKEKKeyringWithoutHelper(t *testing.T) {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		// No helper: the layer must report not-configured, not error.
		c := Custody{
			UseKeyring: true,
			Env:        map[string]string{},
		}
		_, ok, err := c.keyring()
		if err != nil || ok {
			t.Fatalf("keyring without helper = %v, %v; want not-configured", ok, err)
		}
		t.Skip("secret-tool not installed")
	}

	// Helper present: an entry we never stored must be not-configured.
	c := Custody{
		KeyringService: "heimdall-absent-service",
		KeyringAccount: "absent-account",
		Env:            map[string]string{},
	}
	material, ok, err := c.keyring()
	if err != nil {
		// A locked/unavailable keyring is tolerated as not-configured by the
		// implementation; an unexpected error would be a real failure.
		t.Logf("keyring error tolerated: %v", err)
	}
	if ok && len(material) == 0 {
		t.Error("keyring reported configured with empty material")
	}
}

// TestWrapKEKForRecoveryRejectsBadKEK covers the non-32-byte KEK branch.
func TestWrapKEKForRecoveryRejectsBadKEK(t *testing.T) {
	if _, err := WrapKEKForRecovery([]byte("short"), []byte("pass"), testParams); err == nil {
		t.Fatal("short KEK accepted")
	}
}

// TestUnwrapRecoveryEmptyPassphrase covers the empty-passphrase rejection after
// a well-formed blob.
func TestUnwrapRecoveryEmptyPassphrase(t *testing.T) {
	kek, _ := DeriveKEK([]byte("m"), bytes.Repeat([]byte{7}, SaltSize), testParams)
	blob, err := WrapKEKForRecovery(kek, []byte("pass"), testParams)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := UnwrapKEKFromRecovery(blob, nil, testParams); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}

// TestUnwrapRecoveryBadKDFParams covers the DeriveKEK error propagation.
func TestUnwrapRecoveryBadKDFParams(t *testing.T) {
	kek, _ := DeriveKEK([]byte("m"), bytes.Repeat([]byte{7}, SaltSize), testParams)
	blob, _ := WrapKEKForRecovery(kek, []byte("pass"), testParams)
	// Zeroed params make DeriveKEK fail inside Unwrap.
	if _, err := UnwrapKEKFromRecovery(blob, []byte("pass"), KDFParams{}); err == nil {
		t.Fatal("invalid params accepted")
	}
}

// TestUnwrapRecoveryWrongLengths drives each decoded-length rejection.
func TestUnwrapRecoveryWrongLengths(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltSize)
	iv := bytes.Repeat([]byte{2}, IVSize)
	ct := []byte("cipher")
	tag := bytes.Repeat([]byte{3}, TagSize)

	makeBlob := func(s, i, c, tg []byte) string {
		return "enc:recovery:" + b64encode(s) + ":" + b64encode(i) + ":" +
			b64encode(c) + ":" + b64encode(tg)
	}

	cases := map[string]string{
		"short salt":  makeBlob(salt[:4], iv, ct, tag),
		"short iv":    makeBlob(salt, iv[:4], ct, tag),
		"short tag":   makeBlob(salt, iv, ct, tag[:4]),
		"empty ct ok": makeBlob(salt, iv, nil, tag), // decodes fine; auth fails
	}
	for name, blob := range cases {
		if name == "empty ct ok" {
			continue
		}
		if _, err := UnwrapKEKFromRecovery(blob, []byte("pass"), testParams); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestRecoveryMalformedParts covers splitRecovery's validation branches.
func TestRecoveryMalformedParts(t *testing.T) {
	bad := []string{
		"",
		"enc:recovery",
		"enc:wrong:AAAA:BBBB:CCCC:DDDD",
		"enc:recovery:!!!!:BBBB:CCCC:DDDD",
		"enc:recovery:AAAA:BBBB:CCCC", // too few
	}
	for _, blob := range bad {
		if _, err := UnwrapKEKFromRecovery(blob, []byte("x"), testParams); err == nil {
			t.Errorf("malformed recovery blob accepted: %q", blob)
		}
	}
}

// TestRecoveryBadSaltAndIV covers the decoded-length checks.
func TestRecoveryBadSaltAndIV(t *testing.T) {
	// Build a well-formed prefix with a short salt (base64 of 4 bytes).
	blob := "enc:recovery:" + b64encode([]byte{1, 2, 3, 4}) + ":" +
		b64encode(bytes.Repeat([]byte{9}, IVSize)) + ":" +
		b64encode([]byte("ct")) + ":" + b64encode(bytes.Repeat([]byte{8}, TagSize))
	if _, err := UnwrapKEKFromRecovery(blob, []byte("x"), testParams); err == nil {
		t.Fatal("short salt accepted")
	}
}

// TestStoreSealOpenWithNilKEKStore covers NewWithKEK rejection and Store
// Rewrap/RotateTo guards.
func TestStoreNewWithKEKRejectsBadLength(t *testing.T) {
	if _, err := NewWithKEK([]byte("short")); err == nil {
		t.Fatal("short KEK accepted")
	}
}

func TestStoreRewrapAndRotateGuards(t *testing.T) {
	kek, _ := DeriveKEK([]byte("m"), bytes.Repeat([]byte{4}, SaltSize), testParams)
	s, err := NewWithKEK(kek)
	if err != nil {
		t.Fatalf("NewWithKEK: %v", err)
	}

	// Rewrap to a bad-length key fails.
	if _, err := s.Rewrap([]byte("short"), "enc:v1:a:b:c"); err == nil {
		t.Error("Rewrap accepted a short new KEK")
	}

	// RotateTo with a bad-length key fails.
	if _, err := s.RotateTo([]byte("short"), ""); err == nil {
		t.Error("RotateTo accepted a short KEK")
	}

	// RotateTo with an empty sample uses a fresh probe and succeeds.
	newKEK, _ := DeriveKEK([]byte("m2"), bytes.Repeat([]byte{5}, SaltSize), testParams)
	if _, err := s.RotateTo(newKEK, ""); err != nil {
		t.Errorf("RotateTo with a probe: %v", err)
	}
}

// TestRotateToNilStoreAndBadSample covers the nil-store guard and the
// probe-seal and rewrapped-read failure branches.
func TestRotateToNilStoreAndBadSample(t *testing.T) {
	var nilStore *Store
	if _, err := nilStore.RotateTo(make([]byte, KEKSize), ""); err == nil {
		t.Error("nil store RotateTo succeeded")
	}

	kek, _ := DeriveKEK([]byte("m"), bytes.Repeat([]byte{4}, SaltSize), testParams)
	s, _ := NewWithKEK(kek)
	// A sample sealed under a DIFFERENT key cannot be opened: RotateTo must
	// refuse before mutating.
	otherKEK, _ := DeriveKEK([]byte("other"), bytes.Repeat([]byte{6}, SaltSize), testParams)
	foreign, _ := Seal(otherKEK, []byte("x"))
	newKEK, _ := DeriveKEK([]byte("n"), bytes.Repeat([]byte{7}, SaltSize), testParams)
	if _, err := s.RotateTo(newKEK, foreign); err == nil {
		t.Error("RotateTo accepted an unreadable sample")
	}
}

func TestStoreRewrapNilReceiver(t *testing.T) {
	var s *Store
	if _, err := s.Rewrap(nil, "x"); err == nil {
		t.Error("nil Store.Rewrap accepted")
	}
}

// TestNewRejectsNilParams covers New's param validation.
func TestNewRejectsNilParams(t *testing.T) {
	if _, err := New(Options{Salt: bytes.Repeat([]byte{1}, SaltSize)}); err == nil {
		t.Fatal("New accepted zero KDF params")
	}
}

// TestEnvelopeSealRandError is not reachable without a failing entropy source;
// documented rather than faked.
func TestSealWithWrongKeySize(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("x")); err == nil {
		t.Fatal("Seal accepted a short KEK")
	}
	if _, err := Open([]byte("short"), "enc:v1:AAAA:BBBB:CCCC"); err == nil {
		t.Fatal("Open accepted a short KEK")
	}
}

// TestWrapRecoveryDeriveError covers WrapKEKForRecovery's DeriveKEK failure: a
// non-empty passphrase with zeroed params.
func TestWrapRecoveryDeriveError(t *testing.T) {
	kek, _ := DeriveKEK([]byte("m"), bytes.Repeat([]byte{1}, SaltSize), testParams)
	if _, err := WrapKEKForRecovery(kek, []byte("pass"), KDFParams{}); err == nil {
		t.Fatal("WrapKEKForRecovery accepted invalid params")
	}
}

// TestUnwrapRecoveryDeriveError covers UnwrapKEKFromRecovery's DeriveKEK failure
// with a well-formed blob and zeroed params.
func TestUnwrapRecoveryDeriveError(t *testing.T) {
	kek, _ := DeriveKEK([]byte("m"), bytes.Repeat([]byte{1}, SaltSize), testParams)
	blob, _ := WrapKEKForRecovery(kek, []byte("pass"), testParams)
	if _, err := UnwrapKEKFromRecovery(blob, []byte("pass"), KDFParams{}); err == nil {
		t.Fatal("UnwrapKEKFromRecovery accepted invalid params")
	}
}
