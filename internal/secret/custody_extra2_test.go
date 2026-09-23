package secret

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeInfo is a minimal os.FileInfo for injected stat results.
type fakeInfo struct{ mode os.FileMode }

func (f fakeInfo) Name() string       { return "f" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// withCustodyFS swaps the custody FS seams for fn, restoring them after.
func withCustodyFS(t *testing.T, fs custodyFS, fn func()) {
	t.Helper()
	old := custodyFileOps
	custodyFileOps = fs
	t.Cleanup(func() { custodyFileOps = old })
	fn()
	custodyFileOps = old
}

// TestKeyFileStatError covers keyFile's non-ENOENT stat failure.
func TestKeyFileStatError(t *testing.T) {
	fs := defaultCustodyFS
	fs.Stat = func(string) (os.FileInfo, error) { return nil, errors.New("stat denied") }
	fs.IsNotExist = func(error) bool { return false }
	withCustodyFS(t, fs, func() {
		c := Custody{KeyFilePath: "/x/key", Env: map[string]string{}}
		if _, _, err := c.keyFile(); err == nil {
			t.Fatal("stat failure accepted")
		}
	})
}

// TestKeyFileReadError covers keyFile's read failure (stat succeeds, read
// fails).
func TestKeyFileReadError(t *testing.T) {
	fs := defaultCustodyFS
	fs.Stat = func(string) (os.FileInfo, error) { return fakeInfo{mode: 0o600}, nil }
	fs.ReadFile = func(string) ([]byte, error) { return nil, errors.New("read denied") }
	withCustodyFS(t, fs, func() {
		c := Custody{KeyFilePath: "/x/key", Env: map[string]string{}}
		_, _, err := c.keyFile()
		if err == nil {
			t.Fatal("read failure accepted")
		}
		if de := err.(*domain.DomainError); de.Code != domain.CodeSecretKeyfileFailed {
			t.Fatalf("code = %q", de.Code)
		}
	})
}

// TestSystemdCredentialReadError covers the systemd-credential read failure.
func TestSystemdCredentialReadError(t *testing.T) {
	fs := defaultCustodyFS
	fs.ReadFile = func(string) ([]byte, error) { return nil, errors.New("read denied") }
	fs.IsNotExist = func(error) bool { return false }
	withCustodyFS(t, fs, func() {
		c := Custody{CredentialsDir: "/cred", Env: map[string]string{}}
		if _, _, err := c.systemdCredential(); err == nil {
			t.Fatal("systemd credential read failure accepted")
		}
	})
}

// TestResolveKEKLayerErrorPropagation covers the "layer configured but failed"
// fatal branch for the keyring and env layers (each returns an error that must
// stop the chain rather than fall through).
func TestResolveKEKLayerErrorPropagation(t *testing.T) {
	// Keyring configured and returning a fatal (non-ExitError) failure.
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(string, string) ([]byte, error) { return nil, errors.New("dbus down") },
		func() {
			c := Custody{
				UseKeyring: true,
				Salt:       bytes.Repeat([]byte{1}, SaltSize),
				Params:     testParams,
				Env:        map[string]string{},
			}
			if _, _, err := c.ResolveKEK(); err == nil {
				t.Fatal("fatal keyring error did not stop the chain")
			}
		})
}

// TestDefaultKeyFilePathNoHome covers the bare "master-key" fallback.
func TestDefaultKeyFilePathNoHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")
	if got := DefaultKeyFilePath(); got != "master-key" {
		t.Errorf("DefaultKeyFilePath with no HOME = %q, want master-key", got)
	}
}

// TestEnvOverrideEmptyValue covers the not-configured branch (empty value).
func TestEnvOverrideEmptyValue(t *testing.T) {
	c := Custody{MasterKeyEnv: "EMPTY_KEY", AllowEnvOverride: true, Env: map[string]string{"EMPTY_KEY": ""}}
	if material, ok := c.envOverride(); ok || material != nil {
		t.Fatalf("empty env value = %v, %v; want not-configured", material, ok)
	}
}

// TestEnvOverrideDefaultName covers the default MasterKeyEnv name branch.
func TestEnvOverrideDefaultName(t *testing.T) {
	c := Custody{AllowEnvOverride: true, Env: map[string]string{"HEIMDALL_MASTER_KEY": "val"}}
	material, ok := c.envOverride()
	if !ok || string(material) != "val" {
		t.Fatalf("default env name = %q, %v", material, ok)
	}
}

// TestResolveKEKRingLayerFatalError is covered elsewhere; this asserts the
// keyFile-permissive branch (a mode with group/world bits) explicitly, which the
// injected FS makes deterministic.
func TestKeyFilePermissiveMode(t *testing.T) {
	fs := defaultCustodyFS
	fs.Stat = func(string) (os.FileInfo, error) { return fakeInfo{mode: 0o644}, nil }
	withCustodyFS(t, fs, func() {
		c := Custody{KeyFilePath: "/x/key", Env: map[string]string{}}
		_, _, err := c.keyFile()
		if err == nil {
			t.Fatal("0644 key file accepted")
		}
		if de := err.(*domain.DomainError); de.Code != domain.CodeSecretKeyfileFailed {
			t.Fatalf("code = %q", de.Code)
		}
	})
}

// TestKeyFileMissing covers the not-configured (ENOENT) branch.
func TestKeyFileMissing(t *testing.T) {
	fs := defaultCustodyFS
	fs.Stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	fs.IsNotExist = func(error) bool { return true }
	withCustodyFS(t, fs, func() {
		c := Custody{KeyFilePath: "/x/key", Env: map[string]string{}}
		material, ok, err := c.keyFile()
		if err != nil || ok || material != nil {
			t.Fatalf("missing key file = %v, %v, %v; want not-configured", material, ok, err)
		}
	})
}

// TestDefaultKeyFilePathForIsHermetic is the F5-1 regression guard: resolving
// the key path from an INJECTED environment must never consult the process
// environment (or the host's real home), so a test that injects an isolated
// env cannot see the operator's real ~/.local/share/heimdall/master-key.
func TestDefaultKeyFilePathForIsHermetic(t *testing.T) {
	// The process environment points somewhere with a marker.
	t.Setenv("XDG_DATA_HOME", "/host/xdg")
	t.Setenv("HOME", "/host/home")

	// An injected env with its own XDG_DATA_HOME wins over the process env.
	if got := DefaultKeyFilePathFor(map[string]string{"XDG_DATA_HOME": "/injected/xdg"}); got != "/injected/xdg/heimdall/master-key" {
		t.Errorf("injected XDG_DATA_HOME = %q", got)
	}
	// An injected env with only HOME derives from that home, NOT the process one.
	if got := DefaultKeyFilePathFor(map[string]string{"HOME": "/injected/home"}); got != "/injected/home/.local/share/heimdall/master-key" {
		t.Errorf("injected HOME = %q", got)
	}
	// An EMPTY (non-nil) env means "no variables": it must not fall back to the
	// process environment, so it yields the bare fallback, never the host path.
	if got := DefaultKeyFilePathFor(map[string]string{}); got != "master-key" {
		t.Errorf("empty injected env = %q, want master-key (hermetic)", got)
	}
}
