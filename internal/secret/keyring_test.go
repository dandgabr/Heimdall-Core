package secret

import (
	"bytes"
	"errors"
	"os/exec"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// withKeyringSeams swaps the keyring seams for the duration of fn and restores
// them, so a test drives every branch deterministically.
func withKeyringSeams(t *testing.T, lookPath func(string) (string, error), lookup func(string, string) ([]byte, error), fn func()) {
	t.Helper()
	oldLook, oldLookup := keyringLookPath, keyringLookup
	keyringLookPath, keyringLookup = lookPath, lookup
	t.Cleanup(func() {
		keyringLookPath, keyringLookup = oldLook, oldLookup
	})
	fn()
	keyringLookPath, keyringLookup = oldLook, oldLookup
}

func TestKeyringHelperMissing(t *testing.T) {
	withKeyringSeams(t,
		func(string) (string, error) { return "", errors.New("not found") },
		nil,
		func() {
			material, ok, err := Custody{}.keyring()
			if err != nil || ok {
				t.Fatalf("missing helper = %v, %v; want not-configured", ok, err)
			}
			if material != nil {
				t.Errorf("material = %q, want nil", material)
			}
		})
}

func TestKeyringEntryPresent(t *testing.T) {
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(service, account string) ([]byte, error) {
			if service != "heimdall" || account != "master-key" {
				t.Errorf("defaults not applied: service=%q account=%q", service, account)
			}
			return []byte("keyring-material\n"), nil
		},
		func() {
			material, ok, err := Custody{}.keyring()
			if err != nil || !ok {
				t.Fatalf("entry present = %v, %v", ok, err)
			}
			if string(material) != "keyring-material" {
				t.Errorf("material = %q, want the trimmed value", material)
			}
		})
}

func TestKeyringCustomServiceAccount(t *testing.T) {
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(service, account string) ([]byte, error) {
			if service != "custom-svc" || account != "custom-acct" {
				t.Errorf("custom service/account ignored: %q %q", service, account)
			}
			return []byte("m"), nil
		},
		func() {
			c := Custody{KeyringService: "custom-svc", KeyringAccount: "custom-acct"}
			if _, ok, err := c.keyring(); err != nil || !ok {
				t.Fatalf("custom = %v, %v", ok, err)
			}
		})
}

func TestKeyringExitErrorIsNotConfigured(t *testing.T) {
	exitErr := &exec.ExitError{Stderr: []byte("no such entry")}
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(string, string) ([]byte, error) { return nil, exitErr },
		func() {
			_, ok, err := Custody{}.keyring()
			if err != nil || ok {
				t.Fatalf("exit error = %v, %v; want not-configured", ok, err)
			}
		})
}

func TestKeyringUnexpectedErrorIsFatal(t *testing.T) {
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(string, string) ([]byte, error) { return nil, errors.New("dbus exploded") },
		func() {
			_, _, err := Custody{}.keyring()
			if err == nil {
				t.Fatal("unexpected keyring error swallowed")
			}
			de, ok := err.(*domain.DomainError)
			if !ok || de.Code != domain.CodeSecretKeyfileFailed {
				t.Fatalf("err = %v, want secret.keyfile_failed", err)
			}
		})
}

func TestKeyringEmptyEntryIsNotConfigured(t *testing.T) {
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(string, string) ([]byte, error) { return []byte("\n"), nil },
		func() {
			_, ok, err := Custody{}.keyring()
			if err != nil || ok {
				t.Fatalf("empty entry = %v, %v; want not-configured", ok, err)
			}
		})
}

// TestResolveKEKUsesKeyring covers the chain reaching the keyring layer.
func TestResolveKEKUsesKeyring(t *testing.T) {
	withKeyringSeams(t,
		func(string) (string, error) { return "/usr/bin/secret-tool", nil },
		func(string, string) ([]byte, error) { return []byte("keyring-material"), nil },
		func() {
			c := Custody{
				UseKeyring: true,
				Salt:       bytes.Repeat([]byte{9}, SaltSize),
				Params:     testParams,
				Env:        map[string]string{},
			}
			kek, source, err := c.ResolveKEK()
			if err != nil {
				t.Fatalf("ResolveKEK: %v", err)
			}
			if source != SourceKeyring {
				t.Errorf("source = %q, want keyring", source)
			}
			if len(kek) != KEKSize {
				t.Errorf("kek length = %d", len(kek))
			}
		})
}
