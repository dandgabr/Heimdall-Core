package secret

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Custody resolves the KEK for a vault, following the availability order fixed
// by ADR-SEC-01 §5. The chain is tried top-down and the FIRST layer that yields
// material wins; a layer that is simply not configured returns
// errNotConfigured and the chain falls through. A layer that IS configured but
// FAILS (bad passphrase, unreadable key file, TPM unseal error) is fatal: the
// chain stops rather than silently downgrading to a weaker layer, because a
// downgrade is exactly the failure mode fail-closed forbids.
//
// Order:
//  1. systemd credential ($CREDENTIALS_DIRECTORY/<name>) — TPM2-sealed, headless;
//  2. keyring (secret-tool) when a session bus is present;
//  3. key file 0600 + passphrase (Argon2id) — universal fallback;
//  4. env override (HEIMDALL_MASTER_KEY) — explicit, warned, deprecated.
type Custody struct {
	// Salt is the per-installation salt, resolved before the chain runs.
	Salt []byte
	// Params are the Argon2id cost parameters.
	Params KDFParams

	// CredentialsDir overrides $CREDENTIALS_DIRECTORY (tests, systemd unit).
	CredentialsDir string
	// CredentialName is the file name inside the credentials dir.
	CredentialName string

	// KeyringService / KeyringAccount address the keyring entry.
	KeyringService string
	KeyringAccount string
	// UseKeyring enables the keyring layer. It is false when there is no
	// session bus, which is the normal systemd --user headless case.
	UseKeyring bool

	// KeyFilePath is the 0600 file holding the passphrase. In headless mode the
	// passphrase comes from here (never from env by default).
	KeyFilePath string
	// PassphraseEnv names an env var holding the passphrase. Disabled by
	// default: an env passphrase is the "env override" layer, not the file one.
	PassphraseEnv string

	// Env is the environment snapshot (nil means os.Getenv).
	Env map[string]string
	// MasterKeyEnv is the explicit override variable name.
	MasterKeyEnv string
	// AllowEnvOverride gates the env layer. Even when a variable is set, the
	// layer is skipped unless the operator opted in.
	AllowEnvOverride bool

	// Logger receives the deprecation warning for the env layer (never the
	// value). Nil means slog.Default().
	Logger *slog.Logger
}

// KEKSource records which layer produced the key, for diagnostics and tests.
// It is safe to log: it names the layer, never the material.
type KEKSource string

const (
	// SourceSystemdCredential is the TPM2-sealed credential layer.
	SourceSystemdCredential KEKSource = "systemd_credential"
	// SourceKeyring is the desktop keyring layer.
	SourceKeyring KEKSource = "keyring"
	// SourceKeyFile is the 0600 key file + passphrase layer.
	SourceKeyFile KEKSource = "key_file"
	// SourceEnvOverride is the explicit, deprecated env layer.
	SourceEnvOverride KEKSource = "env_override"
)

// ResolveKEK walks the custody chain and returns the derived KEK and the layer
// that produced it. It never returns a zero KEK: if no layer yields material the
// result is config.secret_missing and the caller must refuse to start.
func (c Custody) ResolveKEK() ([]byte, KEKSource, error) {
	if err := c.Params.Validate(); err != nil {
		return nil, "", err
	}
	if len(c.Salt) != SaltSize {
		return nil, "", domain.New(domain.CodeSecretKDFFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "salt must be 16 bytes"}),
		)
	}

	// Layer 1 — systemd credential (TPM2-sealed plaintext key material).
	if material, ok, err := c.systemdCredential(); err != nil {
		return nil, "", err
	} else if ok {
		return c.derive(material, SourceSystemdCredential)
	}

	// Layer 2 — keyring.
	if c.UseKeyring {
		if material, ok, err := c.keyring(); err != nil {
			return nil, "", err
		} else if ok {
			return c.derive(material, SourceKeyring)
		}
	}

	// Layer 3 — 0600 key file (+ optional passphrase env, only if configured).
	if c.KeyFilePath != "" {
		if material, ok, err := c.keyFile(); err != nil {
			return nil, "", err
		} else if ok {
			return c.derive(material, SourceKeyFile)
		}
	}

	// Layer 4 — explicit env override. Reading an environment value cannot fail,
	// so this layer has no error path (unlike the file/keyring layers): it either
	// yields material or is not configured.
	if c.AllowEnvOverride {
		if material, ok := c.envOverride(); ok {
			return c.derive(material, SourceEnvOverride)
		}
	}

	// Nothing configured anywhere: refuse to start.
	return nil, "", domain.New(domain.CodeConfigSecretMissing,
		domain.WithHTTPStatus(500),
	)
}

// derive runs the KDF over the layer's material.
func (c Custody) derive(material []byte, source KEKSource) ([]byte, KEKSource, error) {
	kek, err := DeriveKEK(material, c.Salt, c.Params)
	if err != nil {
		return nil, "", err
	}
	return kek, source, nil
}

// systemdCredential reads the credential file systemd placed in
// $CREDENTIALS_DIRECTORY. systemd-creds has already unsealed it, so the bytes
// here are the raw material; the Argon2id pass still applies, which means a
// leaked credential file alone is not the key.
func (c Custody) systemdCredential() (material []byte, ok bool, err error) {
	dir := c.CredentialsDir
	if dir == "" {
		dir = c.env("CREDENTIALS_DIRECTORY")
	}
	if dir == "" {
		return nil, false, nil
	}
	name := c.CredentialName
	if name == "" {
		name = "heimdall-master-key"
	}
	path := filepath.Join(dir, name)
	raw, readErr := custodyFileOps.ReadFile(path)
	if readErr != nil {
		if custodyFileOps.IsNotExist(readErr) {
			// The dir exists but our credential is not there: not configured.
			return nil, false, nil
		}
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(readErr),
			domain.WithParams(map[string]string{"reason": "cannot read systemd credential"}),
		)
	}
	material = trimNewline(raw)
	if len(material) == 0 {
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "systemd credential is empty"}),
		)
	}
	return material, true, nil
}

// keyring reads the KEK material from the desktop keyring via secret-tool. The
// keyringLookPath and keyringLookup are seams over the secret-tool binary so a
// test can exercise every branch (helper missing, entry absent, entry present,
// helper error) without depending on the host's keyring. Production uses the
// real implementations.
var (
	keyringLookPath = exec.LookPath
	keyringLookup   = func(service, account string) ([]byte, error) {
		return exec.Command("secret-tool", "lookup",
			"service", service, "account", account).Output()
	}
)

// binary is invoked, not linked: there is no libsecret dependency, so the
// CGO_ENABLED=0 build is untouched.
func (c Custody) keyring() (material []byte, ok bool, err error) {
	if _, lookErr := keyringLookPath("secret-tool"); lookErr != nil {
		// No helper installed: not configured, move on.
		return nil, false, nil
	}
	service := c.KeyringService
	if service == "" {
		service = "heimdall"
	}
	account := c.KeyringAccount
	if account == "" {
		account = "master-key"
	}
	out, cmdErr := keyringLookup(service, account)
	if cmdErr != nil {
		var exitErr *exec.ExitError
		if errors.As(cmdErr, &exitErr) {
			// A non-zero exit from secret-tool means "no such entry" or a
			// locked collection; treat it as not configured rather than fatal,
			// so a headless host without a keyring falls through to the file.
			return nil, false, nil
		}
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(cmdErr),
			domain.WithParams(map[string]string{"reason": "secret-tool failed"}),
		)
	}
	material = trimNewline(out)
	if len(material) == 0 {
		return nil, false, nil
	}
	return material, true, nil
}

// custodyFS is the filesystem seam for the key-file and systemd-credential
// layers. Production uses the os implementations; a test injects failures to
// reach the stat/read error branches a healthy host will not produce.
type custodyFS struct {
	Stat       func(string) (os.FileInfo, error)
	ReadFile   func(string) ([]byte, error)
	IsNotExist func(error) bool
}

var defaultCustodyFS = custodyFS{
	Stat:       os.Stat,
	ReadFile:   os.ReadFile,
	IsNotExist: os.IsNotExist,
}

var custodyFileOps = defaultCustodyFS

// keyFile reads the passphrase from a 0600 file. The file holds the material
// that Argon2id turns into the KEK, so the file alone does not decrypt the
// vault. A file that exists but is group/world-readable is REFUSED (fail-closed)
// rather than repaired, matching the vault policy in internal/store.
func (c Custody) keyFile() (material []byte, ok bool, err error) {
	info, statErr := custodyFileOps.Stat(c.KeyFilePath)
	if statErr != nil {
		if custodyFileOps.IsNotExist(statErr) {
			return nil, false, nil
		}
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(statErr),
			domain.WithParams(map[string]string{"reason": "cannot stat key file"}),
		)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{
				"reason": "key file is too permissive; require 0600",
			}),
		)
	}
	raw, readErr := custodyFileOps.ReadFile(c.KeyFilePath)
	if readErr != nil {
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(readErr),
			domain.WithParams(map[string]string{"reason": "cannot read key file"}),
		)
	}
	material = trimNewline(raw)

	// An optional passphrase env supplies a second factor; the Argon2id input
	// is material||passphrase so neither half alone reproduces the KEK.
	if c.PassphraseEnv != "" {
		if pass := c.env(c.PassphraseEnv); pass != "" {
			material = append(material, []byte(pass)...)
		}
	}
	if len(material) == 0 {
		return nil, false, domain.New(domain.CodeSecretKeyfileFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "key file is empty"}),
		)
	}
	return material, true, nil
}

// envOverride is the explicit, deprecated layer. It is only consulted when the
// operator set AllowEnvOverride; the value then passes through Argon2id like any
// other material, so even this layer does not use the raw env value as a key.
func (c Custody) envOverride() (material []byte, ok bool) {
	name := c.MasterKeyEnv
	if name == "" {
		name = "HEIMDALL_MASTER_KEY"
	}
	value := c.env(name)
	if value == "" {
		return nil, false
	}
	c.logger().Warn("deprecated master key source in use; prefer TPM2, keyring or a 0600 key file",
		slog.String("var", name))
	return []byte(value), true
}

func (c Custody) env(name string) string {
	if c.Env != nil {
		return c.Env[name]
	}
	return os.Getenv(name)
}

func (c Custody) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// trimNewline strips a trailing newline (and optional CR) so a key written with
// a trailing "\n" is the same material as one without.
func trimNewline(b []byte) []byte {
	s := strings.TrimRight(string(b), "\r\n")
	return []byte(s)
}

// DefaultKeyFilePath is the conventional 0600 key-file location:
// $XDG_DATA_HOME/heimdall/master-key, falling back to
// ~/.local/share/heimdall/master-key. It sits next to the vault by default so a
// single data directory holds the database, the token and the key file.
func DefaultKeyFilePath() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "master-key"
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "heimdall", "master-key")
}
