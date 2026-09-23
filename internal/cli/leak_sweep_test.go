package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedSecrets creates an app whose config carries a passthrough API key seeded to
// a distinctive value, and a client-key/management-token on disk. It returns the
// config path, the seeded secret values, and everything a command might be
// expected NOT to print.
//
// The sweep below asserts these values never appear in the read-only command
// output. Each is a distinctive literal so a match is unambiguous: a careless
// implementation printing a config key, a provider key or the operator token
// would be caught.
const (
	sweepAPIKey      = "sk-live-SWEEP-API-KEY-abcdefghijklmnop"
	sweepProviderKey = "sk-SWEEP-PROVIDER-KEY-zyxwvutsrqponmlk"
)

func setupSweepCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("sweep-material-1234567890"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	db := filepath.Join(dir, "heimdall.db")
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + db + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"z.ai\"\nbase_url = \"https://x/v1\"\n" +
		"auth_header = \"bearer\"\nenabled = true\nmodels = [\"glm-4.6\"]\n" +
		"[passthrough]\nbase_url = \"https://x/v1\"\napi_key = \"" + sweepAPIKey + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("LC_ALL", "C")

	// Seed a provider credential (its sealed blob must never surface) and a
	// client key through the real vault, so `provider list`/`quota list` have
	// accounts and the client-key store has a row.
	writeSecretFile(t, db, cfg, dir)
	return cfg
}

// writeSecretFile uses the real app API to add a provider key and a client key,
// writing their plaintexts to temp files so the sweep can prove they are not
// echoed by the READ-ONLY commands. The add/create commands legitimately print
// their one-time reveal; those are excluded from the sweep.
func writeSecretFile(t *testing.T, db, cfg, dir string) {
	t.Helper()
	// Add an API key via stdin (the add command itself is not swept).
	withStdin(t, sweepProviderKey+"\n")
	if code := executeToWithStdout(&strings.Builder{}, []string{"provider", "add-key", "z.ai", "--label", "sweep", "--config", cfg}); code != 0 {
		t.Fatalf("seed provider key failed")
	}
	// Create a client key (its plaintext is revealed once by the create command;
	// only the READ-ONLY list is swept). We do not need the returned value for
	// the sweep — the invariant is "list never prints a key at all".
	if code := executeToWithStdout(&strings.Builder{}, []string{"client-key", "create", "--label", "sweep", "--config", cfg}); code != 0 {
		t.Fatalf("seed client key failed")
	}
	// The management token file holds the operator secret; the READ-ONLY
	// commands must never read or print it.
	if _, err := os.Stat(filepath.Join(dir, "management-token")); err != nil {
		t.Fatalf("management token file missing: %v", err)
	}
}

// TestNoCommandLeaksSecret is the F5.3 anti-leak sweep: the READ-ONLY commands
// config show, provider list, provider status, quota list and gate list must
// never print the seeded passthrough key or provider key. Every seed is a
// distinctive literal so a match is unambiguous.
func TestNoCommandLeaksSecret(t *testing.T) {
	cfg := setupSweepCLI(t)

	commands := [][]string{
		{"config", "show", "--config", cfg},
		{"config", "validate", "--config", cfg},
		{"config", "path", "--config", cfg},
		{"provider", "list", "--config", cfg},
		{"provider", "status", "--config", cfg},
		{"quota", "list", "--config", cfg},
		{"gate", "list", "--config", cfg},
		{"gate", "show", "logger", "--config", cfg},
		{"client-key", "list", "--config", cfg},
	}

	// The seeded secrets that must never appear in the swept output. The
	// management token is read from the 0600 file the daemon wrote on first
	// boot: a read-only command must never surface it.
	secrets := []string{sweepAPIKey, sweepProviderKey}
	if tok, err := os.ReadFile(filepath.Join(filepath.Dir(cfg), "management-token")); err == nil {
		if v := strings.TrimSpace(string(tok)); v != "" {
			secrets = append(secrets, v)
		}
	} else {
		t.Fatalf("read management token: %v", err)
	}

	// Also capture the raw vault bytes at the end and check the plaintext keys
	// never landed there unsealed.
	dbPath := readStorePath(cfg)

	for _, args := range commands {
		var out strings.Builder
		var errBuf strings.Builder
		executeWith(&errBuf, &out, args)
		for _, s := range secrets {
			if strings.Contains(out.String(), s) {
				t.Errorf("%v leaked a secret on stdout", args)
			}
			if strings.Contains(errBuf.String(), s) {
				t.Errorf("%v leaked a secret on stderr", args)
			}
		}
		// A redacted marker is expected on config show, proving the field was
		// enumerated AND hidden rather than simply absent.
		if len(args) >= 2 && args[0] == "config" && args[1] == "show" {
			if !strings.Contains(out.String(), "passthrough.api_key") {
				t.Errorf("config show did not enumerate passthrough.api_key")
			}
		}
	}

	// The vault file must not contain the plaintext provider key.
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if strings.Contains(string(raw), sweepProviderKey) {
		t.Fatal("the plaintext provider key is present in the vault file")
	}
}

// TestConfigShowRedactsEverySecretKey proves the config projection redacts
// passthrough.api_key regardless of the surrounding config.
func TestConfigShowRedactsEverySecretKey(t *testing.T) {
	cfg := setupSweepCLI(t)
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"config", "show", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if strings.Contains(out.String(), sweepAPIKey) {
		t.Fatal("config show leaked the passthrough key")
	}
	if !strings.Contains(out.String(), "passthrough.api_key\t[REDACTED]") {
		t.Fatalf("config show did not redact the passthrough key: %s", out.String())
	}
}
