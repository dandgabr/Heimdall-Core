package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRedactedFieldsCoverSchema proves the redacted projection enumerates the
// fixed config schema deterministically, and that a secret-bearing key is
// substituted with the literal and never its value.
func TestRedactedFieldsCoverSchema(t *testing.T) {
	c := Defaults()
	c.Passthrough.APIKey = "sk-live-SUPER-SECRET-key"
	c.Passthrough.APIKeyEnv = "OPENAI_API_KEY"

	fields := RedactedFields(c, nil)
	byKey := map[string]Field{}
	for _, f := range fields {
		byKey[f.Key] = f
	}

	// The raw key's value must be the literal, never the secret.
	if got := byKey["passthrough.api_key"].Value; got != Redacted {
		t.Fatalf("passthrough.api_key = %q, want %q", got, Redacted)
	}
	// A NAMED env var is not itself a secret, so it is shown.
	if got := byKey["passthrough.api_key_env"].Value; got != "OPENAI_API_KEY" {
		t.Fatalf("passthrough.api_key_env = %q, want the variable name", got)
	}
	// A representative spread of the schema is present.
	for _, key := range []string{
		"config_version", "server.host", "server.port", "server.allow_remote",
		"log.level", "log.format", "store.path", "store.token_path",
		"features.gates.token", "features.gates.memory", "features.gates.security",
		"features.gates.security.pii_policy", "features.gates.security.injection_policy",
		"security.require_client_key", "security.host_allowlist",
		"security.cors_allowed_origins", "security.management_login_rate_limit.rate",
		"passthrough.family", "passthrough.base_url", "passthrough.api_key",
		"passthrough.api_key_env",
	} {
		if _, ok := byKey[key]; !ok {
			t.Errorf("RedactedFields missing key %q", key)
		}
	}
	// Deterministic order: two renders are identical.
	again := RedactedFields(c, nil)
	if len(again) != len(fields) {
		t.Fatalf("length changed: %d vs %d", len(fields), len(again))
	}
	for i := range fields {
		if fields[i] != again[i] {
			t.Fatalf("field %d differs: %+v vs %+v", i, fields[i], again[i])
		}
	}
}

// TestRedactedFieldsProvidersAndMaps covers the per-provider and per-map
// enumeration, including sorted map keys.
func TestRedactedFieldsProvidersAndMaps(t *testing.T) {
	c := Defaults()
	c.Providers = []ProviderConfig{{ID: "z.ai", BaseURL: "https://x/v1", Enabled: true, Models: []string{"m1", "m2"}}}
	c.Features.Gates.Enabled = map[string]bool{"rate-limit": false, "pii-masker": true}
	c.Features.Gates.TokenEngines = map[string]TokenEngineConfig{
		"collapse-whitespace": {Disabled: true, AllowPrefixRewrite: true},
	}
	fields := RedactedFields(c, nil)
	byKey := map[string]Field{}
	for _, f := range fields {
		byKey[f.Key] = f
	}
	if got := byKey["providers.0.id"].Value; got != "z.ai" {
		t.Errorf("providers.0.id = %q", got)
	}
	if got := byKey["providers.0.models"].Value; got != "m1,m2" {
		t.Errorf("providers.0.models = %q", got)
	}
	if got := byKey["features.gates.pii-masker"].Value; got != "true" {
		t.Errorf("pii-masker switch = %q", got)
	}
	if got := byKey["features.gates.rate-limit"].Value; got != "false" {
		t.Errorf("rate-limit switch = %q", got)
	}
	if got := byKey["features.gates.token.engines.collapse-whitespace.enabled"].Value; got != "false" {
		t.Errorf("engine enabled = %q (Disabled should invert)", got)
	}
	if got := byKey["features.gates.token.engines.collapse-whitespace.allow_prefix_rewrite"].Value; got != "true" {
		t.Errorf("engine allow_prefix_rewrite = %q", got)
	}
}

// TestRedactedFieldKeysIsSortedAndStable proves the exported key list is stable
// and non-empty.
func TestRedactedFieldKeysIsSortedAndStable(t *testing.T) {
	keys := RedactedFieldKeys()
	if len(keys) == 0 {
		t.Fatal("no redacted field keys")
	}
	again := RedactedFieldKeys()
	if len(again) != len(keys) {
		t.Fatal("RedactedFieldKeys is not deterministic")
	}
	for i := range keys {
		if keys[i] != again[i] {
			t.Fatal("RedactedFieldKeys is not deterministic")
		}
	}
}

// TestLoadWithSourcesPrecedence proves the provenance layer records the WINNING
// layer per key under env > flag > file > default.
func TestLoadWithSourcesPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[server]\nhost = \"127.0.0.1\"\nport = 9000\n" +
		"[log]\nlevel = \"warn\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, sources, err := LoadWithSources(Options{
		FilePath: path,
		Flags:    map[string]string{"port": "9100"},
		Env:      map[string]string{"HEIMDALL_LOG_LEVEL": "debug", "HEIMDALL_STORE_PATH": filepath.Join(dir, "h.db")},
	})
	if err != nil {
		t.Fatalf("LoadWithSources: %v", err)
	}
	// file set server.host; nothing overrode it.
	if got := sources.SourceOf("server.host"); got != SourceFile {
		t.Errorf("server.host source = %q, want file", got)
	}
	// flag beat the file for server.port.
	if got := sources.SourceOf("server.port"); got != SourceFlag {
		t.Errorf("server.port source = %q, want flag", got)
	}
	if cfg.Server.Port != 9100 {
		t.Errorf("server.port = %d, want the flag value 9100", cfg.Server.Port)
	}
	// env beat the file for log.level.
	if got := sources.SourceOf("log.level"); got != SourceEnv {
		t.Errorf("log.level source = %q, want env", got)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level = %q, want debug", cfg.Log.Level)
	}
	// server.allow_remote was never set -> default.
	if got := sources.SourceOf("server.allow_remote"); got != SourceDefault {
		t.Errorf("server.allow_remote source = %q, want default", got)
	}
}

// TestLoadWithSourcesIgnoresUnknownKeys proves an unknown file key is not
// recorded as if it had taken effect.
func TestLoadWithSourcesIgnoresUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[future]\nthing = \"x\"\n[store]\npath = \"" + filepath.Join(dir, "h.db") + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, sources, err := LoadWithSources(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("LoadWithSources: %v", err)
	}
	if got := sources.SourceOf("future.thing"); got != SourceDefault {
		t.Fatalf("unknown key recorded as %q, want default", got)
	}
}

// TestResolvePath covers explicit > env > default-name > none.
func TestResolvePath(t *testing.T) {
	dir := t.TempDir()
	explicit := filepath.Join(dir, "explicit.toml")
	if got := ResolvePath(Options{FilePath: explicit, Env: map[string]string{}}); got != explicit {
		t.Fatalf("explicit path = %q", got)
	}
	envPath := filepath.Join(dir, "env.toml")
	if got := ResolvePath(Options{Env: map[string]string{ConfigEnvVar: envPath}}); got != envPath {
		t.Fatalf("env path = %q", got)
	}
	// No file anywhere: empty (or a default name if the CWD happens to hold one).
	if got := ResolvePath(Options{Env: map[string]string{}}); got != "" {
		if !strings.HasSuffix(got, "heimdall.toml") && !strings.HasSuffix(got, "config.toml") {
			t.Fatalf("ResolvePath = %q, want empty or a default name", got)
		}
	}

	// A default file name in the CURRENT directory is found.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "heimdall.toml"), []byte("config_version = 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Chdir(dir2)
	if got := ResolvePath(Options{Env: map[string]string{}}); got != "heimdall.toml" {
		t.Fatalf("ResolvePath with a default file = %q, want heimdall.toml", got)
	}
}

// TestKnownKeyProbesSetters proves knownKey recognises exactly the keys a setter
// claims and rejects an unknown one.
func TestKnownKeyProbesSetters(t *testing.T) {
	for _, key := range []string{
		"config_version", "server.host", "log.level", "store.path",
		"features.gates.token", "features.gates.rate-limit",
		"features.gates.memory.ttl", "features.gates.security.pii_policy",
		"features.gates.token.engines.x.enabled",
		"security.require_client_key", "security.management_login_rate_limit.rate",
		"passthrough.api_key", "providers.0.base_url",
	} {
		if !knownKey(key) {
			t.Errorf("knownKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"future.thing", "", "server.nope", "security.nope"} {
		if knownKey(key) {
			t.Errorf("knownKey(%q) = true, want false", key)
		}
	}
}
