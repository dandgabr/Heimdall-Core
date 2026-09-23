package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestProviderClientSecretResolve proves the OAuth client secret resolves from
// the direct value first, then the named env var, and is empty when neither is
// set.
func TestProviderClientSecretResolve(t *testing.T) {
	env := map[string]string{"ANTIGRAVITY_CLIENT_SECRET": "env-secret-value"}

	direct := ProviderConfig{ID: "antigravity", ClientSecret: "direct-secret", ClientSecretEnv: "ANTIGRAVITY_CLIENT_SECRET"}
	if got := direct.ResolveClientSecret(env); got != "direct-secret" {
		t.Fatalf("direct wins: got %q", got)
	}
	envOnly := ProviderConfig{ID: "antigravity", ClientSecretEnv: "ANTIGRAVITY_CLIENT_SECRET"}
	if got := envOnly.ResolveClientSecret(env); got != "env-secret-value" {
		t.Fatalf("env: got %q", got)
	}
	none := ProviderConfig{ID: "antigravity"}
	if got := none.ResolveClientSecret(env); got != "" {
		t.Fatalf("none: got %q, want empty", got)
	}
	// An env var that is not set resolves to empty (never a placeholder).
	missingEnv := ProviderConfig{ID: "antigravity", ClientSecretEnv: "NOT_SET_ANYWHERE"}
	if got := missingEnv.ResolveClientSecret(env); got != "" {
		t.Fatalf("missing env: got %q, want empty", got)
	}
}

// TestResolveClientSecretsMap proves the per-provider map skips providers with
// no secret and empty ids.
func TestResolveClientSecretsMap(t *testing.T) {
	providers := []ProviderConfig{
		{ID: "antigravity", ClientSecret: "s1"},
		{ID: "z.ai"},
		{ID: "", ClientSecret: "ignored"},
		{ID: "ollama-cloud", ClientSecretEnv: "OC"},
	}
	got := ResolveClientSecrets(providers, map[string]string{"OC": "s2"})
	if len(got) != 2 || got["antigravity"] != "s1" || got["ollama-cloud"] != "s2" {
		t.Fatalf("ResolveClientSecrets = %v", got)
	}
	if _, ok := got["z.ai"]; ok {
		t.Fatal("z.ai must not appear (no secret)")
	}
}

// TestProviderClientSecretLoadAndRedact proves the config file reaches the field
// and that BOTH the direct secret is redacted while the env NAME is shown.
func TestProviderClientSecretLoadAndRedact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	// A fixture value that is clearly NOT a real secret (and does not carry the
	// GOCSPX prefix, which the repo guard scans for even in tests).
	const secret = "fixture-client-secret-value-only"
	body := "config_version = 1\n" +
		"[store]\npath = \"" + filepath.Join(dir, "h.db") + "\"\n" +
		"[[providers]]\nid = \"antigravity\"\n" +
		"client_secret = \"" + secret + "\"\n" +
		"client_secret_env = \"ANTIGRAVITY_CLIENT_SECRET\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, sources, err := LoadWithSources(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("LoadWithSources: %v", err)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].ClientSecret != secret {
		t.Fatalf("client_secret not loaded: %+v", cfg.Providers)
	}
	if cfg.Providers[0].ClientSecretEnv != "ANTIGRAVITY_CLIENT_SECRET" {
		t.Fatalf("client_secret_env not loaded: %+v", cfg.Providers)
	}
	if sources.SourceOf("providers.0.client_secret") != SourceFile {
		t.Fatalf("source = %q, want file", sources.SourceOf("providers.0.client_secret"))
	}

	// Redaction: the secret value must never be printed; the env NAME may be.
	fields := RedactedFields(cfg, sources)
	byKey := map[string]Field{}
	for _, f := range fields {
		byKey[f.Key] = f
	}
	if got := byKey["providers.0.client_secret"].Value; got != Redacted {
		t.Fatalf("providers.0.client_secret = %q, want %q", got, Redacted)
	}
	if got := byKey["providers.0.client_secret_env"].Value; got != "ANTIGRAVITY_CLIENT_SECRET" {
		t.Fatalf("client_secret_env = %q, want the variable name", got)
	}
}

// TestProviderClientSecretEnvOverride proves the env layer can set the secret
// via HEIMDALL_PROVIDERS_<i>_CLIENT_SECRET.
func TestProviderClientSecretEnvOverride(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(Options{Env: map[string]string{
		"HEIMDALL_STORE_PATH":                    filepath.Join(dir, "h.db"),
		"HEIMDALL_PROVIDERS_0_ID":                "antigravity",
		"HEIMDALL_PROVIDERS_0_CLIENT_SECRET":     "from-env",
		"HEIMDALL_PROVIDERS_0_CLIENT_SECRET_ENV": "SOME_VAR",
	}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Providers) != 1 {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
	if cfg.Providers[0].ClientSecret != "from-env" {
		t.Fatalf("client_secret = %q", cfg.Providers[0].ClientSecret)
	}
	if cfg.Providers[0].ClientSecretEnv != "SOME_VAR" {
		t.Fatalf("client_secret_env = %q", cfg.Providers[0].ClientSecretEnv)
	}
}

// TestValidateProviderClientSecretEnvShape rejects a whitespace env name.
func TestValidateProviderClientSecretEnvShape(t *testing.T) {
	c := Defaults()
	c.Providers = []ProviderConfig{{ID: "antigravity", ClientSecretEnv: "has space"}}
	err := c.Validate()
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigLoadFailed {
		t.Fatalf("err = %v, want config.load_failed", err)
	}
	if !strings.Contains(de.Params["reason"], "whitespace") {
		t.Fatalf("reason = %q, want a whitespace rejection", de.Params["reason"])
	}

	c.Providers[0].ClientSecretEnv = "  "
	if err := c.Validate(); err == nil {
		t.Fatal("blank client_secret_env accepted")
	}
	// A valid name passes.
	c.Providers[0].ClientSecretEnv = "ANTIGRAVITY_CLIENT_SECRET"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid client_secret_env rejected: %v", err)
	}
}

// TestIsSecretKey covers the redaction classification for both static and
// per-provider keys.
func TestIsSecretKey(t *testing.T) {
	for _, k := range []string{"passthrough.api_key", "providers.0.client_secret", "providers.12.client_secret"} {
		if !isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"providers.0.client_secret_env", "providers.0.base_url", "passthrough.api_key_env"} {
		if isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = true, want false", k)
		}
	}
}
