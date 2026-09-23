package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

func writeTOML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestProvidersBlockParses pins the [[providers]] parse: every field, in order.
func TestProvidersBlockParses(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://api.z.ai/api/paas/v4"
auth_header = "bearer"
allow_loopback = false
ttft = "45s"
idle = "10s"
enabled = true

[[providers]]
id = "ollama-cloud"
base_url = "https://ollama.com/v1"
auth_header = "x-api-key"
enabled = false
`)
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(cfg.Providers))
	}
	p0 := cfg.Providers[0]
	if p0.ID != "z.ai" || p0.BaseURL != "https://api.z.ai/api/paas/v4" || p0.AuthHeader != "bearer" ||
		p0.AllowLoopback || !p0.Enabled || p0.TTFT != 45*time.Second || p0.Idle != 10*time.Second {
		t.Fatalf("provider[0] = %+v", p0)
	}
	p1 := cfg.Providers[1]
	if p1.ID != "ollama-cloud" || p1.AuthHeader != "x-api-key" || p1.Enabled {
		t.Fatalf("provider[1] = %+v", p1)
	}
}

// TestProvidersAuthHeaderDefaultsEmpty covers an omitted auth_header: "" is the
// bearer default and must validate.
func TestProvidersAuthHeaderDefaultsEmpty(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://api.z.ai/v1"
enabled = true
`)
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Providers[0].AuthHeader != "" {
		t.Fatalf("auth_header = %q, want empty", cfg.Providers[0].AuthHeader)
	}
}

// TestProvidersEnvOverride covers precedence: HEIMDALL_PROVIDERS_0_BASE_URL
// overrides the file value.
func TestProvidersEnvOverride(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://file.example/v1"
enabled = true
`)
	cfg, err := Load(Options{
		FilePath: path,
		Env:      map[string]string{"HEIMDALL_PROVIDERS_0_BASE_URL": "https://env.example/v1"},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Providers[0].BaseURL != "https://env.example/v1" {
		t.Fatalf("base_url = %q, want the env value", cfg.Providers[0].BaseURL)
	}
}

// TestProvidersRejectsInvalidBaseURL is the fail-closed ADR-SEC-05 check: a
// plain-HTTP remote is refused.
func TestProvidersRejectsInvalidBaseURL(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "http://api.z.ai/v1"
enabled = true
`)
	_, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err == nil {
		t.Fatal("plain-HTTP remote base_url accepted")
	}
	if de, ok := err.(*domain.DomainError); !ok || de.Code != domain.CodeConfigLoadFailed {
		t.Fatalf("err = %v, want %s", err, domain.CodeConfigLoadFailed)
	}
}

// TestProvidersLoopbackRequiresLiteral covers the allow_loopback guard: it is
// only legal for a loopback literal.
func TestProvidersLoopbackRequiresLiteral(t *testing.T) {
	t.Run("loopback literal allowed", func(t *testing.T) {
		path := writeTOML(t, `config_version = 1
[[providers]]
id = "local"
base_url = "http://127.0.0.1:11434/v1"
allow_loopback = true
enabled = true
`)
		if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err != nil {
			t.Fatalf("loopback literal rejected: %v", err)
		}
	})
	t.Run("non-literal with allow_loopback rejected", func(t *testing.T) {
		path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://api.z.ai/v1"
allow_loopback = true
enabled = true
`)
		if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
			t.Fatal("allow_loopback on a non-loopback host accepted")
		}
	})
	t.Run("loopback literal without opt-in rejected for http", func(t *testing.T) {
		path := writeTOML(t, `config_version = 1
[[providers]]
id = "local"
base_url = "http://127.0.0.1:11434/v1"
enabled = true
`)
		if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
			t.Fatal("plain http loopback without allow_loopback accepted")
		}
	})
}

// TestProvidersEnabledRequiresBaseURL is the fail-closed boot decision: an
// enabled provider without a base_url is rejected.
func TestProvidersEnabledRequiresBaseURL(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
enabled = true
`)
	_, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err == nil {
		t.Fatal("enabled provider with no base_url accepted")
	}
	// Disabled without base_url is allowed.
	path2 := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
enabled = false
`)
	if _, err := Load(Options{FilePath: path2, Env: map[string]string{}}); err != nil {
		t.Fatalf("disabled provider without base_url rejected: %v", err)
	}
}

// TestProvidersRejectsBadFields drives every per-field validation error.
func TestProvidersRejectsBadFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty id", `config_version = 1
[[providers]]
base_url = "https://x/v1"
enabled = true
`},
		{"bad auth_header", `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
auth_header = "basic"
enabled = true
`},
		{"bad bool", `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
enabled = "maybe"
`},
		{"bad duration", `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
ttft = "notaduration"
enabled = true
`},
		{"bad allow_loopback bool", `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
allow_loopback = "nope"
enabled = true
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTOML(t, tt.body)
			if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
				t.Fatal("invalid provider accepted")
			}
		})
	}
}

// TestParseProviderKey covers the key splitter's accept/reject branches.
func TestParseProviderKey(t *testing.T) {
	tests := []struct {
		key   string
		ok    bool
		index int
		field string
	}{
		{"providers.0.id", true, 0, "id"},
		{"providers.12.base_url", true, 12, "base_url"},
		{"providers.id", false, 0, ""},
		{"providers..id", false, 0, ""},
		{"providers.x.id", false, 0, ""},
		{"providers.-1.id", false, 0, ""},
		{"providers.1.", false, 0, ""},
		{"other.0.id", false, 0, ""},
	}
	for _, tt := range tests {
		i, f, ok := parseProviderKey(tt.key)
		if ok != tt.ok || (ok && (i != tt.index || f != tt.field)) {
			t.Errorf("parseProviderKey(%q) = %d,%q,%v want %d,%q,%v", tt.key, i, f, ok, tt.index, tt.field, tt.ok)
		}
	}
}

// TestParseDurationEmpty covers the unset branch.
func TestParseDurationEmpty(t *testing.T) {
	if d, err := parseDuration("  "); err != nil || d != 0 {
		t.Fatalf("empty duration = %v, %v", d, err)
	}
	if d, err := parseDuration("30s"); err != nil || d != 30*time.Second {
		t.Fatalf("30s = %v, %v", d, err)
	}
}

// TestProvidersUnknownFieldIgnored covers forward-compatibility.
func TestProvidersUnknownFieldIgnored(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
enabled = true
future_field = "ignored"
`)
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err != nil {
		t.Fatalf("unknown provider field rejected: %v", err)
	}
}

// TestIsCleartextURLBranches covers https, http, a parse failure and a
// scheme-less value.
func TestIsCleartextURLBranches(t *testing.T) {
	if isCleartextURL("https://x/v1") {
		t.Error("https marked cleartext")
	}
	if !isCleartextURL("http://x/v1") {
		t.Error("http not marked cleartext")
	}
	if !isCleartextURL("://bad") {
		t.Error("unparseable URL not treated as cleartext")
	}
}

// TestParseProviderEnvVarRejects covers the malformed-variable branches.
func TestParseProviderEnvVarRejects(t *testing.T) {
	for _, name := range []string{
		"OTHER_0_ID",
		"HEIMDALL_PROVIDERS_",
		"HEIMDALL_PROVIDERS_0",      // no field
		"HEIMDALL_PROVIDERS_0_",     // empty field
		"HEIMDALL_PROVIDERS_0_TYPO", // unknown field
		"HEIMDALL_PROVIDERS_x_ID",   // non-numeric index
		"HEIMDALL_PROVIDERS_-1_ID",  // negative index
	} {
		if _, ok := parseProviderEnvVar(name); ok {
			t.Errorf("parseProviderEnvVar(%q) accepted", name)
		}
	}
	// A valid one with a multi-underscore field.
	if k, ok := parseProviderEnvVar("HEIMDALL_PROVIDERS_2_ALLOW_LOOPBACK"); !ok || k != "providers.2.allow_loopback" {
		t.Fatalf("valid env var = %q, %v", k, ok)
	}
}

// TestSetProviderBadIdle covers the idle-duration error branch.
func TestSetProviderBadIdle(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
idle = "nope"
enabled = true
`)
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("bad idle accepted")
	}
}

// TestProvidersModelsParsed proves a provider's `models` string array is parsed
// into the declared list, and env can set it too.
func TestProvidersModelsParsed(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[[providers]]
id = "z.ai"
base_url = "https://x/v1"
models = ["glm-4.6", "glm-4.5"]
enabled = true
`)
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Providers[0].Models
	if len(got) != 2 || got[0] != "glm-4.6" || got[1] != "glm-4.5" {
		t.Fatalf("models = %v", got)
	}

	// Env override of the list.
	cfg2, err := Load(Options{FilePath: path, Env: map[string]string{
		"HEIMDALL_PROVIDERS_0_MODELS": "a,b , c",
	}})
	if err != nil {
		t.Fatalf("Load(env): %v", err)
	}
	if got := cfg2.Providers[0].Models; len(got) != 3 || got[2] != "c" {
		t.Fatalf("env models = %v", got)
	}
}

// TestSplitList covers the comma list parser.
func TestSplitList(t *testing.T) {
	if got := splitList("  "); got != nil {
		t.Fatalf("blank list = %v, want nil", got)
	}
	if got := splitList("a,,b, "); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("splitList = %v", got)
	}
}

// TestProvidersEnvAddsNewEntry covers env creating a provider entry that the
// file did not declare.
func TestProvidersEnvAddsNewEntry(t *testing.T) {
	path := writeTOML(t, `config_version = 1
`)
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{
		"HEIMDALL_PROVIDERS_0_ID":       "z.ai",
		"HEIMDALL_PROVIDERS_0_BASE_URL": "https://env.example/v1",
		"HEIMDALL_PROVIDERS_0_ENABLED":  "true",
	}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].ID != "z.ai" || !cfg.Providers[0].Enabled {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
}
