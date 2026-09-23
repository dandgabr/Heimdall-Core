package config

import (
	"testing"
	"time"
)

// TestGateParamsLoadFromTOML proves the wave-5 parameter keys load from the
// config file with their typed values (durations, ints, enums, URLs).
func TestGateParamsLoadFromTOML(t *testing.T) {
	file := `
[features.gates.memory]
ttl = "168h"
budget = "250ms"
retrieval_limit = 5
max_content = 2048
sink_capacity = 16

[features.gates.memory.embeddings]
base_url = "https://embeddings.example.com/v1"
model = "embed-3"
api_key_env = "HEIMDALL_EMBED_KEY"
dim = 8

[features.gates.security]
pii_policy = "block"
injection_policy = "flag"

[features.gates.security.rate_limit]
rate = 30
interval = "1m"
`
	cfg, err := Load(Options{FilePath: writeTOML(t, file), Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.Features.Gates.MemoryParams
	if m.TTL != 168*time.Hour || m.Budget != 250*time.Millisecond {
		t.Fatalf("durations = %v/%v", m.TTL, m.Budget)
	}
	if m.RetrievalLimit != 5 || m.MaxContent != 2048 || m.SinkCapacity != 16 {
		t.Fatalf("limits = %+v", m)
	}
	if m.Embeddings.BaseURL != "https://embeddings.example.com/v1" ||
		m.Embeddings.Model != "embed-3" || m.Embeddings.APIKeyEnv != "HEIMDALL_EMBED_KEY" || m.Embeddings.Dim != 8 {
		t.Fatalf("embeddings = %+v", m.Embeddings)
	}
	sec := cfg.Features.Gates.SecurityParams
	if sec.PIIPolicy != "block" || sec.InjectPolicy != "flag" {
		t.Fatalf("policies = %q/%q", sec.PIIPolicy, sec.InjectPolicy)
	}
	if sec.RateLimit.Rate != 30 || sec.RateLimit.Interval != time.Minute {
		t.Fatalf("rate limit = %+v", sec.RateLimit)
	}
	// And the whole thing validates.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestGateParamsDefaultsAreExplicit pins the shipped defaults so an operator
// reading the defaults knows what the gates do before overriding.
func TestGateParamsDefaultsAreExplicit(t *testing.T) {
	g := Defaults().Features.Gates
	if g.MemoryParams.TTL != 30*24*time.Hour {
		t.Fatalf("default TTL = %v", g.MemoryParams.TTL)
	}
	if g.MemoryParams.RetrievalLimit != 3 || g.MemoryParams.Budget != 100*time.Millisecond ||
		g.MemoryParams.MaxContent != 4096 || g.MemoryParams.SinkCapacity != 64 {
		t.Fatalf("memory defaults = %+v", g.MemoryParams)
	}
	if g.MemoryParams.Embeddings.BaseURL != "" {
		t.Fatal("vector mode must default OFF (local-first, ADR-SEC-07 §5)")
	}
	if g.SecurityParams.PIIPolicy != "mask" || g.SecurityParams.InjectPolicy != "block" {
		t.Fatalf("security defaults = %+v", g.SecurityParams)
	}
	if g.SecurityParams.RateLimit.Rate != 0 {
		t.Fatal("the throttle must default OFF (no safe capacity guess)")
	}
}

// TestGateParamsValidationRejects is the fail-closed table: a typo'd policy or
// an incoherent opt-in must fail the boot, never fall back silently.
func TestGateParamsValidationRejects(t *testing.T) {
	base := func(mutate func(*Config)) Config {
		cfg := Defaults()
		mutate(&cfg)
		return cfg
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"typo'd pii policy", func(c *Config) { c.Features.Gates.SecurityParams.PIIPolicy = "blok" }},
		{"typo'd injection policy", func(c *Config) { c.Features.Gates.SecurityParams.InjectPolicy = "blockk" }},
		{"negative rate", func(c *Config) {
			c.Features.Gates.SecurityParams.RateLimit = RateLimitConfig{Rate: -1, Interval: time.Minute}
		}},
		{"rate without interval", func(c *Config) {
			c.Features.Gates.SecurityParams.RateLimit = RateLimitConfig{Rate: 10}
		}},
		{"negative ttl", func(c *Config) { c.Features.Gates.MemoryParams.TTL = -time.Hour }},
		{"negative retrieval limit", func(c *Config) { c.Features.Gates.MemoryParams.RetrievalLimit = -1 }},
		{"embeddings without model", func(c *Config) {
			c.Features.Gates.MemoryParams.Embeddings = EmbeddingsConfig{BaseURL: "https://e.example.com", Dim: 4}
		}},
		{"embeddings without dim", func(c *Config) {
			c.Features.Gates.MemoryParams.Embeddings = EmbeddingsConfig{
				BaseURL: "https://e.example.com", Model: "m",
			}
		}},
		{"embeddings over cleartext http", func(c *Config) {
			c.Features.Gates.MemoryParams.Embeddings = EmbeddingsConfig{
				BaseURL: "http://embeddings.example.com", Model: "m", Dim: 4,
			}
		}},
		{"embeddings to cleartext private host", func(c *Config) {
			c.Features.Gates.MemoryParams.Embeddings = EmbeddingsConfig{
				BaseURL: "http://10.0.0.5:9", Model: "m", Dim: 4,
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := base(tc.mutate).Validate(); err == nil {
				t.Fatal("Validate accepted an invalid gate parameter block")
			}
		})
	}
}

// TestGateParamsValidationAcceptsValidEmbeddings covers the loopback
// exception (ADR-SEC-05 §2): a local embedding server on an explicit loopback
// IP literal is a legitimate local-first opt-in — with https, and with the
// cleartext http form the exception exists for.
func TestGateParamsValidationAcceptsValidEmbeddings(t *testing.T) {
	for _, baseURL := range []string{"https://127.0.0.1:11434", "http://127.0.0.1:11434", "http://[::1]:11434"} {
		cfg := Defaults()
		cfg.Features.Gates.MemoryParams.Embeddings = EmbeddingsConfig{
			BaseURL: baseURL, Model: "local-embed", Dim: 8,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate rejected the loopback endpoint %s: %v", baseURL, err)
		}
	}
}

// TestGateParamsUnknownKeysFallThrough proves the parameter setters claim only
// their own keys: an unknown key under either new prefix is ignored (the
// forward-compatible behaviour), never an error and never a wrong write.
func TestGateParamsUnknownKeysFallThrough(t *testing.T) {
	file := `
[features.gates.memory]
unknown_key = 1
[features.gates.security]
unknown_key = "x"
`
	cfg, err := Load(Options{FilePath: writeTOML(t, file), Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load rejected unknown gate keys: %v", err)
	}
	if cfg.Features.Gates.MemoryParams.TTL != 30*24*time.Hour {
		t.Fatalf("unknown key perturbed the defaults: %+v", cfg.Features.Gates.MemoryParams)
	}
}

// TestGateParamsBadValuesAreTypedErrors covers the parser error branches: a
// malformed number or duration is a config error, not a silent zero.
func TestGateParamsBadValuesAreTypedErrors(t *testing.T) {
	cases := []struct {
		name string
		file string
	}{
		{"bad retrieval_limit", "[features.gates.memory]\nretrieval_limit = \"abc\"\n"},
		{"bad ttl", "[features.gates.memory]\nttl = \"abc\"\n"},
		{"bad sink_capacity", "[features.gates.memory]\nsink_capacity = \"x\"\n"},
		{"bad embeddings dim", "[features.gates.memory.embeddings]\ndim = \"x\"\n"},
		{"bad rate", "[features.gates.security.rate_limit]\nrate = \"abc\"\n"},
		{"bad interval", "[features.gates.security.rate_limit]\ninterval = \"xyz\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(Options{FilePath: writeTOML(t, tc.file), Env: map[string]string{}}); err == nil {
				t.Fatalf("%s: Load accepted a malformed value", tc.name)
			}
		})
	}
}
