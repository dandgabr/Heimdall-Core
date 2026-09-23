package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestSecurityDefaults pins the F5.1 safe defaults (ADR-SEC-06): client-key
// auth OFF for out-of-the-box local use, no extra trusted Host/Origin names,
// CORS closed, and a conservative management-login throttle.
func TestSecurityDefaults(t *testing.T) {
	c := Defaults()
	if c.Security.RequireClientKey {
		t.Error("require_client_key must default off")
	}
	if len(c.Security.HostAllowlist) != 0 || len(c.Security.CORSAllowedOrigins) != 0 {
		t.Error("host/cors allowlists must default empty")
	}
	if c.Security.ManagementLoginRateLimit.Rate != 5 {
		t.Errorf("login rate = %d, want 5", c.Security.ManagementLoginRateLimit.Rate)
	}
	if c.Security.ManagementLoginRateLimit.Interval != time.Minute {
		t.Errorf("login interval = %v, want 1m", c.Security.ManagementLoginRateLimit.Interval)
	}
}

// TestValidateSecurityRejectsWildcardCORS is the fail-closed check the ADR
// mandates: a wildcard CORS entry must be refused at load.
func TestValidateSecurityRejectsWildcardCORS(t *testing.T) {
	c := Defaults()
	c.Security.CORSAllowedOrigins = []string{"*"}
	err := c.Validate()
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigLoadFailed {
		t.Fatalf("wildcard CORS accepted: %v", err)
	}
	if !strings.Contains(de.Params["reason"], "wildcard") {
		t.Fatalf("reason = %q, want a wildcard rejection", de.Params["reason"])
	}
}

func TestValidateSecurityShape(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Security)
		wantErr bool
	}{
		{"full origin ok", func(s *Security) { s.CORSAllowedOrigins = []string{"http://localhost:3000"} }, false},
		{"bare host origin rejected", func(s *Security) { s.CORSAllowedOrigins = []string{"localhost:3000"} }, true},
		{"empty host allowlist entry rejected", func(s *Security) { s.HostAllowlist = []string{" "} }, true},
		{"negative rate rejected", func(s *Security) { s.ManagementLoginRateLimit = RateLimitConfig{Rate: -1} }, true},
		{"rate without interval rejected", func(s *Security) { s.ManagementLoginRateLimit = RateLimitConfig{Rate: 3} }, true},
		{"zero rate disables", func(s *Security) { s.ManagementLoginRateLimit = RateLimitConfig{} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Defaults()
			tc.mutate(&c.Security)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestSetHTTPSecurityParam exercises the file/env resolver for the security
// block keys, including a bad boolean and an unknown security.* key.
func TestSetHTTPSecurityParam(t *testing.T) {
	c := Defaults()

	apply := func(key, value string) error {
		ok, err := setHTTPSecurityParam(&c, key, value)
		if !ok {
			t.Fatalf("key %q not recognised", key)
		}
		return err
	}

	if err := apply("security.require_client_key", "true"); err != nil {
		t.Fatalf("require_client_key: %v", err)
	}
	if !c.Security.RequireClientKey {
		t.Fatal("require_client_key not set")
	}

	if err := apply("security.host_allowlist", "router.local, router.lan:8080"); err != nil {
		t.Fatalf("host_allowlist: %v", err)
	}
	if len(c.Security.HostAllowlist) != 2 || c.Security.HostAllowlist[0] != "router.local" {
		t.Fatalf("host_allowlist = %v", c.Security.HostAllowlist)
	}

	if err := apply("security.cors_allowed_origins", "http://localhost:3000"); err != nil {
		t.Fatalf("cors: %v", err)
	}
	if len(c.Security.CORSAllowedOrigins) != 1 {
		t.Fatalf("cors = %v", c.Security.CORSAllowedOrigins)
	}

	if err := apply("security.management_login_rate_limit.rate", "9"); err != nil {
		t.Fatalf("rate: %v", err)
	}
	if c.Security.ManagementLoginRateLimit.Rate != 9 {
		t.Fatalf("rate = %d", c.Security.ManagementLoginRateLimit.Rate)
	}
	if err := apply("security.management_login_rate_limit.interval", "30s"); err != nil {
		t.Fatalf("interval: %v", err)
	}
	if c.Security.ManagementLoginRateLimit.Interval != 30*time.Second {
		t.Fatalf("interval = %v", c.Security.ManagementLoginRateLimit.Interval)
	}

	// Bad boolean.
	if err := apply("security.require_client_key", "maybe"); err == nil {
		t.Fatal("bad boolean accepted")
	}
	// Unknown security.* key falls through (ok=false).
	if ok, _ := setHTTPSecurityParam(&c, "security.unknown", "x"); ok {
		t.Fatal("unknown security key was recognised")
	}
	// A non-security key is not handled here.
	if ok, _ := setHTTPSecurityParam(&c, "server.host", "x"); ok {
		t.Fatal("non-security key was recognised")
	}
}

// TestLoadSecurityBlock loads a TOML file carrying the security block, proving
// the file layer reaches the resolver.
func TestLoadSecurityBlock(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/heimdall.toml"
	body := "config_version = 1\n" +
		"[store]\npath = \"" + dir + "/heimdall.db\"\ntoken_path = \"" + dir + "/tok\"\n" +
		"[security]\nrequire_client_key = true\n" +
		"host_allowlist = [\"router.local\"]\n" +
		"cors_allowed_origins = [\"http://localhost:3000\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Security.RequireClientKey {
		t.Error("require_client_key not loaded")
	}
	if len(cfg.Security.HostAllowlist) != 1 || cfg.Security.HostAllowlist[0] != "router.local" {
		t.Errorf("host_allowlist = %v", cfg.Security.HostAllowlist)
	}
	if len(cfg.Security.CORSAllowedOrigins) != 1 {
		t.Errorf("cors = %v", cfg.Security.CORSAllowedOrigins)
	}
}

// TestEnvSecurityRequireClientKey covers the env-layer mapping.
func TestEnvSecurityRequireClientKey(t *testing.T) {
	cfg, err := Load(Options{Env: map[string]string{
		"HEIMDALL_SECURITY_REQUIRE_CLIENT_KEY": "true",
		"HEIMDALL_STORE_PATH":                  "/tmp/x/heimdall.db",
	}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Security.RequireClientKey {
		t.Error("env require_client_key not applied")
	}
}
