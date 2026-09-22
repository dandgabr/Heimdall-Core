package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

func TestLoadPrecedenceEnvFlagFileDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	file := `config_version = 1
[server]
host = "127.0.0.1"
port = 1111
[log]
level = "warn"
`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	tests := []struct {
		name         string
		flags        map[string]string
		env          map[string]string
		wantPort     int
		wantLogLevel string
	}{
		{
			name:         "file overrides default",
			wantPort:     1111,
			wantLogLevel: "warn",
		},
		{
			name:         "flag overrides file",
			flags:        map[string]string{"port": "2222"},
			wantPort:     2222,
			wantLogLevel: "warn",
		},
		{
			name:         "env overrides flag",
			flags:        map[string]string{"port": "2222"},
			env:          map[string]string{"HEIMDALL_SERVER_PORT": "3333"},
			wantPort:     3333,
			wantLogLevel: "warn",
		},
		{
			name:         "env overrides file directly",
			env:          map[string]string{"HEIMDALL_SERVER_PORT": "4444"},
			wantPort:     4444,
			wantLogLevel: "warn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(Options{FilePath: path, Flags: tt.flags, Env: tt.env})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Server.Port != tt.wantPort {
				t.Errorf("port = %d, want %d", cfg.Server.Port, tt.wantPort)
			}
			if cfg.Log.Level != tt.wantLogLevel {
				t.Errorf("log.level = %q, want %q", cfg.Log.Level, tt.wantLogLevel)
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(Options{Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Host != LoopbackHost {
		t.Errorf("host = %q, want %q", cfg.Server.Host, LoopbackHost)
	}
	if cfg.Server.AllowRemote {
		t.Error("allow_remote must default to false")
	}
	if cfg.Server.Port != 8787 {
		t.Errorf("port = %d, want 8787", cfg.Server.Port)
	}
}

func TestValidateRejectsNonLoopbackWithoutOverride(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Host = "0.0.0.0"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for 0.0.0.0 without allow_remote")
	}
	de, ok := err.(*domain.DomainError)
	if !ok {
		t.Fatalf("error type = %T, want *domain.DomainError", err)
	}
	if de.Code != domain.CodeConfigBindNotLoopback {
		t.Errorf("code = %q, want %q", de.Code, domain.CodeConfigBindNotLoopback)
	}

	cfg.Server.AllowRemote = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation with explicit override: %v", err)
	}
}

func TestValidateRejectsUnspecifiedIPv6AndEmptyHost(t *testing.T) {
	for _, host := range []string{"::", "", "0.0.0.0", "192.168.1.10"} {
		cfg := Defaults()
		cfg.Server.Host = host
		if err := cfg.Validate(); err == nil {
			t.Errorf("host %q: expected rejection without allow_remote", host)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1":          true,
		"127.0.0.53":         true,
		"127.1.2.3":          true,
		"localhost":          true,
		"LOCALHOST":          true,
		"::1":                true,
		"[::1]":              true,
		"0:0:0:0:0:0:0:1":    true,
		"0.0.0.0":            false,
		"::":                 false,
		"":                   false,
		"10.0.0.1":           false,
		"192.168.1.5":        false,
		"127.evil.com":       false,
		"example.com":        false,
		"localhost.evil.com": false,
		"127.0.0.1.evil.com": false,
	}
	for host, want := range tests {
		if got := (Server{Host: host}).IsLoopback(); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestAddrCanonicalisesHost is the N1 regression guard: an unbracketed IPv6
// literal used to produce "::1:8787", which net.Listen rejects with
// "too many colons in address".
func TestAddrCanonicalisesHost(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"127.0.0.1", "127.0.0.1:8787"},
		{"::1", "[::1]:8787"},
		{"[::1]", "[::1]:8787"},
		{"0:0:0:0:0:0:0:1", "[0:0:0:0:0:0:0:1]:8787"},
		{"localhost", "localhost:8787"},
		{" 127.0.0.1 ", "127.0.0.1:8787"},
	}
	for _, tt := range tests {
		got := Server{Host: tt.host, Port: 8787}.Addr()
		if got != tt.want {
			t.Errorf("Server{Host:%q}.Addr() = %q, want %q", tt.host, got, tt.want)
		}
	}
}

// TestValidateRejectsLoopbackLookalike is the P0-2 regression guard: a prefix
// test accepted "127.evil.com", which resolves to a real interface and defeats
// allow_remote=false.
func TestValidateRejectsLoopbackLookalike(t *testing.T) {
	for _, host := range []string{"127.evil.com", "127.0.0.1.evil.com", "localhost.evil.com"} {
		cfg := Defaults()
		cfg.Server.Host = host
		err := cfg.Validate()
		if err == nil {
			t.Errorf("host %q: expected rejection", host)
			continue
		}
		de, ok := err.(*domain.DomainError)
		if !ok || de.Code != domain.CodeConfigBindNotLoopback {
			t.Errorf("host %q: err = %v, want %s", host, err, domain.CodeConfigBindNotLoopback)
		}
	}
}

func TestLoadRejectsNewerConfigVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	if err := os.WriteFile(path, []byte("config_version = 99\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err == nil {
		t.Fatal("expected error for future config_version")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigInvalidVersion {
		t.Fatalf("err = %v, want %s", err, domain.CodeConfigInvalidVersion)
	}
}

func TestUpgradePromotesVersion(t *testing.T) {
	in := map[string]string{"server.port": "9000"}
	out, err := Upgrade(in)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if out["config_version"] != "1" {
		t.Errorf("config_version = %q, want 1", out["config_version"])
	}
	if out["server.port"] != "9000" {
		t.Errorf("server.port = %q, want 9000", out["server.port"])
	}
}

func TestFeatureFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	file := `[features.gates]
token = false
memory = true
security = false
`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Features.Gates.Token {
		t.Error("features.gates.token must be false")
	}
	if !cfg.Features.Gates.Memory {
		t.Error("features.gates.memory must be true")
	}
}

// TestEnvMultiWordKeys guards against an underscore-to-dot heuristic mangling
// snake_case keys: HEIMDALL_PASSTHROUGH_API_KEY_ENV must land on
// passthrough.api_key_env, not passthrough.api.key.env.
func TestEnvMultiWordKeys(t *testing.T) {
	cfg, err := Load(Options{Env: map[string]string{
		"HEIMDALL_PASSTHROUGH_API_KEY_ENV": "MY_UPSTREAM_KEY",
		"HEIMDALL_PASSTHROUGH_BASE_URL":    "https://example.test/v1",
		"HEIMDALL_SERVER_ALLOW_REMOTE":     "true",
		"HEIMDALL_SERVER_HOST":             "0.0.0.0",
	}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Passthrough.APIKeyEnv != "MY_UPSTREAM_KEY" {
		t.Errorf("api_key_env = %q, want MY_UPSTREAM_KEY", cfg.Passthrough.APIKeyEnv)
	}
	if cfg.Passthrough.BaseURL != "https://example.test/v1" {
		t.Errorf("base_url = %q", cfg.Passthrough.BaseURL)
	}
	if !cfg.Server.AllowRemote {
		t.Error("allow_remote must be true from env")
	}
}

func TestPassthroughResolveKey(t *testing.T) {
	p := Passthrough{APIKeyEnv: "MY_KEY"}
	if got := p.Resolve(map[string]string{"MY_KEY": "from-env"}); got != "from-env" {
		t.Errorf("Resolve = %q, want from-env", got)
	}
	p.APIKey = "direct"
	if got := p.Resolve(map[string]string{"MY_KEY": "from-env"}); got != "direct" {
		t.Errorf("Resolve = %q, want direct (direct value wins)", got)
	}
}
