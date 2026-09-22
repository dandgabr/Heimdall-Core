package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestValidateEveryField drives every rejection branch of Validate.
func TestValidateEveryField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"port zero", func(c *Config) { c.Server.Port = 0 }, domain.CodeConfigInvalidPort},
		{"port too high", func(c *Config) { c.Server.Port = 70000 }, domain.CodeConfigInvalidPort},
		{"non-loopback", func(c *Config) { c.Server.Host = "0.0.0.0" }, domain.CodeConfigBindNotLoopback},
		{"bad log level", func(c *Config) { c.Log.Level = "verbose" }, domain.CodeConfigLoadFailed},
		{"bad log format", func(c *Config) { c.Log.Format = "xml" }, domain.CodeConfigLoadFailed},
		{"empty store path", func(c *Config) { c.Store.Path = "  " }, domain.CodeConfigLoadFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected a validation error")
			}
			de, ok := err.(*domain.DomainError)
			if !ok || de.Code != tt.want {
				t.Fatalf("err = %v, want %s", err, tt.want)
			}
		})
	}
	// The defaults must be valid.
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

// TestPassthroughResolve covers all three resolution branches.
func TestPassthroughResolve(t *testing.T) {
	env := map[string]string{"MY_KEY": "from-env"}
	if got := (Passthrough{APIKey: "direct", APIKeyEnv: "MY_KEY"}).Resolve(env); got != "direct" {
		t.Errorf("direct should win, got %q", got)
	}
	if got := (Passthrough{APIKeyEnv: "MY_KEY"}).Resolve(env); got != "from-env" {
		t.Errorf("env fallback = %q", got)
	}
	if got := (Passthrough{APIKeyEnv: "MISSING"}).Resolve(env); got != "" {
		t.Errorf("missing env = %q, want empty", got)
	}
	if got := (Passthrough{}).Resolve(nil); got != "" {
		t.Errorf("nothing configured = %q, want empty", got)
	}
}

// TestParseBool covers all accepted and rejected forms.
func TestParseBool(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE", " yes ", "on"} {
		if v, err := parseBool(s); err != nil || !v {
			t.Errorf("parseBool(%q) = %v, %v; want true", s, v, err)
		}
	}
	for _, s := range []string{"0", "false", "NO", "off"} {
		if v, err := parseBool(s); err != nil || v {
			t.Errorf("parseBool(%q) = %v, %v; want false", s, v, err)
		}
	}
	if _, err := parseBool("maybe"); err == nil {
		t.Error("parseBool accepted a non-boolean")
	}
}

// TestBadValueIsTyped covers the badValue helper (0% before).
func TestBadValueIsTyped(t *testing.T) {
	err := badValue("server.port", "abc")
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigLoadFailed {
		t.Fatalf("badValue = %v", err)
	}
	if de.Params["reason"] == "" {
		t.Error("badValue missing reason param")
	}
}

// TestEnvLookupNil covers the nil-env branch.
func TestEnvLookupNil(t *testing.T) {
	if got := envLookup(nil, "ANY"); got != "" {
		t.Errorf("envLookup(nil) = %q, want empty", got)
	}
	if got := envLookup(map[string]string{"A": "b"}, "A"); got != "b" {
		t.Errorf("envLookup = %q", got)
	}
}

// TestSetInvalidValues drives set's error branches through Load.
func TestSetInvalidValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	// A non-integer port and a non-boolean flag.
	body := "config_version = 1\n[server]\nport = \"not-a-port\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("non-integer port accepted")
	}

	body2 := "config_version = 1\n[server]\nallow_remote = \"maybe\"\n"
	if err := os.WriteFile(path, []byte(body2), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("non-boolean allow_remote accepted")
	}

	// A bad feature flag boolean.
	body3 := "config_version = 1\n[features.gates]\ntoken = \"perhaps\"\n"
	if err := os.WriteFile(path, []byte(body3), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("non-boolean feature flag accepted")
	}
}

// TestFlagLayerAliases covers the flag-name normalisation branches.
func TestFlagLayerAliases(t *testing.T) {
	out := flagLayer(map[string]string{
		"host":         "1.2.3.4",
		"port":         "9",
		"allow-remote": "true",
		"log-level":    "debug",
		"config":       "ignored",
	})
	if out["server.host"] != "1.2.3.4" || out["server.port"] != "9" ||
		out["server.allow_remote"] != "true" || out["log.level"] != "debug" {
		t.Fatalf("flagLayer = %v", out)
	}
	if _, ok := out["config"]; ok {
		t.Error("config must not become a value")
	}
}

// TestEnvLayerKnownKeys covers envLayer's mapped and ignored keys.
func TestEnvLayerKnownKeys(t *testing.T) {
	out := envLayer(map[string]string{
		"HEIMDALL_SERVER_PORT": "1234",
		"HEIMDALL_UNKNOWN":     "x",
		"PATH":                 "y",
	})
	if out["server.port"] != "1234" {
		t.Errorf("server.port = %q", out["server.port"])
	}
	if _, ok := out["HEIMDALL_UNKNOWN"]; ok {
		t.Error("unknown env key mapped")
	}
	if len(out) != 1 {
		t.Errorf("envLayer produced %d keys, want 1", len(out))
	}
}

// TestLoadBadVersion covers the non-numeric config_version branch.
func TestLoadBadVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	if err := os.WriteFile(path, []byte(`config_version = "one"`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// TOML decodes config_version as a string; set() must reject it.
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("non-numeric config_version accepted")
	}
}

// TestFlattenTypes covers flatten's type switches (nil, float, bool, int).
func TestFlattenTypes(t *testing.T) {
	out := flatten(map[string]any{
		"a":      "str",
		"b":      true,
		"c":      int64(42),
		"d":      1.5,
		"e":      nil,
		"nested": map[string]any{"f": "g"},
	})
	if out["a"] != "str" || out["b"] != "true" || out["c"] != "42" || out["d"] != "1.5" {
		t.Fatalf("flatten = %v", out)
	}
	if _, ok := out["e"]; ok {
		t.Error("nil leaf should be omitted")
	}
	if out["nested.f"] != "g" {
		t.Errorf("nested key = %q", out["nested.f"])
	}
}

// TestItoa covers upgrade.go's itoa (negative, zero, positive).
func TestItoa(t *testing.T) {
	tests := map[int]string{0: "0", 1: "1", -1: "-1", 12345: "12345", -987: "-987"}
	for in, want := range tests {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestDefaultDataDirXDG covers defaultDataDir with XDG_DATA_HOME set.
func TestDefaultDataDirXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-test-dir")
	if got := defaultDataDir(); got != filepath.Join("/tmp/xdg-test-dir", "heimdall") {
		t.Errorf("defaultDataDir = %q", got)
	}
	if got := defaultStorePath(); got != filepath.Join("/tmp/xdg-test-dir", "heimdall", "heimdall.db") {
		t.Errorf("defaultStorePath = %q", got)
	}
	if got := defaultTokenPath(); got != filepath.Join("/tmp/xdg-test-dir", "heimdall", "management-token") {
		t.Errorf("defaultTokenPath = %q", got)
	}
}

// TestReadFileValuesDefaultNames covers the default-file-name search: a
// heimdall.toml in the working directory is picked up when no path is given.
func TestReadFileValuesDefaultNames(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	if err := os.WriteFile("heimdall.toml", []byte("config_version = 1\n[server]\nport = 4242\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(Options{Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 4242 {
		t.Errorf("port = %d, want 4242 from the default-named file", cfg.Server.Port)
	}
}

// TestReadFileValuesEnvConfig covers HEIMDALL_CONFIG selecting the file.
func TestReadFileValuesEnvConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.toml")
	if err := os.WriteFile(path, []byte("config_version = 1\n[log]\nlevel = \"debug\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(Options{Env: map[string]string{ConfigEnvVar: path}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level = %q, want debug", cfg.Log.Level)
	}
}

// TestLoadInvalidTOML covers the decode-error branch.
func TestLoadInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("this is = = not toml"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("invalid TOML accepted")
	}
}

// TestDefaultDataDirNoXDG covers the UserHomeDir fallback branch.
func TestDefaultDataDirNoXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	got := defaultDataDir()
	if got == "" {
		t.Error("defaultDataDir returned empty")
	}
}

// TestFlattenDefaultType covers flatten's default branch (a type TOML would not
// produce but the function must still stringify).
func TestFlattenDefaultType(t *testing.T) {
	out := flatten(map[string]any{
		"weird": []any{"a", "b"},
	})
	if out["weird"] != "[a b]" {
		t.Errorf("flatten default = %q, want the stringified slice", out["weird"])
	}
}

// TestLoadValidateFailsAfterResolution covers the cfg.Validate branch at the end
// of Load: an env-provided empty store path passes set() but fails Validate.
func TestLoadValidateFailsAfterResolution(t *testing.T) {
	_, err := Load(Options{Env: map[string]string{"HEIMDALL_STORE_PATH": "  "}})
	if err == nil {
		t.Fatal("empty store path accepted through env")
	}
}

// TestReadFileValuesDefaultMissingIsOK covers the non-explicit missing-file
// branch: no file anywhere is a valid defaults-only load.
func TestReadFileValuesDefaultMissingIsOK(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	cfg, err := Load(Options{Env: map[string]string{}})
	if err != nil {
		t.Fatalf("defaults-only Load: %v", err)
	}
	if cfg.Server.Port != 8787 {
		t.Errorf("port = %d, want the default 8787", cfg.Server.Port)
	}
}

// TestSetEveryKey covers every accepted config key through set, including the
// passthrough and per-flag gate switches (previously partially covered).
func TestSetEveryKey(t *testing.T) {
	cfg := Defaults()
	cases := map[string]string{
		"config_version":          "1",
		"server.host":             "127.0.0.2",
		"server.port":             "9000",
		"server.allow_remote":     "true",
		"log.level":               "debug",
		"log.format":              "json",
		"store.path":              "/tmp/x.db",
		"store.token_path":        "/tmp/x.token",
		"features.gates.token":    "true",
		"features.gates.memory":   "false",
		"features.gates.security": "true",
		"passthrough.family":      "anthropic",
		"passthrough.base_url":    "https://x/v1",
		"passthrough.api_key":     "k",
		"passthrough.api_key_env": "MY_ENV",
		"unknown.future.key":      "ignored",
	}
	for key, value := range cases {
		if err := set(&cfg, key, value); err != nil {
			t.Errorf("set(%q, %q): %v", key, value, err)
		}
	}
	if cfg.Server.Host != "127.0.0.2" || cfg.Server.Port != 9000 || !cfg.Server.AllowRemote {
		t.Errorf("server fields not applied: %+v", cfg.Server)
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" {
		t.Errorf("log fields: %+v", cfg.Log)
	}
	if cfg.Store.Path != "/tmp/x.db" || cfg.Store.TokenPath != "/tmp/x.token" {
		t.Errorf("store fields: %+v", cfg.Store)
	}
	if !cfg.Features.Gates.Token || cfg.Features.Gates.Memory || !cfg.Features.Gates.Security {
		t.Errorf("feature gates: %+v", cfg.Features.Gates)
	}
	if cfg.Passthrough.Family != "anthropic" || cfg.Passthrough.APIKey != "k" || cfg.Passthrough.APIKeyEnv != "MY_ENV" {
		t.Errorf("passthrough: %+v", cfg.Passthrough)
	}

	// Bad values for each typed key must be rejected.
	for _, key := range []string{"config_version", "server.port"} {
		if err := set(&cfg, key, "not-a-number"); err == nil {
			t.Errorf("set(%q) accepted a non-number", key)
		}
	}
	for _, key := range []string{"server.allow_remote", "features.gates.token", "features.gates.memory", "features.gates.security"} {
		if err := set(&cfg, key, "maybe"); err == nil {
			t.Errorf("set(%q) accepted a non-boolean", key)
		}
	}
}

// TestDefaultDataDirNoHome covers the "." fallback when neither XDG_DATA_HOME
// nor a home directory resolves.
func TestDefaultDataDirNoHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")
	if got := defaultDataDir(); got != "." {
		t.Errorf("defaultDataDir with no HOME = %q, want %q", got, ".")
	}
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this environment resolves a home directory without HOME")
	}
}

// TestReadFileValuesExplicitMissing covers the explicit-path-missing branch.
func TestReadFileValuesExplicitMissing(t *testing.T) {
	_, err := Load(Options{FilePath: "/nonexistent/does-not-exist.toml", Env: map[string]string{}})
	if err == nil {
		t.Fatal("missing explicit config accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeConfigLoadFailed {
		t.Fatalf("err = %v, want config.load_failed", err)
	}
}

// TestLoadUpgradeError covers Load's Upgrade-error branch via the seam.
func TestLoadUpgradeError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	// A config_version BELOW current triggers Upgrade.
	if err := os.WriteFile(path, []byte("config_version = 0\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := upgradeFn
	upgradeFn = func(map[string]string) (map[string]string, error) { return nil, errors.New("upgrade denied") }
	t.Cleanup(func() { upgradeFn = old })
	if _, err := Load(Options{FilePath: path, Env: map[string]string{}}); err == nil {
		t.Fatal("Load succeeded when Upgrade failed")
	}
	upgradeFn = old
}

// TestReadFileValuesNonExplicitStatError covers the branch where a default-
// named file exists in the search list but the explicit stat of the chosen
// path fails and explicit is false. The search only picks a name that stats
// cleanly, so this path needs statFn to succeed during the search and fail on
// the second call.
func TestReadFileValuesNonExplicitStatError(t *testing.T) {
	oldWD, _ := os.Getwd()
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	old := statFn
	calls := 0
	statFn = func(path string) (os.FileInfo, error) {
		calls++
		if calls == 1 {
			// First call (the search) reports the file exists.
			return os.Stat(path)
		}
		// Second call (the validation) fails.
		return nil, errors.New("stat denied")
	}
	t.Cleanup(func() { statFn = old })

	// Create heimdall.toml so the first os.Stat succeeds.
	if err := os.WriteFile("heimdall.toml", []byte("config_version = 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(Options{Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err) // a non-explicit stat failure is tolerated
	}
	if cfg.ConfigVersion != 1 {
		t.Errorf("config_version = %d", cfg.ConfigVersion)
	}
	statFn = old
}
