package config

import "testing"

// TestGateEnabledPerGateSwitch proves the single rule the composition root uses
// (ADR-0014 §4): an explicit per-gate entry wins; a gate absent from the map
// falls back to its group switch.
func TestGateEnabledPerGateSwitch(t *testing.T) {
	g := GatesFeatures{Token: true, Memory: false, Security: false, Enabled: map[string]bool{
		"logger": false, // explicitly off though its group (none) is on
		"token":  false, // explicitly off
	}}
	cases := []struct {
		name  string
		group bool
		want  bool
	}{
		{"logger", true, false},  // explicit off wins
		{"token", true, false},   // explicit off wins
		{"memory", false, false}, // absent, group false
		{"other", true, true},    // absent, group true
	}
	for _, c := range cases {
		if got := g.GateEnabled(c.name, c.group); got != c.want {
			t.Errorf("GateEnabled(%q, %v) = %v, want %v", c.name, c.group, got, c.want)
		}
	}
	// A nil Enabled map falls back to the group switch.
	empty := GatesFeatures{Token: true}
	if !empty.GateEnabled("logger", true) || empty.GateEnabled("logger", false) {
		t.Error("nil Enabled did not fall back to the group switch")
	}
}

// TestParseGateSwitch covers the per-gate key parser: the three group switches
// are excluded, a dotted or empty name is refused.
func TestParseGateSwitch(t *testing.T) {
	ok := map[string]string{
		"features.gates.logger":  "logger",
		"features.gates.my_gate": "my_gate",
	}
	for key, want := range ok {
		got, valid := parseGateSwitch(key)
		if !valid || got != want {
			t.Errorf("parseGateSwitch(%q) = %q, %v", key, got, valid)
		}
	}
	for _, key := range []string{
		"features.gates.token", "features.gates.memory", "features.gates.security",
		"features.gates.", "features.gates.a.b", "features.other.x", "other",
	} {
		if _, valid := parseGateSwitch(key); valid {
			t.Errorf("parseGateSwitch(%q) accepted", key)
		}
	}
}

// TestParseGateEnvVar covers the env form of a per-gate switch.
func TestParseGateEnvVar(t *testing.T) {
	if got, ok := parseGateEnvVar("HEIMDALL_FEATURES_GATES_LOGGER"); !ok || got != "logger" {
		t.Fatalf("parseGateEnvVar = %q, %v", got, ok)
	}
	for _, name := range []string{
		"HEIMDALL_FEATURES_GATES_TOKEN", "HEIMDALL_FEATURES_GATES_MEMORY",
		"HEIMDALL_FEATURES_GATES_SECURITY", "HEIMDALL_FEATURES_GATES_",
		"HEIMDALL_FEATURES_GATES_MY_GATE", "OTHER",
	} {
		if _, ok := parseGateEnvVar(name); ok {
			t.Errorf("parseGateEnvVar(%q) accepted", name)
		}
	}
}

// TestParseTokenEngineKey covers the nested token-engine key parser.
func TestParseTokenEngineKey(t *testing.T) {
	name, field, ok := parseTokenEngineKey("features.gates.token.engines.dedup-lines.allow_prefix_rewrite")
	if !ok || name != "dedup-lines" || field != "allow_prefix_rewrite" {
		t.Fatalf("parse = %q/%q/%v", name, field, ok)
	}
	// A dotted engine name is allowed (the field is the last segment).
	name, field, ok = parseTokenEngineKey("features.gates.token.engines.a.b.enabled")
	if !ok || name != "a.b" || field != "enabled" {
		t.Fatalf("dotted name = %q/%q/%v", name, field, ok)
	}
	for _, key := range []string{
		"features.gates.token.engines..enabled",
		"features.gates.token.engines.x",
		"features.gates.token.engines.x.typo",
		"features.gates.token.engines.x.enabled.extra",
		"features.gates.token",
		"other",
	} {
		if _, _, ok := parseTokenEngineKey(key); ok {
			t.Errorf("parseTokenEngineKey(%q) accepted", key)
		}
	}
}

// TestTokenEngineConfigLoad proves the nested token-engine config loads from
// TOML, with disabled + opt-in, and queryable via the helpers.
func TestTokenEngineConfigLoad(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[features.gates.token.engines.collapse-whitespace]
enabled = false
[features.gates.token.engines.prefix-rewrite]
allow_prefix_rewrite = true
`)
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	g := cfg.Features.Gates
	if g.TokenEngineEnabled("collapse-whitespace") {
		t.Fatal("collapse-whitespace should be disabled")
	}
	if !g.TokenEngineEnabled("dedup-lines") {
		t.Fatal("an unconfigured engine should default to enabled")
	}
	if !g.TokenEngineAllowPrefixRewrite("prefix-rewrite") {
		t.Fatal("prefix-rewrite opt-in lost")
	}
	if g.TokenEngineAllowPrefixRewrite("dedup-lines") {
		t.Fatal("unexpected opt-in for dedup-lines")
	}

	// A bad value is rejected.
	if _, err := Load(Options{FilePath: writeTOML(t, `config_version = 1
[features.gates.token.engines.x]
enabled = "maybe"
`), Env: map[string]string{}}); err == nil {
		t.Fatal("bad nested bool accepted")
	}
}

// TestPerGateConfigFileAndEnv proves a per-gate switch loads from TOML and from
// env, and reaches GatesFeatures.Enabled.
func TestPerGateConfigFileAndEnv(t *testing.T) {
	path := writeTOML(t, `config_version = 1
[features.gates]
token = true
logger = false
`)
	cfg, err := Load(Options{FilePath: path, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Features.Gates.Enabled["logger"] {
		t.Fatalf("logger should be disabled: %+v", cfg.Features.Gates.Enabled)
	}
	if !cfg.Features.Gates.GateEnabled("logger", true) {
		// logger is explicitly false, so this should be false; sanity check.
	} else {
		t.Fatal("GateEnabled ignored the explicit false")
	}

	// Env form.
	cfg2, err := Load(Options{FilePath: writeTOML(t, "config_version = 1\n"), Env: map[string]string{
		"HEIMDALL_FEATURES_GATES_LOGGER": "false",
	}})
	if err != nil {
		t.Fatalf("Load(env): %v", err)
	}
	if cfg2.Features.Gates.GateEnabled("logger", true) {
		t.Fatalf("env per-gate switch not applied: %+v", cfg2.Features.Gates.Enabled)
	}

	// A bad bool value is rejected.
	if _, err := Load(Options{FilePath: writeTOML(t, "config_version = 1\n[features.gates]\nlogger = \"maybe\"\n"), Env: map[string]string{}}); err == nil {
		t.Fatal("bad per-gate bool accepted")
	}
}
