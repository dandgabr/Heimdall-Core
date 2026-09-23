package config

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file builds the REDACTED, ordered projection of the effective config used
// by `heimdall config show`. It lives in the config package for one reason: the
// set of SECRET-BEARING keys is a property of the config schema, so the "never
// print a secret" rule has a single owner. The CLI cannot forget a key because
// it only renders what this function hands it.

// Redacted is the literal substituted for a secret-bearing field. It carries no
// length hint.
const Redacted = "[REDACTED]"

// Field is one rendered config entry: its dotted key, its (possibly redacted)
// value, and the precedence layer it came from.
type Field struct {
	Key    string
	Value  string
	Source Source
}

// RedactedFields returns the effective configuration as an ordered, secret-free
// list. Order is deterministic (the fixed schema order, with per-provider and
// per-gate map entries sorted), so the output is stable across runs.
//
// secretKeys names the fields whose VALUE must never be printed. Only a direct
// credential belongs here: passthrough.api_key (a raw key). APIKeyEnv NAMES a
// variable and is not itself a secret, so it is shown.
var secretKeys = map[string]bool{
	"passthrough.api_key": true,
}

// secretKeySuffixes are dotted-key SUFFIXES that mark a secret value, matched
// against the per-provider (index-addressed) keys that cannot be listed
// statically. `providers.<i>.client_secret` is the OAuth client secret; the
// env NAME form is not a secret and is shown.
var secretKeySuffixes = []string{
	".client_secret",
}

// isSecretKey reports whether a dotted key carries a secret value.
func isSecretKey(key string) bool {
	if secretKeys[key] {
		return true
	}
	for _, suffix := range secretKeySuffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// RedactedFieldKeys returns the sorted list of keys RedactedFields will emit,
// for tests and docs. It is derived from a Defaults() config so an empty map
// still enumerates the fixed keys.
func RedactedFieldKeys() []string {
	fields := RedactedFields(Defaults(), nil)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Key)
	}
	return out
}

// RedactedFields enumerates the effective config. cfg is the resolved config;
// sources maps each dotted key to the layer that set it (nil = all default).
func RedactedFields(cfg Config, sources Fields) []Field {
	var out []Field
	add := func(key, value string) {
		if isSecretKey(key) {
			value = Redacted
		}
		out = append(out, Field{Key: key, Value: value, Source: sources.SourceOf(key)})
	}
	addBool := func(key string, v bool) { add(key, strconv.FormatBool(v)) }
	addInt := func(key string, v int) { add(key, strconv.Itoa(v)) }
	addDur := func(key string, d time.Duration) { add(key, d.String()) }
	addList := func(key string, v []string) { add(key, strings.Join(v, ",")) }

	addInt("config_version", cfg.ConfigVersion)
	add("server.host", cfg.Server.Host)
	addInt("server.port", cfg.Server.Port)
	addBool("server.allow_remote", cfg.Server.AllowRemote)
	add("log.level", cfg.Log.Level)
	add("log.format", cfg.Log.Format)
	add("store.path", cfg.Store.Path)
	add("store.token_path", cfg.Store.TokenPath)

	addBool("features.gates.token", cfg.Features.Gates.Token)
	addBool("features.gates.memory", cfg.Features.Gates.Memory)
	addBool("features.gates.security", cfg.Features.Gates.Security)
	// Per-gate switches, sorted.
	for _, name := range sortedBoolKeys(cfg.Features.Gates.Enabled) {
		addBool("features.gates."+name, cfg.Features.Gates.Enabled[name])
	}
	// Token engines, sorted by engine then field.
	for _, name := range sortedEngineKeys(cfg.Features.Gates.TokenEngines) {
		ec := cfg.Features.Gates.TokenEngines[name]
		addBool("features.gates.token.engines."+name+".enabled", !ec.Disabled)
		addBool("features.gates.token.engines."+name+".allow_prefix_rewrite", ec.AllowPrefixRewrite)
	}

	mp := cfg.Features.Gates.MemoryParams
	addDur("features.gates.memory.ttl", mp.TTL)
	addInt("features.gates.memory.retrieval_limit", mp.RetrievalLimit)
	addDur("features.gates.memory.budget", mp.Budget)
	addInt("features.gates.memory.max_content", mp.MaxContent)
	addInt("features.gates.memory.sink_capacity", mp.SinkCapacity)
	add("features.gates.memory.embeddings.base_url", mp.Embeddings.BaseURL)
	add("features.gates.memory.embeddings.model", mp.Embeddings.Model)
	add("features.gates.memory.embeddings.api_key_env", mp.Embeddings.APIKeyEnv)
	addInt("features.gates.memory.embeddings.dim", mp.Embeddings.Dim)

	sp := cfg.Features.Gates.SecurityParams
	add("features.gates.security.pii_policy", sp.PIIPolicy)
	add("features.gates.security.injection_policy", sp.InjectPolicy)
	addInt("features.gates.security.rate_limit.rate", sp.RateLimit.Rate)
	addDur("features.gates.security.rate_limit.interval", sp.RateLimit.Interval)

	addBool("security.require_client_key", cfg.Security.RequireClientKey)
	addList("security.host_allowlist", cfg.Security.HostAllowlist)
	addList("security.cors_allowed_origins", cfg.Security.CORSAllowedOrigins)
	addInt("security.management_login_rate_limit.rate", cfg.Security.ManagementLoginRateLimit.Rate)
	addDur("security.management_login_rate_limit.interval", cfg.Security.ManagementLoginRateLimit.Interval)

	add("passthrough.family", cfg.Passthrough.Family)
	add("passthrough.base_url", cfg.Passthrough.BaseURL)
	add("passthrough.api_key", cfg.Passthrough.APIKey)
	add("passthrough.api_key_env", cfg.Passthrough.APIKeyEnv)

	// Providers in declared order (index-addressed), each field.
	for i, p := range cfg.Providers {
		prefix := "providers." + strconv.Itoa(i) + "."
		add(prefix+"id", p.ID)
		add(prefix+"base_url", p.BaseURL)
		add(prefix+"auth_header", p.AuthHeader)
		addBool(prefix+"allow_loopback", p.AllowLoopback)
		addDur(prefix+"ttft", p.TTFT)
		addDur(prefix+"idle", p.Idle)
		addBool(prefix+"enabled", p.Enabled)
		addList(prefix+"models", p.Models)
		add(prefix+"client_secret", p.ClientSecret)
		add(prefix+"client_secret_env", p.ClientSecretEnv)
	}
	return out
}

// sortedBoolKeys returns the map keys sorted, nil-safe.
func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedEngineKeys returns the token-engine map keys sorted, nil-safe.
func sortedEngineKeys(m map[string]TokenEngineConfig) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
