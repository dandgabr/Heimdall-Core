package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// ConfigEnvVar names the environment variable pointing at an explicit config
// file, equivalent to passing --config.
const ConfigEnvVar = "HEIMDALL_CONFIG"

// upgradeFn and statFn are seams. Upgrade's contract returns an error for a
// future migration, and readFileValues probes os.Stat; in a healthy process
// neither fails, so the error branches are only reachable by injection.
var (
	upgradeFn = Upgrade
	statFn    = os.Stat
)

// defaultFileNames are searched, in order, when no path is supplied.
var defaultFileNames = []string{"heimdall.toml", "config.toml"}

// Options carries the raw inputs of one resolution. Precedence, highest first,
// is Env > Flags > File > defaults (ADR-002 / review note: `env>flag>arquivo>default`).
//
// Files must be a valid TOML source or Load returns a DomainError. Env is a
// snapshot (typically from os.Environ) so tests never mutate process state.
type Options struct {
	// FilePath, when set, is the only config file read.
	FilePath string
	// Flags holds flag name -> value for flags the user actually set. A flag
	// left at its default must NOT be placed here, otherwise it would shadow
	// the file (flags outrank files).
	Flags map[string]string
	// Env is the environment snapshot.
	Env map[string]string
}

// Load resolves, upgrades and validates the configuration.
func Load(opts Options) (Config, error) {
	cfg, _, err := load(opts)
	return cfg, err
}

// LoadWithSources resolves the configuration AND returns the per-key provenance.
// It is what `heimdall config show` needs to explain WHERE each value came from
// (ADR-002 precedence: env > flag > file > default). Load is the provenance-free
// façade over the same resolution, so the two can never diverge.
func LoadWithSources(opts Options) (Config, Fields, error) {
	return load(opts)
}

// load is the single resolution engine. sources records, per dotted key, the
// LAST layer that set it, which is exactly the layer that won under the
// documented precedence.
func load(opts Options) (Config, Fields, error) {
	cfg := Defaults()
	sources := Fields{}

	fileVals, err := readFileValues(opts)
	if err != nil {
		return Config{}, nil, err
	}

	// A config_version above this build's schema is refused outright; a lower
	// one is upgraded in place before any other key is applied.
	if v, ok := fileVals["config_version"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, nil, domain.New(domain.CodeConfigInvalidVersion,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"version": v}),
			)
		}
		if n > CurrentConfigVersion {
			return Config{}, nil, domain.New(domain.CodeConfigInvalidVersion,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"version": v}),
			)
		}
		if n < CurrentConfigVersion {
			if fileVals, err = upgradeFn(fileVals); err != nil {
				return Config{}, nil, err
			}
		}
	}

	// Apply in ascending priority: defaults are already in cfg, then file,
	// then flags, then environment. Later layers win, so each successful set
	// OVERWRITES the recorded source.
	for _, layer := range []struct {
		values map[string]string
		source Source
	}{
		{fileVals, SourceFile},
		{flagLayer(opts.Flags), SourceFlag},
		{envLayer(opts.Env), SourceEnv},
	} {
		for _, k := range sortedKeys(layer.values) {
			// Only a key this build RECOGNISES is recorded: an unknown key is
			// ignored by set (forward-compatible) and must not appear as if it
			// had taken effect.
			if !knownKey(k) {
				continue
			}
			if err := set(&cfg, k, layer.values[k]); err != nil {
				return Config{}, nil, err
			}
			sources[k] = layer.source
		}
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, nil, err
	}
	return cfg, sources, nil
}

// knownKey reports whether a dotted key is one this build recognises. It probes
// the SAME setters `set` dispatches to against a throwaway config, so the two
// can never drift: a key is "known" exactly when some setter claims it. The
// value is irrelevant (an unrecognised key reports handled=false regardless);
// a recognised key with an invalid value still reports handled=true and would
// surface its typed error through set.
func knownKey(key string) bool {
	var scratch Config
	if ok, _ := setMemoryGateParam(&scratch, key, ""); ok {
		return true
	}
	if ok, _ := setSecurityGateParam(&scratch, key, ""); ok {
		return true
	}
	if ok, _ := setHTTPSecurityParam(&scratch, key, ""); ok {
		return true
	}
	if _, _, ok := parseProviderKey(key); ok {
		return true
	}
	if _, _, ok := parseTokenEngineKey(key); ok {
		return true
	}
	if _, ok := parseGateSwitch(key); ok {
		return true
	}
	switch key {
	case "config_version", "server.host", "server.port", "server.allow_remote",
		"log.level", "log.format", "store.path", "store.token_path",
		"features.gates.token", "features.gates.memory", "features.gates.security",
		"passthrough.family", "passthrough.base_url", "passthrough.api_key",
		"passthrough.api_key_env":
		return true
	}
	return false
}

// ResolvePath returns the config file that WOULD be read for these options,
// empty when none is found. It uses the same selection rule as readFileValues
// (explicit path > HEIMDALL_CONFIG > default names) so `config path` reports the
// real file instead of a second implementation that could drift.
func ResolvePath(opts Options) string {
	path := opts.FilePath
	if path == "" {
		path = envLookup(opts.Env, ConfigEnvVar)
	}
	if path != "" {
		return path
	}
	for _, name := range defaultFileNames {
		if _, err := statFn(name); err == nil {
			return name
		}
	}
	return ""
}

// readFileValues loads and flattens the config file. A missing explicit path is
// an error; a missing default path is not (defaults-only operation is valid).
func readFileValues(opts Options) (map[string]string, error) {
	path := opts.FilePath
	explicit := path != ""
	if !explicit {
		if envPath := envLookup(opts.Env, ConfigEnvVar); envPath != "" {
			path, explicit = envPath, true
		}
	}
	if path == "" {
		for _, name := range defaultFileNames {
			if _, err := statFn(name); err == nil {
				path = name
				break
			}
		}
	}
	if path == "" {
		return map[string]string{}, nil
	}

	if _, err := statFn(path); err != nil {
		if explicit {
			return nil, domain.New(domain.CodeConfigLoadFailed,
				domain.WithHTTPStatus(500),
				domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "cannot read " + path}),
			)
		}
		return map[string]string{}, nil
	}

	var raw map[string]any
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, domain.New(domain.CodeConfigLoadFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "invalid TOML in " + path}),
		)
	}
	return flatten(raw), nil
}

// flagLayer normalises flag names ("server-host") to config keys
// ("server.host"), with explicit aliases for flags whose name differs.
func flagLayer(flags map[string]string) map[string]string {
	out := make(map[string]string, len(flags))
	for name, value := range flags {
		key := strings.TrimPrefix(name, "--")
		key = strings.ReplaceAll(key, "_", "-")
		switch key {
		case "allow-remote":
			out["server.allow_remote"] = value
		case "host":
			out["server.host"] = value
		case "port":
			out["server.port"] = value
		case "config":
			// handled as a file selector, not a value
		default:
			out[strings.ReplaceAll(key, "-", ".")] = value
		}
	}
	return out
}

// envKeyMap maps a supported environment variable to its config key. An
// explicit table beats an underscore-to-dot heuristic: keys such as
// passthrough.api_key_env and server.allow_remote contain underscores that a
// blanket "_"->"." rule would mangle into api.key.env / server.allow.remote.
// The surface is small and known, so spelling it out is both clearer and less
// error-prone. HEIMDALL_CONFIG is intentionally absent: it selects the file, it
// is not a value.
var envKeyMap = map[string]string{
	"HEIMDALL_SERVER_HOST":                   "server.host",
	"HEIMDALL_SERVER_PORT":                   "server.port",
	"HEIMDALL_SERVER_ALLOW_REMOTE":           "server.allow_remote",
	"HEIMDALL_LOG_LEVEL":                     "log.level",
	"HEIMDALL_LOG_FORMAT":                    "log.format",
	"HEIMDALL_STORE_PATH":                    "store.path",
	"HEIMDALL_STORE_TOKEN_PATH":              "store.token_path",
	"HEIMDALL_FEATURES_GATES_TOKEN":          "features.gates.token",
	"HEIMDALL_FEATURES_GATES_MEMORY":         "features.gates.memory",
	"HEIMDALL_FEATURES_GATES_SECURITY":       "features.gates.security",
	"HEIMDALL_SECURITY_REQUIRE_CLIENT_KEY":   "security.require_client_key",
	"HEIMDALL_SECURITY_HOST_ALLOWLIST":       "security.host_allowlist",
	"HEIMDALL_SECURITY_CORS_ALLOWED_ORIGINS": "security.cors_allowed_origins",
	"HEIMDALL_PASSTHROUGH_FAMILY":            "passthrough.family",
	"HEIMDALL_PASSTHROUGH_BASE_URL":          "passthrough.base_url",
	"HEIMDALL_PASSTHROUGH_API_KEY":           "passthrough.api_key",
	"HEIMDALL_PASSTHROUGH_API_KEY_ENV":       "passthrough.api_key_env",
}

// envLayer maps a supported HEIMDALL_* variable to its config key. Unknown
// variables are ignored; adding a key means adding it to envKeyMap. A
// per-provider variable (HEIMDALL_PROVIDERS_<i>_<FIELD>) is mapped by
// parseProviderEnvVar, since its index is open-ended.
func envLayer(env map[string]string) map[string]string {
	out := map[string]string{}
	for name, value := range env {
		upper := strings.ToUpper(name)
		if key, ok := envKeyMap[upper]; ok {
			out[key] = value
			continue
		}
		if key, ok := parseProviderEnvVar(upper); ok {
			out[key] = value
			continue
		}
		// A per-gate switch: HEIMDALL_FEATURES_GATES_<NAME> (ADR-0014 §4). The
		// three group variables are in envKeyMap above, so anything else under
		// that prefix is a gate name. The name is lowercased so the key matches
		// the TOML form (features.gates.<name>).
		if name, ok := parseGateEnvVar(upper); ok {
			out["features.gates."+name] = value
		}
	}
	return out
}

// parseGateEnvVar recognises HEIMDALL_FEATURES_GATES_<NAME> for a NAME that is
// not one of the three group switches. The name is lowercased.
func parseGateEnvVar(name string) (string, bool) {
	const prefix = "HEIMDALL_FEATURES_GATES_"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	rest := strings.ToLower(name[len(prefix):])
	switch rest {
	case "", "token", "memory", "security":
		return "", false
	}
	if strings.Contains(rest, "_") {
		// Underscores would be ambiguous with the group variables; a gate name
		// uses dots/hyphens, which env cannot express. Refuse rather than guess.
		return "", false
	}
	return rest, true
}

// providerEnvFields is the closed set of provider fields addressable via env.
var providerEnvFields = map[string]string{
	"ID":                "id",
	"BASE_URL":          "base_url",
	"AUTH_HEADER":       "auth_header",
	"ALLOW_LOOPBACK":    "allow_loopback",
	"TTFT":              "ttft",
	"IDLE":              "idle",
	"ENABLED":           "enabled",
	"MODELS":            "models",
	"CLIENT_SECRET":     "client_secret",
	"CLIENT_SECRET_ENV": "client_secret_env",
}

// parseProviderEnvVar recognises HEIMDALL_PROVIDERS_<index>_<FIELD> and returns
// the dotted config key (providers.<index>.<field>). The field is matched
// against the known set so a variable like HEIMDALL_PROVIDERS_0_TYPO is ignored
// rather than silently setting nothing.
func parseProviderEnvVar(name string) (string, bool) {
	const prefix = "HEIMDALL_PROVIDERS_"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	rest := name[len(prefix):]
	// Split at the FIRST underscore: the index is digits only, while a field
	// name may itself contain underscores (BASE_URL, ALLOW_LOOPBACK, ...).
	us := strings.IndexByte(rest, '_')
	if us <= 0 || us == len(rest)-1 {
		return "", false
	}
	indexStr, fieldStr := rest[:us], rest[us+1:]
	field, ok := providerEnvFields[fieldStr]
	if !ok {
		return "", false
	}
	i, err := strconv.Atoi(indexStr)
	if err != nil || i < 0 {
		return "", false
	}
	return "providers." + strconv.Itoa(i) + "." + field, true
}

// set assigns one dotted config key. Unknown keys are ignored so a newer config
// file degrades gracefully instead of failing the boot; the version field and
// Validate cover schema and value errors.
func set(cfg *Config, key, value string) error {
	switch key {
	case "config_version":
		n, err := strconv.Atoi(value)
		if err != nil {
			return domain.New(domain.CodeConfigInvalidVersion,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"version": value}),
			)
		}
		cfg.ConfigVersion = n
	case "server.host":
		cfg.Server.Host = value
	case "server.port":
		n, err := strconv.Atoi(value)
		if err != nil {
			return domain.New(domain.CodeConfigInvalidPort,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"port": value}),
			)
		}
		cfg.Server.Port = n
	case "server.allow_remote":
		b, err := parseBool(value)
		if err != nil {
			return badValue(key, value)
		}
		cfg.Server.AllowRemote = b
	case "log.level":
		cfg.Log.Level = value
	case "log.format":
		cfg.Log.Format = value
	case "store.path":
		cfg.Store.Path = value
	case "store.token_path":
		cfg.Store.TokenPath = value
	case "features.gates.token":
		b, err := parseBool(value)
		if err != nil {
			return badValue(key, value)
		}
		cfg.Features.Gates.Token = b
	case "features.gates.memory":
		b, err := parseBool(value)
		if err != nil {
			return badValue(key, value)
		}
		cfg.Features.Gates.Memory = b
	case "features.gates.security":
		b, err := parseBool(value)
		if err != nil {
			return badValue(key, value)
		}
		cfg.Features.Gates.Security = b
	case "passthrough.family":
		cfg.Passthrough.Family = value
	case "passthrough.base_url":
		cfg.Passthrough.BaseURL = value
	case "passthrough.api_key":
		cfg.Passthrough.APIKey = value
	case "passthrough.api_key_env":
		cfg.Passthrough.APIKeyEnv = value
	default:
		// The memory gates' parameter block (F4 wave 5, ADR-SEC-07).
		if ok, err := setMemoryGateParam(cfg, key, value); ok {
			return err
		}
		// The security gates' parameter block (F4 wave 5, ADR-SEC-03/05).
		if ok, err := setSecurityGateParam(cfg, key, value); ok {
			return err
		}
		// The F5.1 HTTP trust block (ADR-SEC-06).
		if ok, err := setHTTPSecurityParam(cfg, key, value); ok {
			return err
		}
		// A `[[providers]]` entry flattens to providers.<i>.<field>.
		if idx, field, ok := parseProviderKey(key); ok {
			return setProvider(cfg, idx, field, value)
		}
		// A token engine switch is
		// features.gates.token.engines.<name>.<field> (ADR-0015 §3/§6).
		if name, field, ok := parseTokenEngineKey(key); ok {
			return setTokenEngine(cfg, name, field, value)
		}
		// A per-gate switch is features.gates.<name> (ADR-0014 §4). The three
		// group switches are handled above, so anything else under
		// features.gates. is a gate name.
		if name, ok := parseGateSwitch(key); ok {
			b, err := parseBool(value)
			if err != nil {
				return badValue(key, value)
			}
			if cfg.Features.Gates.Enabled == nil {
				cfg.Features.Gates.Enabled = map[string]bool{}
			}
			cfg.Features.Gates.Enabled[name] = b
			return nil
		}
		// forward-compatible: ignore unknown keys
	}
	return nil
}

// setMemoryGateParam applies one features.gates.memory.* parameter key. It
// reports whether the key belonged to the block, so unknown keys keep falling
// through to the forward-compatible ignore.
func setMemoryGateParam(cfg *Config, key, value string) (bool, error) {
	const prefix = "features.gates.memory."
	if !strings.HasPrefix(key, prefix) {
		return false, nil
	}
	m := &cfg.Features.Gates.MemoryParams
	switch key {
	case prefix + "ttl":
		return true, setDurationParam(key, value, func(d time.Duration) { m.TTL = d })
	case prefix + "budget":
		return true, setDurationParam(key, value, func(d time.Duration) { m.Budget = d })
	case prefix + "retrieval_limit":
		return true, setIntParam(key, value, func(n int) { m.RetrievalLimit = n })
	case prefix + "max_content":
		return true, setIntParam(key, value, func(n int) { m.MaxContent = n })
	case prefix + "sink_capacity":
		return true, setIntParam(key, value, func(n int) { m.SinkCapacity = n })
	case prefix + "embeddings.base_url":
		m.Embeddings.BaseURL = value
		return true, nil
	case prefix + "embeddings.model":
		m.Embeddings.Model = value
		return true, nil
	case prefix + "embeddings.api_key_env":
		m.Embeddings.APIKeyEnv = value
		return true, nil
	case prefix + "embeddings.dim":
		return true, setIntParam(key, value, func(n int) { m.Embeddings.Dim = n })
	}
	return false, nil
}

// setHTTPSecurityParam applies one security.* key of the F5.1 HTTP trust block
// (ADR-SEC-06). List values are comma-separated (the same representation
// splitList produces from a TOML string array).
func setHTTPSecurityParam(cfg *Config, key, value string) (bool, error) {
	const prefix = "security."
	if !strings.HasPrefix(key, prefix) {
		return false, nil
	}
	sec := &cfg.Security
	switch key {
	case prefix + "require_client_key":
		b, err := parseBool(value)
		if err != nil {
			return true, badValue(key, value)
		}
		sec.RequireClientKey = b
	case prefix + "host_allowlist":
		sec.HostAllowlist = splitList(value)
	case prefix + "cors_allowed_origins":
		sec.CORSAllowedOrigins = splitList(value)
	case prefix + "management_login_rate_limit.rate":
		return true, setIntParam(key, value, func(n int) { sec.ManagementLoginRateLimit.Rate = n })
	case prefix + "management_login_rate_limit.interval":
		return true, setDurationParam(key, value, func(d time.Duration) { sec.ManagementLoginRateLimit.Interval = d })
	default:
		return false, nil
	}
	return true, nil
}

// setSecurityGateParam applies one features.gates.security.* parameter key.
func setSecurityGateParam(cfg *Config, key, value string) (bool, error) {
	const prefix = "features.gates.security."
	if !strings.HasPrefix(key, prefix) {
		return false, nil
	}
	sec := &cfg.Features.Gates.SecurityParams
	switch key {
	case prefix + "pii_policy":
		sec.PIIPolicy = strings.ToLower(strings.TrimSpace(value))
		return true, nil
	case prefix + "injection_policy":
		sec.InjectPolicy = strings.ToLower(strings.TrimSpace(value))
		return true, nil
	case prefix + "rate_limit.rate":
		return true, setIntParam(key, value, func(n int) { sec.RateLimit.Rate = n })
	case prefix + "rate_limit.interval":
		return true, setDurationParam(key, value, func(d time.Duration) { sec.RateLimit.Interval = d })
	}
	return false, nil
}

// setIntParam parses and stores one integer parameter with a typed error.
func setIntParam(key, value string, set func(int)) error {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return badValue(key, value)
	}
	set(n)
	return nil
}

// setDurationParam parses and stores one duration parameter with a typed error.
func setDurationParam(key, value string, set func(time.Duration)) error {
	d, err := parseDuration(value)
	if err != nil {
		return badValue(key, value)
	}
	set(d)
	return nil
}

// tokenEngineFields is the closed set of per-engine fields of the token gate.
var tokenEngineFields = map[string]bool{"enabled": true, "allow_prefix_rewrite": true}

// parseTokenEngineKey recognises
// features.gates.token.engines.<name>.<field> and returns the engine name and
// field. The name may contain dots; the field is the last segment and must be
// one of the known fields (ADR-0015 §3/§6), so a typo is ignored rather than
// silently setting nothing.
func parseTokenEngineKey(key string) (name, field string, ok bool) {
	const prefix = "features.gates.token.engines."
	if !strings.HasPrefix(key, prefix) {
		return "", "", false
	}
	rest := key[len(prefix):]
	dot := strings.LastIndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return "", "", false
	}
	engine, f := rest[:dot], rest[dot+1:]
	if !tokenEngineFields[f] {
		return "", "", false
	}
	return engine, f, true
}

// setTokenEngine writes one field of one token engine's config, growing the map.
func setTokenEngine(cfg *Config, name, field, value string) error {
	b, err := parseBool(value)
	if err != nil {
		return badValue("features.gates.token.engines."+name+"."+field, value)
	}
	if cfg.Features.Gates.TokenEngines == nil {
		cfg.Features.Gates.TokenEngines = map[string]TokenEngineConfig{}
	}
	ec := cfg.Features.Gates.TokenEngines[name]
	switch field {
	case "enabled":
		ec.Disabled = !b
	case "allow_prefix_rewrite":
		ec.AllowPrefixRewrite = b
	}
	cfg.Features.Gates.TokenEngines[name] = ec
	return nil
}

// parseGateSwitch recognises features.gates.<name> for a gate name that is NOT
// one of the three group switches (token/memory/security). The name is the last
// segment after "features.gates." and must be non-empty.
func parseGateSwitch(key string) (string, bool) {
	const prefix = "features.gates."
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	name := key[len(prefix):]
	switch name {
	case "token", "memory", "security", "":
		return "", false
	}
	if strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

// parseProviderKey splits "providers.<i>.<field>" into its parts. It returns
// ok=false for anything that is not a well-formed provider index key.
func parseProviderKey(key string) (index int, field string, ok bool) {
	const prefix = "providers."
	if !strings.HasPrefix(key, prefix) {
		return 0, "", false
	}
	rest := key[len(prefix):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return 0, "", false
	}
	i, err := strconv.Atoi(rest[:dot])
	if err != nil || i < 0 {
		return 0, "", false
	}
	return i, rest[dot+1:], true
}

// setProvider writes one field of the provider entry at index, growing the slice
// as needed. An unknown field is ignored (forward-compatible).
func setProvider(cfg *Config, index int, field, value string) error {
	for len(cfg.Providers) <= index {
		cfg.Providers = append(cfg.Providers, ProviderConfig{})
	}
	p := &cfg.Providers[index]
	switch field {
	case "id":
		p.ID = value
	case "base_url":
		p.BaseURL = value
	case "auth_header":
		p.AuthHeader = value
	case "allow_loopback":
		b, err := parseBool(value)
		if err != nil {
			return badValue("providers."+strconv.Itoa(index)+".allow_loopback", value)
		}
		p.AllowLoopback = b
	case "ttft":
		d, err := parseDuration(value)
		if err != nil {
			return badValue("providers."+strconv.Itoa(index)+".ttft", value)
		}
		p.TTFT = d
	case "idle":
		d, err := parseDuration(value)
		if err != nil {
			return badValue("providers."+strconv.Itoa(index)+".idle", value)
		}
		p.Idle = d
	case "enabled":
		b, err := parseBool(value)
		if err != nil {
			return badValue("providers."+strconv.Itoa(index)+".enabled", value)
		}
		p.Enabled = b
	case "models":
		p.Models = splitList(value)
	case "client_secret":
		p.ClientSecret = value
	case "client_secret_env":
		p.ClientSecretEnv = value
	default:
		// forward-compatible: ignore unknown provider fields
	}
	return nil
}

// splitList splits a comma-separated value into its non-empty, trimmed parts.
// It is the inverse of the comma-join flatten applies to a string array, so a
// provider's model list has one representation from TOML and from env.
func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseDuration parses a Go duration string ("30s", "2m"). An empty value means
// "unset" (zero).
func parseDuration(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}

func badValue(key, value string) error {
	return domain.New(domain.CodeConfigLoadFailed,
		domain.WithHTTPStatus(500),
		domain.WithParams(map[string]string{"reason": fmt.Sprintf("invalid value %q for %s", value, key)}),
	)
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean: %q", value)
}

// flatten turns a decoded TOML tree into dotted keys, stringifying leaves.
func flatten(in map[string]any) map[string]string {
	out := map[string]string{}
	var walk func(prefix string, node map[string]any)
	walk = func(prefix string, node map[string]any) {
		for k, v := range node {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			switch typed := v.(type) {
			case map[string]any:
				walk(key, typed)
			case []map[string]any:
				// An array of tables, e.g. [[providers]]. Flatten each element
				// to a zero-based index segment so the resolver can address
				// providers.0.id etc. without a second decoded representation.
				// A scalar array falls through to the default branch below and
				// is stringified there.
				for i, elem := range typed {
					walk(key+"."+strconv.Itoa(i), elem)
				}
			case []string:
				// A string list, e.g. providers.0.models. Join with commas so
				// the value layer has one representation whether it came from
				// TOML or an env var (splitList reverses it).
				out[key] = strings.Join(typed, ",")
			case []any:
				// A heterogeneous scalar array (TOML decodes ["a","b"] this
				// way). Stringify each element; the consumer splits on commas.
				parts := make([]string, 0, len(typed))
				for _, elem := range typed {
					parts = append(parts, fmt.Sprintf("%v", elem))
				}
				out[key] = strings.Join(parts, ",")
			case string:
				out[key] = typed
			case bool:
				out[key] = strconv.FormatBool(typed)
			case int64:
				out[key] = strconv.FormatInt(typed, 10)
			case float64:
				out[key] = strconv.FormatFloat(typed, 'f', -1, 64)
			case nil:
				// omit
			default:
				out[key] = fmt.Sprintf("%v", typed)
			}
		}
	}
	walk("", in)
	return out
}

func envLookup(env map[string]string, name string) string {
	if env == nil {
		return ""
	}
	return env[name]
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
