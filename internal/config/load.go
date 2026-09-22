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
	cfg := Defaults()

	fileVals, err := readFileValues(opts)
	if err != nil {
		return Config{}, err
	}

	// A config_version above this build's schema is refused outright; a lower
	// one is upgraded in place before any other key is applied.
	if v, ok := fileVals["config_version"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, domain.New(domain.CodeConfigInvalidVersion,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"version": v}),
			)
		}
		if n > CurrentConfigVersion {
			return Config{}, domain.New(domain.CodeConfigInvalidVersion,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"version": v}),
			)
		}
		if n < CurrentConfigVersion {
			if fileVals, err = upgradeFn(fileVals); err != nil {
				return Config{}, err
			}
		}
	}

	// Apply in ascending priority: defaults are already in cfg, then file,
	// then flags, then environment. Later layers win.
	for _, layer := range []map[string]string{fileVals, flagLayer(opts.Flags), envLayer(opts.Env)} {
		for _, k := range sortedKeys(layer) {
			if err := set(&cfg, k, layer[k]); err != nil {
				return Config{}, err
			}
		}
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
	"HEIMDALL_SERVER_HOST":             "server.host",
	"HEIMDALL_SERVER_PORT":             "server.port",
	"HEIMDALL_SERVER_ALLOW_REMOTE":     "server.allow_remote",
	"HEIMDALL_LOG_LEVEL":               "log.level",
	"HEIMDALL_LOG_FORMAT":              "log.format",
	"HEIMDALL_STORE_PATH":              "store.path",
	"HEIMDALL_STORE_TOKEN_PATH":        "store.token_path",
	"HEIMDALL_FEATURES_GATES_TOKEN":    "features.gates.token",
	"HEIMDALL_FEATURES_GATES_MEMORY":   "features.gates.memory",
	"HEIMDALL_FEATURES_GATES_SECURITY": "features.gates.security",
	"HEIMDALL_PASSTHROUGH_FAMILY":      "passthrough.family",
	"HEIMDALL_PASSTHROUGH_BASE_URL":    "passthrough.base_url",
	"HEIMDALL_PASSTHROUGH_API_KEY":     "passthrough.api_key",
	"HEIMDALL_PASSTHROUGH_API_KEY_ENV": "passthrough.api_key_env",
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
		}
	}
	return out
}

// providerEnvFields is the closed set of provider fields addressable via env.
var providerEnvFields = map[string]string{
	"ID":             "id",
	"BASE_URL":       "base_url",
	"AUTH_HEADER":    "auth_header",
	"ALLOW_LOOPBACK": "allow_loopback",
	"TTFT":           "ttft",
	"IDLE":           "idle",
	"ENABLED":        "enabled",
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
		// A `[[providers]]` entry flattens to providers.<i>.<field>.
		if idx, field, ok := parseProviderKey(key); ok {
			return setProvider(cfg, idx, field, value)
		}
		// forward-compatible: ignore unknown keys
	}
	return nil
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
	default:
		// forward-compatible: ignore unknown provider fields
	}
	return nil
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
