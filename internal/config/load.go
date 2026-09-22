package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// ConfigEnvVar names the environment variable pointing at an explicit config
// file, equivalent to passing --config.
const ConfigEnvVar = "HEIMDALL_CONFIG"

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
			if fileVals, err = Upgrade(fileVals); err != nil {
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
			if _, err := os.Stat(name); err == nil {
				path = name
				break
			}
		}
	}
	if path == "" {
		return map[string]string{}, nil
	}

	if _, err := os.Stat(path); err != nil {
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
// variables are ignored; adding a key means adding it to envKeyMap.
func envLayer(env map[string]string) map[string]string {
	out := map[string]string{}
	for name, value := range env {
		key, ok := envKeyMap[strings.ToUpper(name)]
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
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
		// forward-compatible: ignore unknown keys
	}
	return nil
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
