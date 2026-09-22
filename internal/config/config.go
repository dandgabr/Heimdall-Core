// Package config resolves the runtime configuration of Heimdall Core.
//
// Format: TOML. Chosen over YAML because the config surface is small, flat and
// operator-facing, and TOML gives it explicit types, comments and table nesting
// with a single small dependency (BurntSushi/toml) instead of the larger,
// more error-prone YAML footprint. It is also the format systemd and most
// desktop tooling treat as first-class.
//
// Precedence is fixed at env > flag > file > default (see load.go), and the
// resolution is done over a flat, string-keyed map so the rule is applied
// uniformly to every field and is directly unit-testable.
package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// CurrentConfigVersion is the schema version this build understands. A file
// declaring a higher version is rejected; a lower one is run through the
// upgrader (upgrade.go).
const CurrentConfigVersion = 1

// LoopbackHost is the default and only permitted bind when allow_remote is off.
const LoopbackHost = "127.0.0.1"

// Config is the fully resolved, validated configuration.
type Config struct {
	ConfigVersion int
	Server        Server
	Log           Log
	Store         Store
	Features      Features
	Passthrough   Passthrough
}

// Server holds the HTTP listener settings.
type Server struct {
	// Host is the bind address. Defaults to loopback; a non-loopback bind
	// additionally requires AllowRemote (see Validate).
	Host string
	Port int
	// AllowRemote must be explicitly enabled before the process will bind a
	// non-loopback address. Default false (ADR-003 / SEC-04).
	AllowRemote bool
}

// Addr returns the canonical host:port the listener binds.
//
// The address is composed with net.JoinHostPort rather than fmt.Sprintf, because
// an unbracketed IPv6 literal is invalid as a dial/listen address: "::1:8787"
// makes net.Listen fail with "too many colons in address". JoinHostPort adds the
// brackets for a host containing ':' and leaves an IPv4 literal or hostname
// untouched.
//
// Factual correction to the original note: JoinHostPort does NOT accept an
// already-bracketed host — it would produce the double-bracketed "[[::1]]:8787"
// (verified in this session). So the host is canonicalised first, stripping any
// brackets, and the two forms "::1" and "[::1]" both resolve to "[::1]:8787".
func (s Server) Addr() string {
	return net.JoinHostPort(s.canonicalHost(), strconv.Itoa(s.Port))
}

// canonicalHost returns Host without surrounding whitespace or IPv6 brackets,
// the input form net.JoinHostPort and net.ParseIP both expect.
func (s Server) canonicalHost() string {
	return strings.Trim(strings.TrimSpace(s.Host), "[]")
}

// IsLoopback reports whether Host is a loopback address.
//
// The check is deliberately strict: only an IP literal that net.IP.IsLoopback
// accepts (127.0.0.0/8, ::1, and the full form 0:0:0:0:0:0:0:1) or the exact
// name "localhost" qualifies. Any other hostname is rejected. A prefix test such
// as strings.HasPrefix(h, "127.") would accept "127.evil.com": the resolver
// would then send the bind to a real network interface and defeat the SEC-04
// control with allow_remote=false.
// An empty or unspecified host ("0.0.0.0", "::") is NOT loopback.
func (s Server) IsLoopback() bool {
	h := s.canonicalHost()
	if h == "" {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		// Not an IP literal: a hostname other than localhost must be refused,
		// never resolved.
		return false
	}
	return ip.IsLoopback()
}

// Log holds the structured logger settings.
type Log struct {
	// Level is one of debug, info, warn, error.
	Level string
	// Format is "text" or "json".
	Format string
}

// Store holds the SQLite settings.
type Store struct {
	Path string
	// TokenPath is where the management token is written (0600) on first start
	// and on rotation. The plaintext is never persisted in the database.
	TokenPath string
}

// Features is the master switchboard for optional modules. A disabled feature
// must be inert: its package is not wired in, not merely a runtime no-op.
type Features struct {
	Gates GatesFeatures
}

// GatesFeatures controls the gate pipeline stages.
type GatesFeatures struct {
	Token    bool
	Memory   bool
	Security bool
}

// Passthrough is the F0.7 end-to-end provider. It is a single hardcoded
// openai-compatible upstream; F1 replaces it with the provider registry.
type Passthrough struct {
	// Family is the protocol family, e.g. "openai".
	Family string
	// BaseURL is the upstream root, e.g. https://api.openai.com/v1.
	BaseURL string
	// APIKey is a directly supplied key. Prefer APIKeyEnv so the key never
	// lands in a config file.
	APIKey string
	// APIKeyEnv names the environment variable holding the key.
	APIKeyEnv string
}

// Resolve returns the API key, preferring the direct value then the named env
// var. It returns "" when neither is configured.
func (p Passthrough) Resolve(env map[string]string) string {
	if p.APIKey != "" {
		return p.APIKey
	}
	if p.APIKeyEnv != "" {
		return env[p.APIKeyEnv]
	}
	return ""
}

// Defaults returns the built-in configuration. Every field is populated so the
// resolver only ever has to overlay present values on top.
func Defaults() Config {
	return Config{
		ConfigVersion: CurrentConfigVersion,
		Server: Server{
			Host:        LoopbackHost,
			Port:        8787,
			AllowRemote: false,
		},
		Log: Log{
			Level:  "info",
			Format: "text",
		},
		Store: Store{
			Path:      defaultStorePath(),
			TokenPath: defaultTokenPath(),
		},
		Features: GatesFeaturesConfig(false),
		Passthrough: Passthrough{
			Family:    "openai",
			BaseURL:   "",
			APIKeyEnv: "OPENAI_API_KEY",
		},
	}
}

// GatesFeaturesConfig builds the gates feature block with one switch.
func GatesFeaturesConfig(on bool) Features {
	return Features{Gates: GatesFeatures{Token: on, Memory: on, Security: on}}
}

// Validate enforces the ADR-003 bind invariant and shape of every field. It
// returns a *domain.DomainError carrying an i18n code, never a bare error.
func (c Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return domain.New(domain.CodeConfigInvalidPort,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"port": strconv.Itoa(c.Server.Port)}),
		)
	}
	// A non-loopback bind is only reachable through an explicit opt-in. This is
	// the check that stops a config producing 0.0.0.0 from silently exposing the
	// management API.
	if !c.Server.IsLoopback() && !c.Server.AllowRemote {
		return domain.New(domain.CodeConfigBindNotLoopback,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"host": c.Server.Host}),
		)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return domain.New(domain.CodeConfigLoadFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "invalid log.level: " + c.Log.Level}),
		)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return domain.New(domain.CodeConfigLoadFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "invalid log.format: " + c.Log.Format}),
		)
	}
	if strings.TrimSpace(c.Store.Path) == "" {
		return domain.New(domain.CodeConfigLoadFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "store.path is empty"}),
		)
	}
	return nil
}

// defaultStorePath resolves the per-user data directory. Fallback to the
// working directory keeps the daemon usable on systems without an XDG home.
func defaultStorePath() string {
	return filepath.Join(defaultDataDir(), "heimdall.db")
}

// defaultTokenPath places the token file next to the database.
func defaultTokenPath() string {
	return filepath.Join(defaultDataDir(), "management-token")
}

func defaultDataDir() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "."
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "heimdall")
}
