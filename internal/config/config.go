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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
)

// CurrentConfigVersion is the schema version this build understands. A file
// declaring a higher version is rejected; a lower one is run through the
// upgrader (upgrade.go).
//
// The `[[providers]]` block did NOT require a version bump: it is ADDITIVE
// (an older file with no providers still loads, and a newer file's provider keys
// are ignored by an older build through the forward-compatible `set` default),
// and the resolver already ignores unknown keys. The upgrader therefore stays a
// no-op at v1. A future REMOVAL or SEMANTIC change to an existing key would need
// a bump and a migration in Upgrade.
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
	// Providers is the per-provider upstream configuration (the `[[providers]]`
	// block). It is file-driven; env can override individual fields via
	// HEIMDALL_PROVIDERS_<n>_<FIELD>, following the same precedence rule. An
	// empty list is valid: the built-in descriptors still register (listable),
	// and a provider without a base_url simply cannot build an executor yet.
	Providers []ProviderConfig
}

// ProviderConfig configures ONE provider's upstream transport (ADR-SEC-05).
// It is deliberately data: the composition root turns it into an
// OpenAICompatOptions, and the family's BuildExecutor refuses an empty BaseURL.
type ProviderConfig struct {
	// ID is the ProviderID this entry configures (e.g. "z.ai").
	ID string
	// BaseURL is the upstream root, e.g. https://api.z.ai/api/paas/v4. It is
	// validated at load time: HTTPS unless it is an explicit loopback literal
	// with AllowLoopback set (ADR-SEC-05 §2).
	BaseURL string
	// AuthHeader is "bearer" (Authorization: Bearer) or "x-api-key". Empty
	// means bearer.
	AuthHeader string
	// AllowLoopback unlocks the loopback exception for a local runtime. It is
	// only legal for an explicit loopback IP literal in BaseURL.
	AllowLoopback bool
	// TTFT bounds time-to-first-token. Zero uses the executor default.
	TTFT time.Duration
	// Idle bounds the gap between stream chunks. Zero disables the idle guard.
	Idle time.Duration
	// Enabled marks the provider as intended for use. An enabled provider MUST
	// have a BaseURL (fail-closed at Validate): silently registering a family
	// that can never execute would be a trap.
	Enabled bool
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
	if err := validateProviders(c.Providers); err != nil {
		return err
	}
	return nil
}

// validAuthHeaders is the closed set of auth-header styles a provider entry may
// declare. "" defaults to bearer.
var validAuthHeaders = map[string]bool{"": true, "bearer": true, "x-api-key": true}

// validateProviders enforces the ADR-SEC-05 shape of every `[[providers]]`
// entry. It is fail-closed:
//
//   - an enabled provider MUST have a BaseURL;
//   - a BaseURL MUST pass the same scheme/host policy the egress layer applies
//     (HTTPS, or an explicit loopback literal only when AllowLoopback is set);
//   - AllowLoopback MUST NOT be set for a non-loopback host (a decorative
//     opt-in would silently widen the dial policy);
//   - auth_header MUST be one of the known styles.
//
// A disabled provider with no base_url is allowed (it may be declared ahead of
// its endpoint); it simply will not build an executor.
func validateProviders(list []ProviderConfig) error {
	for i, p := range list {
		if strings.TrimSpace(p.ID) == "" {
			return configProviderError("provider entry has an empty id", map[string]string{"index": strconv.Itoa(i)})
		}
		if !validAuthHeaders[p.AuthHeader] {
			return configProviderError("invalid auth_header",
				map[string]string{"id": p.ID, "value": p.AuthHeader})
		}
		if p.Enabled && strings.TrimSpace(p.BaseURL) == "" {
			return configProviderError("enabled provider has no base_url",
				map[string]string{"id": p.ID})
		}
		if strings.TrimSpace(p.BaseURL) == "" {
			// A disabled provider may omit base_url; nothing else to check.
			continue
		}
		loopbackLiteral, err := egress.ValidateUpstreamURL(p.BaseURL)
		if err != nil {
			return configProviderError("base_url rejected by the egress policy",
				map[string]string{"id": p.ID})
		}
		// AllowLoopback is only ever meaningful for a loopback literal; setting
		// it otherwise is a misconfiguration that would look like a live
		// exception.
		if p.AllowLoopback && !loopbackLiteral {
			return configProviderError("allow_loopback requires a loopback literal base_url",
				map[string]string{"id": p.ID})
		}
		// A cleartext (http) base_url is legal ONLY for an explicit loopback
		// literal with the opt-in. ValidateUpstreamURL accepts the loopback http
		// form because the POLICY decides the exception from the spec flag; the
		// config layer must enforce the flag here, or a loopback http URL would
		// slip through with AllowLoopback false (ADR-SEC-05 §2).
		if isCleartextURL(p.BaseURL) && !(p.AllowLoopback && loopbackLiteral) {
			return configProviderError("http base_url requires allow_loopback with a loopback literal",
				map[string]string{"id": p.ID})
		}
	}
	return nil
}

func configProviderError(reason string, params map[string]string) error {
	params["reason"] = reason
	return domain.New(domain.CodeConfigLoadFailed,
		domain.WithHTTPStatus(500),
		domain.WithParams(params),
	)
}

// isCleartextURL reports whether raw is an http:// (not https://) URL. A parse
// failure is treated as cleartext (fail-closed): ValidateUpstreamURL has already
// rejected a malformed URL, so this only ever runs on a URL it accepted.
func isCleartextURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	return !strings.EqualFold(u.Scheme, "https")
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
