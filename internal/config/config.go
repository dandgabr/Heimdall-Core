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
	Security      Security
	Passthrough   Passthrough
	// Providers is the per-provider upstream configuration (the `[[providers]]`
	// block). It is file-driven; env can override individual fields via
	// HEIMDALL_PROVIDERS_<n>_<FIELD>, following the same precedence rule. An
	// empty list is valid: the built-in descriptors still register (listable),
	// and a provider without a base_url simply cannot build an executor yet.
	Providers []ProviderConfig
	// NOTE: combos are deliberately NOT a config block. Config declares
	// BOOTSTRAP and TRANSPORT (where a provider is, how to reach it); combos are
	// operator DATA that changes at runtime, so they live in the database like
	// credentials (ADR-0013 §1). Declaring them here would create a second
	// source of truth and a boot-time import path. See internal/combos.
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
	// Models is the set of model ids this provider serves. It is operator DATA
	// (like credentials/combos, ADR-0013 §1): the Router expands a model step and
	// a provider wildcard over the declared set, and a family that does not
	// declare a model reports Capabilities ok=false so the Router skips it
	// (ADR-0001). Empty means the provider declares no models and is not
	// routable until one is added.
	Models []string
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

// Security holds the F5.1 HTTP trust settings (ADR-SEC-06): client-key
// authentication of the inference gateway and the anti-rebinding/CSRF and CORS
// controls of the local surfaces.
type Security struct {
	// RequireClientKey makes the inference gateway (/v1/*) demand an
	// authenticated client key. The default is FALSE with a documented warning:
	// the product is a local personal router, and forcing every existing
	// OpenAI-compatible client to provision a key before the first request
	// would break the out-of-the-box experience the project promises. With the
	// flag ON, a request with no key (or an invalid/revoked one) is 401
	// clientkey.invalid. Operators who expose the gateway beyond loopback MUST
	// set it (ADR-SEC-06 §6.4: a tunnel/LAN transfers the risk to the operator).
	RequireClientKey bool
	// HostAllowlist is the set of EXTRA Host header values accepted in addition
	// to the built-in loopback forms (127.0.0.1, localhost, [::1], with or
	// without port). It exists for an allow-remote deployment whose configured
	// server.host is a name the browser sends verbatim. Empty means only the
	// loopback forms are accepted.
	HostAllowlist []string
	// CORSAllowedOrigins is the closed set of origins allowed to cross-call the
	// inference gateway (/v1/*). It NEVER includes a wildcard (ADR-SEC-06 §3.3
	// forbids `*`); an empty list disables CORS entirely. Management and GUI
	// origins are never cross-origin permissive.
	CORSAllowedOrigins []string
	// ManagementLoginRateLimit throttles failed management-token authentication
	// per client IP (ADR-SEC-06 §4.2): at most Rate failures per Interval, then
	// a Retry-After cooldown. Zero Rate disables it.
	ManagementLoginRateLimit RateLimitConfig
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
	// Enabled is the PER-GATE switch (ADR-0014 §4): a gate named here is
	// enabled/disabled individually, independent of the Token/Memory/Security
	// group switches. A gate absent from the map falls back to its group switch.
	// The switch layer declares only on/off — never order: the order is derived
	// from the gate graph (ADR-0014 §1); per-gate PARAMETERS live in the typed
	// blocks below (Memory/Security) and are consumed only by the gates.
	Enabled map[string]bool
	// TokenEngines is the token gate's per-ENGINE config (ADR-0015 §3/§6):
	// `features.gates.token.engines.<name>.enabled` and
	// `...allow_prefix_rewrite`. It is DATA for the token gate only; the core
	// never reads it.
	TokenEngines map[string]TokenEngineConfig
	// MemoryParams is the memory gates' parameter block (F4 wave 5, ADR-SEC-07):
	// `features.gates.memory.*`. It is DATA for the memory gates only; the
	// group switch is Memory (bool) above.
	MemoryParams MemoryGatesConfig
	// SecurityParams is the security gates' parameter block (F4 wave 5,
	// ADR-SEC-03/05): `features.gates.security.*`. The group switch is
	// Security (bool) above.
	SecurityParams SecurityGatesConfig
}

// MemoryGatesConfig carries the memory gates' documented parameters. Every
// zero value falls back to the gate's own safe default, so a partially
// populated block is valid.
type MemoryGatesConfig struct {
	// TTL is the retention of a stored memory (ADR-SEC-07 §4: episodic default
	// of 30 days). Zero → the gate's DefaultTTL. No memory is perennial.
	TTL time.Duration
	// RetrievalLimit caps how many memories one retrieval injects. Zero →
	// the gate default (3).
	RetrievalLimit int
	// Budget bounds ONE synchronous retrieval call (ADR-SEC-07 §1: 100ms).
	// Zero → the gate default. A store slower than the budget fail-opens.
	Budget time.Duration
	// MaxContent bounds one extracted/stored text in bytes. Zero → the gate
	// default (4096).
	MaxContent int
	// SinkCapacity bounds the async writer queue: pending memory writes before
	// backpressure starts DROPPING them. Zero → the gate default (64).
	SinkCapacity int
	// Embeddings is the vector-mode opt-in (ADR-SEC-07 §5). The zero value is
	// OFF (local-first: FTS5-only retrieval). A non-empty BaseURL turns the
	// opt-in ON and requires Model, Dim and an HTTPS URL (validated at boot;
	// the egress policy validates the destination again at client build).
	Embeddings EmbeddingsConfig
}

// EmbeddingsConfig is the opt-in external embedding engine.
type EmbeddingsConfig struct {
	// BaseURL is the embeddings API root. Empty = vector mode OFF.
	BaseURL string
	// Model is the provider's embedding model identifier.
	Model string
	// APIKeyEnv NAMES the environment variable holding the API key; the key
	// itself never appears in the config file.
	APIKeyEnv string
	// Dim is the expected vector dimensionality (a mismatch is an error, never
	// a silent truncation).
	Dim int
}

// SecurityGatesConfig carries the security gates' policies.
type SecurityGatesConfig struct {
	// PIIPolicy is the PII masker's behaviour on detection: "mask" (rewrites
	// the match into a typed placeholder — the default), "block" (refuses the
	// request listing only the detected types) or "off" (the gate is not
	// constructed). Empty → mask.
	PIIPolicy string
	// InjectPolicy is the injection guard's behaviour on a signature match:
	// "block" (refuses with a 400 synthetic — the default, FailClosed) or
	// "flag" (records the matched rule name and continues — FailOpen). Empty →
	// block.
	InjectPolicy string
	// RateLimit is the per-client-key throttle. The zero Rate keeps it OFF:
	// the burst size is an operator capacity decision with no safe default.
	RateLimit RateLimitConfig
}

// RateLimitConfig configures the token-bucket throttle: Rate requests per
// Interval, burst = Rate, refill = Rate/Interval per second. Rate 0 = off.
type RateLimitConfig struct {
	Rate int
	// Interval is the refill period. Zero (with Rate set) fails validation.
	Interval time.Duration
}

// TokenEngineConfig is the per-engine switch of the token gate (ADR-0015 §3/§6).
type TokenEngineConfig struct {
	// Disabled turns an individual engine off even when the token gate is on.
	Disabled bool
	// AllowPrefixRewrite is the operator's explicit opt-in for an ImpactHigh
	// engine (ADR-0015 §3). It is refused at registration when the engine is not
	// ImpactHigh.
	AllowPrefixRewrite bool
}

// TokenEngineEnabled reports whether a token engine runs. An unknown engine
// defaults to enabled (the gate's own default set); an explicit Disabled wins.
func (g GatesFeatures) TokenEngineEnabled(name string) bool {
	if ec, ok := g.TokenEngines[name]; ok {
		return !ec.Disabled
	}
	return true
}

// TokenEngineAllowPrefixRewrite reports the operator's opt-in for an engine.
func (g GatesFeatures) TokenEngineAllowPrefixRewrite(name string) bool {
	return g.TokenEngines[name].AllowPrefixRewrite
}

// GateEnabled reports whether an individual gate is enabled, given its group
// switch as the fallback. An explicit per-gate entry wins; otherwise the group
// switch decides. This is the single rule the composition root uses, so the core
// needs no change to add a gate.
func (g GatesFeatures) GateEnabled(name string, groupEnabled bool) bool {
	if g.Enabled != nil {
		if v, ok := g.Enabled[name]; ok {
			return v
		}
	}
	return groupEnabled
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
		// F5.1 defaults are SAFE and USABLE: client-key auth is off (a local
		// personal router must work out of the box) with a boot warning, no
		// extra Host/Origin names are trusted, CORS is closed, and the
		// management login throttle starts from a conservative 5 failures/min.
		Security: Security{
			RequireClientKey:         false,
			HostAllowlist:            nil,
			CORSAllowedOrigins:       nil,
			ManagementLoginRateLimit: RateLimitConfig{Rate: 5, Interval: time.Minute},
		},
		Features: GatesFeaturesConfig(false),
		Passthrough: Passthrough{
			Family:    "openai",
			BaseURL:   "",
			APIKeyEnv: "OPENAI_API_KEY",
		},
	}
}

// GatesFeaturesConfig builds the gates feature block with one switch and the
// documented parameter defaults (the gates re-default zero values themselves,
// but the shipped defaults are explicit so operators can see and override
// them).
func GatesFeaturesConfig(on bool) Features {
	return Features{Gates: GatesFeatures{
		Token: on, Memory: on, Security: on,
		MemoryParams: MemoryGatesConfig{
			TTL:            30 * 24 * time.Hour, // ADR-SEC-07 §4
			RetrievalLimit: 3,
			Budget:         100 * time.Millisecond, // ADR-SEC-07 §1
			MaxContent:     4096,
			SinkCapacity:   64,
			Embeddings:     EmbeddingsConfig{}, // vector OFF: local-first
		},
		SecurityParams: SecurityGatesConfig{
			PIIPolicy:    "mask",
			InjectPolicy: "block",
			RateLimit:    RateLimitConfig{}, // off: opt-in capacity decision
		},
	}}
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
	if err := validateSecurity(c.Security); err != nil {
		return err
	}
	return validateGates(c.Features.Gates)
}

// validateSecurity enforces the F5.1 HTTP trust shape (ADR-SEC-06). It is
// fail-closed on the one value that could silently widen the attack surface:
// a CORS wildcard. Everything else is a conservative shape check.
func validateSecurity(s Security) error {
	for _, origin := range s.CORSAllowedOrigins {
		if strings.TrimSpace(origin) == "*" {
			return configProviderError("cors_allowed_origins must not contain a wildcard",
				map[string]string{"value": origin})
		}
		// An origin is scheme://host[:port]; reject a bare host or a path so a
		// malformed entry cannot be interpreted loosely.
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return configProviderError("cors_allowed_origins entries must be full origins",
				map[string]string{"value": origin})
		}
	}
	for _, host := range s.HostAllowlist {
		if strings.TrimSpace(host) == "" {
			return configProviderError("host_allowlist must not contain an empty entry", nil)
		}
	}
	if s.ManagementLoginRateLimit.Rate < 0 {
		return configProviderError("negative security.management_login_rate_limit.rate", nil)
	}
	if s.ManagementLoginRateLimit.Rate > 0 && s.ManagementLoginRateLimit.Interval <= 0 {
		return configProviderError("management_login_rate_limit.rate set without a positive interval", nil)
	}
	return nil
}

// validateGates enforces the shape of the gate parameter blocks (fail-closed:
// an unknown policy name is a config error, never a silent fallback — a typo'd
// "blok" must not boot as if the operator had chosen the default).
func validateGates(g GatesFeatures) error {
	switch strings.ToLower(g.SecurityParams.PIIPolicy) {
	case "", "mask", "block", "off":
	default:
		return configProviderError("invalid features.gates.security.pii_policy",
			map[string]string{"value": g.SecurityParams.PIIPolicy})
	}
	switch strings.ToLower(g.SecurityParams.InjectPolicy) {
	case "", "block", "flag":
	default:
		return configProviderError("invalid features.gates.security.injection_policy",
			map[string]string{"value": g.SecurityParams.InjectPolicy})
	}
	if g.SecurityParams.RateLimit.Rate < 0 {
		return configProviderError("negative features.gates.security.rate_limit.rate",
			map[string]string{"value": strconv.Itoa(g.SecurityParams.RateLimit.Rate)})
	}
	if g.SecurityParams.RateLimit.Rate > 0 && g.SecurityParams.RateLimit.Interval <= 0 {
		return configProviderError("rate_limit.rate set without a positive interval",
			map[string]string{"rate": strconv.Itoa(g.SecurityParams.RateLimit.Rate)})
	}
	if g.MemoryParams.TTL < 0 || g.MemoryParams.Budget < 0 {
		return configProviderError("negative memory ttl/budget", nil)
	}
	if g.MemoryParams.RetrievalLimit < 0 || g.MemoryParams.MaxContent < 0 || g.MemoryParams.SinkCapacity < 0 {
		return configProviderError("negative memory limit", nil)
	}
	emb := g.MemoryParams.Embeddings
	if strings.TrimSpace(emb.BaseURL) == "" {
		return nil // vector mode OFF: nothing else to validate
	}
	if strings.TrimSpace(emb.Model) == "" || emb.Dim <= 0 {
		return configProviderError("embeddings opt-in requires model and a positive dim",
			map[string]string{"model": emb.Model, "dim": strconv.Itoa(emb.Dim)})
	}
	// The same scheme/host policy the egress layer applies at client build
	// time (ADR-SEC-05): an http:// or private destination is refused at boot
	// rather than silently downgraded to "vector off".
	if _, err := egress.ValidateUpstreamURL(emb.BaseURL); err != nil {
		return configProviderError("embeddings base_url fails the egress policy",
			map[string]string{"url": emb.BaseURL})
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
	if params == nil {
		params = map[string]string{}
	}
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
