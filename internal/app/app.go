// Package app is the composition root.
//
// It is the ONLY package allowed to import every other internal package; the
// leaves (domain, i18n, contracts) never import it, which is what keeps the
// dependency graph acyclic. Everything a phase adds is wired here and nowhere
// else.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/api/mgmt"
	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/api/openai"
	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/breaker"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/dispatcher"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
	"github.com/dandgabr/heimdall-core/internal/executors"
	"github.com/dandgabr/heimdall-core/internal/gates"
	"github.com/dandgabr/heimdall-core/internal/gates/memory"
	"github.com/dandgabr/heimdall-core/internal/gates/security"
	"github.com/dandgabr/heimdall-core/internal/gates/token"
	"github.com/dandgabr/heimdall-core/internal/gateway"
	"github.com/dandgabr/heimdall-core/internal/i18n"
	"github.com/dandgabr/heimdall-core/internal/importers"
	"github.com/dandgabr/heimdall-core/internal/observability"
	"github.com/dandgabr/heimdall-core/internal/passthrough"
	"github.com/dandgabr/heimdall-core/internal/pipeline"
	"github.com/dandgabr/heimdall-core/internal/providers"
	"github.com/dandgabr/heimdall-core/internal/quota"
	"github.com/dandgabr/heimdall-core/internal/router"
	"github.com/dandgabr/heimdall-core/internal/secret"
	"github.com/dandgabr/heimdall-core/internal/store"
	"github.com/dandgabr/heimdall-core/internal/webui"
)

// App holds the assembled components of a running instance.
type App struct {
	Config config.Config
	Store  *store.Store
	Logger *slog.Logger
	Bundle *i18n.Bundle

	// F1 vault layer. Secrets is nil when the vault holds no credentials yet
	// and no KEK is configured: a fresh install must boot without a key.
	Secrets     *secret.Store
	Credentials *store.CredentialStore
	// ClientKeys persists the downstream client keys of the inference gateway
	// (F5.1, ADR-SEC-06 §2). Hash-only, like the management token.
	ClientKeys *store.ClientKeyStore
	// loginThrottle is the per-IP failed-auth throttle of the management API
	// (ADR-SEC-06 §4.2). It is built ONCE (in wireVault) and shared by every
	// Handler() call, so its bucket state survives across requests — a
	// per-Handler instance would reset the counter on every call and never
	// throttle. A test may set it before calling Handler().
	loginThrottle *middleware.LoginThrottle
	// rotationThrottle is the management-token rotation frequency lock
	// (ADR-SEC-06 §4.2, 1/5s). Built ONCE for the same reason as loginThrottle:
	// a per-Handler instance would forget the last rotation and never throttle.
	rotationThrottle *mgmt.RotationThrottle
	Providers        *providers.Registry
	Flows            *auth.FlowFactory
	// Gates is the frozen gate chain, wired with the F1 logger gate.
	Gates *pipeline.Chain
	// GateOrder is the per-stage order the gate registry computed at boot
	// (ADR-0014 §1). It is diagnostics and test surface: the chain executes
	// from it, and `gate` diagnostics can print the derived order.
	GateOrder gates.Order

	// F3 routing layer.
	Combos    *store.ComboStore
	Router    *router.Resolver
	Breaker   *breaker.Breaker
	QuotaRec  *quota.Recorder
	QuotaFilt *quota.Filter
	// QuotaStore is the durable quota/usage persistence. It is also the read
	// path for the management API's usage rollup (AggregateUsage), which sums
	// the idempotent attempt log on demand.
	QuotaStore *store.QuotaStore
	Dispatcher *dispatcher.Dispatcher
	// Gateway is the minimal inference handler (POST /v1/chat/completions).
	Gateway *gateway.Handler

	// F5.2 management surface state.
	// version is the build version reported by GET /api/mgmt/status.
	version string
	// startedAt is the boot instant; uptime is derived from it.
	startedAt time.Time

	env    map[string]string
	server *http.Server
	// descriptor resolves a provider's static descriptor. It defaults to
	// auth.Descriptor; it is a field so a test can inject a fake (e.g. a
	// non-future OAuth descriptor) without mutating the real catalog.
	descriptor func(domain.ProviderID) (contracts.ProviderDescriptor, error)
	// sealer overrides the API-key sealer in tests (nil = use a.Secrets).
	sealer apiKeySealer

	// gateRecords is written by the gate sink, which runs on EVERY request
	// goroutine, and read by GateRecords. It must be guarded: net/http serves
	// requests concurrently, so an unchecked append would race the slice header
	// (and growslice) against readers. gateMu is held for the whole read/write.
	gateMu      sync.Mutex
	gateRecords []map[string]string
}

// Options are the inputs to Build.
type Options struct {
	Config config.Config
	// Env is the environment snapshot used to resolve passthrough credentials.
	Env map[string]string
	// LogOutput overrides the logger destination (tests, CLI).
	LogOutput io.Writer
	// SecretOptions overrides custody resolution. Tests inject a KEK directly;
	// production leaves it zero so the custody chain runs.
	SecretOptions *secret.Options
	// FlowDeps overrides the OAuth client dependencies (HTTP client, clock).
	// Production leaves it zero; tests inject an httptest-backed client.
	FlowDeps *oauth.ClientDeps
	// Version is the build version reported by the management API and the CLI.
	// Empty falls back to "dev" so a build without -ldflags still reports one.
	Version string
}

// appSeams groups the injectable construction steps Build performs. Production
// uses the defaults; a test swaps one to reach an error branch that a healthy
// process cannot provoke (e.g. an i18n catalog failure, which the embedded FS
// makes impossible).
type appSeams struct {
	LoadBundle  func() (*i18n.Bundle, error)
	OpenStore   func(string) (*store.Store, error)
	EnsureToken func(*store.Store) (string, bool, error)
	NewChain    func([]contracts.Gate) (*pipeline.Chain, error)
	// NewOrderedChain builds the chain from the per-stage order the gate
	// registry computed (ADR-0014). It is a seam for the chain-error branch.
	NewOrderedChain func(pre, chunk, post []contracts.Gate) (*pipeline.Chain, error)
	NewObserver     func(*pipeline.Chain) (*pipeline.Observer, error)
	// NewRegistry and BuildGateOrder are seams over the gate engine, so a test
	// can force a registration/build failure a healthy registry never produces.
	NewRegistry    func() gateRegistry
	BuildGateOrder func(gateRegistry) (gates.Order, error)
	// TokenEngines is a seam over the built-in token engine set, so a test can
	// inject an incoherent engine and reach buildTokenGate's validation error.
	TokenEngines func() []token.CompressionEngine
	// Descriptors supplies the provider descriptors the registry is built from.
	// It is a seam so a test can feed an invalid or duplicate descriptor and
	// reach the registry-loop error branches; production uses the fixed set.
	Descriptors func() map[domain.ProviderID]contracts.ProviderDescriptor
	// HasCredentials reads whether the vault holds any credential. It is a seam
	// for the vault-read error branch.
	HasCredentials func(*store.CredentialStore) (bool, error)
	// ShutdownServer drains the HTTP server on Run's cancellation. It is a seam
	// for the shutdown-error branch.
	ShutdownServer func(*http.Server, context.Context) error
	// CloseStore releases the store on Close. It is a seam for the
	// store-close-error branch.
	CloseStore func(*store.Store) error
	// WireRouting builds the F3 routing layer. It is a seam so a test can force
	// a construction failure (which a healthy registry never produces) and prove
	// the boot fails closed by closing the store.
	WireRouting func(*App) error
}

var defaultAppSeams = appSeams{
	LoadBundle:      i18n.New,
	OpenStore:       store.Open,
	EnsureToken:     func(s *store.Store) (string, bool, error) { return s.EnsureManagementTokenHash() },
	NewChain:        pipeline.New,
	NewOrderedChain: pipeline.NewOrdered,
	NewObserver:     pipeline.NewObserver,
	NewRegistry:     func() gateRegistry { return gates.NewRegistry() },
	BuildGateOrder:  func(r gateRegistry) (gates.Order, error) { return r.Build() },
	TokenEngines:    token.DefaultEngines,
	Descriptors:     auth.Descriptors,
	HasCredentials: func(cs *store.CredentialStore) (bool, error) {
		creds, err := cs.List(context.Background())
		if err != nil {
			return false, err
		}
		return len(creds) > 0, nil
	},
	ShutdownServer: func(s *http.Server, ctx context.Context) error { return s.Shutdown(ctx) },
	CloseStore:     func(s *store.Store) error { return s.Close() },
	WireRouting:    func(a *App) error { return a.wireRouting() },
}

// gateRegistry is the narrow view of *gates.Registry the composition root uses,
// so the registry and its order build are injectable seams.
type gateRegistry interface {
	RegisterGate(name string, factory gates.Factory) error
	Build() (gates.Order, error)
}

// appSeam is swapped by tests; never mutated in production.
var appSeam = defaultAppSeams

// Build constructs the application: store, logger, i18n bundle and the HTTP
// handler graph, without starting the listener.
func Build(opts Options) (*App, error) {
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	bundle, err := appSeam.LoadBundle()
	if err != nil {
		return nil, err
	}

	logger := observability.New(observability.Options{
		Level:    cfg.Log.Level,
		Format:   cfg.Log.Format,
		Output:   opts.LogOutput,
		Redactor: i18n.Redacter{},
		Service:  "heimdall",
	})

	st, err := appSeam.OpenStore(cfg.Store.Path)
	if err != nil {
		return nil, err
	}

	// The management token is generated once and written to a 0600 file. Neither
	// the value nor a recoverable form of it is ever logged: the database stores
	// only its SHA-256 hash (store.EnsureManagementTokenHash). The i18n message
	// carries the file path, never the token.
	token, created, err := appSeam.EnsureToken(st)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if created {
		if err := store.WriteTokenFile(cfg.Store.TokenPath, token); err != nil {
			_ = st.Close()
			return nil, err
		}
		logger.Info(bundle.Format(i18n.DefaultLanguage,
			domain.CodeStartupTokenReady,
			map[string]string{"path": cfg.Store.TokenPath}))
	}

	version := opts.Version
	if version == "" {
		version = "dev"
	}
	app := &App{
		Config:     cfg,
		Store:      st,
		Logger:     logger,
		Bundle:     bundle,
		env:        opts.Env,
		descriptor: auth.Descriptor,
		version:    version,
		startedAt:  time.Now(),
	}

	// The ADR-SEC-06 §6.2 startup warnings. They are OBSERVABILITY, not
	// refusals: the operator deliberately chose the exposure (config.Validate
	// already required the explicit allow_remote opt-in), and the point is that
	// the posture is never silent.
	if cfg.Server.AllowRemote {
		logger.Warn(bundle.Format(i18n.DefaultLanguage,
			domain.CodeStartupWarningRemoteAccess, nil))
	}
	// With the gateway reachable from more than loopback, an unauthenticated
	// /v1/* is a real risk (any local or LAN process can spend paid quota).
	// Warn when remote access is on and client-key auth is off.
	if cfg.Server.AllowRemote && !cfg.Security.RequireClientKey {
		logger.Warn("security.require_client_key is false while allow_remote is on; " +
			"the inference gateway is unauthenticated on the network")
	}

	// Build the F1 vault layer. The rule is precise:
	//
	//   - a FRESH vault (no credentials) boots WITHOUT a KEK: requiring a key
	//     before there is anything to encrypt would make first-run unusable;
	//   - a vault WITH credentials REQUIRES a KEK, and its absence is
	//     config.secret_missing (ADR-SEC-01, fail-closed). Without this the
	//     daemon would come up and the first decrypt would fail at request time.
	if err := app.wireVault(opts); err != nil {
		_ = st.Close()
		return nil, err
	}

	// Build the F3 routing layer AFTER the vault, so the executor factory sees
	// the resolved SecretStore (the executor opens a credential's sealed blob
	// through it). A construction failure is fatal at boot.
	if err := appSeam.WireRouting(app); err != nil {
		_ = st.Close()
		return nil, err
	}

	app.server = &http.Server{
		Addr:              cfg.Server.Addr(),
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return app, nil
}

// wireVault builds the CredentialStore, the provider registry and the flow
// factory, resolving the KEK through the custody chain when the vault holds
// credentials (or when the operator has configured a key explicitly).
func (a *App) wireVault(opts Options) error {
	st := a.Store
	logger := a.Logger

	a.Credentials = store.NewCredentialStore(st)
	a.ClientKeys = store.NewClientKeyStore(st)
	a.loginThrottle = middleware.NewLoginThrottle(
		a.Config.Security.ManagementLoginRateLimit.Rate,
		a.Config.Security.ManagementLoginRateLimit.Interval,
		nil,
	)
	a.rotationThrottle = mgmt.NewRotationThrottle(mgmt.DefaultRotationWindow, nil)

	// The provider registry is always available: listing providers needs no key.
	//
	// Each family is built with the per-provider transport config ([[providers]]):
	// BaseURL, auth header and the loopback exception. A provider with no base_url
	// still registers (listable), but BuildExecutor refuses it until one is set;
	// an ENABLED provider with no base_url was already rejected by
	// Config.Validate (fail-closed), so it never reaches here.
	byID := make(map[domain.ProviderID]config.ProviderConfig, len(a.Config.Providers))
	for _, pc := range a.Config.Providers {
		byID[domain.ProviderID(pc.ID)] = pc
	}
	registry := providers.NewRegistry()
	for _, desc := range appSeam.Descriptors() {
		pc := byID[desc.ID]
		family, err := buildFamily(desc, pc)
		if err != nil {
			return err
		}
		if err := registry.Register(family); err != nil {
			return err
		}
	}
	a.Providers = registry

	// The flow factory needs the ADR-SEC-05 egress policy plus a clock; it holds
	// no key material. EVERY OAuth call (token exchange, device polling,
	// userinfo, loadCodeAssist, onboarding, refresh) builds its client from this
	// policy, so TLS verification, the SSRF dial-time denylist and redirect
	// blocking apply to OAuth exactly as to inference. A real OAuth endpoint is
	// always HTTPS, so loopback stays disabled.
	//
	// Injected deps (tests) win; a test that supplies only HTTP leaves Egress
	// nil, and the injected client is used. If neither is set the flow fails
	// closed (it never falls back to http.DefaultClient).
	flowDeps := oauth.ClientDeps{Egress: egress.New(), Clock: systemClock{}}
	if opts.FlowDeps != nil {
		flowDeps = *opts.FlowDeps
		if flowDeps.Clock == nil {
			flowDeps.Clock = systemClock{}
		}
		if flowDeps.Egress == nil && flowDeps.HTTP == nil {
			flowDeps.Egress = egress.New()
		}
	}
	// The per-provider OAuth client secrets come from config/env, never from a
	// hardcoded literal (removed for secret-scanning reasons). The factory
	// fails closed per provider when a required secret is absent; the values
	// are never logged.
	clientSecrets := config.ResolveClientSecrets(a.Config.Providers, a.env)
	a.Flows = auth.NewFlowFactoryWithSecrets(flowDeps, clientSecrets)

	// Build the gate chain with the F1 logger gate. Its sink records metadata
	// for tests and feeds the structured logger in production; it never sees a
	// body or a header value.
	if err := a.wireGates(); err != nil {
		return err
	}

	hasCreds, err := appSeam.HasCredentials(a.Credentials)
	if err != nil {
		return err
	}

	if opts.SecretOptions != nil {
		sec, err := secret.New(*opts.SecretOptions)
		if err != nil {
			return err
		}
		a.Secrets = sec
		return nil
	}

	// Resolve the custody chain only when it is actually required. A fresh
	// vault with no key configured stays usable (Secrets nil); that is the
	// "boot must not fail for lack of credentials" rule.
	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		return err
	}
	// LoadOrCreateSalt persists the salt lazily; on a fresh vault this creates
	// the row, which is fine and required before the first seal.

	custody := secret.Custody{
		Env: a.env,
		// Resolve the key-file path against the SAME injected environment the
		// custody chain reads, never the process environment: a test that runs
		// with an empty env must not see the host operator's real key file
		// (F5-1 hermeticity). Production injects the full process snapshot, so
		// the result is identical there.
		KeyFilePath:      secret.DefaultKeyFilePathFor(a.env),
		AllowEnvOverride: false, // env only via explicit opt-in, never by default
		Logger:           logger,
	}
	if !hasCreds {
		// No credentials yet: attempt resolution but tolerate absence, because
		// there is nothing to decrypt. Only an EXPLICITLY configured key that
		// fails to load is an error.
		sec, resolveErr := secret.New(secret.Options{Salt: salt, Params: secret.DefaultKDFParams, Custody: custody})
		if resolveErr == nil {
			a.Secrets = sec
			return nil
		}
		if isMissingKey(resolveErr) {
			logger.Info("vault is empty and no master key is configured; " +
				"credentials cannot be stored until one is provided")
			return nil
		}
		return resolveErr
	}

	// Credentials exist: a key MUST resolve or the daemon refuses to start.
	sec, err := secret.New(secret.Options{Salt: salt, Params: secret.DefaultKDFParams, Custody: custody})
	if err != nil {
		return err
	}
	a.Secrets = sec
	return nil
}

// vaultHasCredentials reports whether any credential row exists. It uses the
// seam so the read-error branch is reachable in tests.
func (a *App) vaultHasCredentials() (bool, error) {
	return appSeam.HasCredentials(a.Credentials)
}

// isMissingKey reports whether err is the fail-closed "no master key" error.
func isMissingKey(err error) bool {
	var de *domain.DomainError
	return errors.As(err, &de) && de.Code == domain.CodeConfigSecretMissing
}

// systemClock adapts the standard library clock to contracts.Clock without
// pulling a helper type into a leaf.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// familyModels converts the operator-declared model ids into the capability
// table a family is built with. It declares every model with the streaming +
// tools + system-prompt capabilities and the text modality: enough for the
// Router to route and the capability-aware ordering to keep the model, without
// inventing per-model capabilities the operator did not declare. An empty list
// leaves the family with no declared models (not routable until one is added).
func familyModels(models []string) map[domain.ModelID]providers.ModelCapabilities {
	out := make(map[domain.ModelID]providers.ModelCapabilities, len(models))
	caps := contracts.CapStream.Add(contracts.CapTools, contracts.CapSystemPrompt)
	mods := contracts.ModalitySet(0).Add(contracts.ModalityText)
	for _, m := range models {
		if m == "" {
			continue
		}
		out[domain.ModelID(m)] = providers.ModelCapabilities{Capabilities: caps, Modalities: mods}
	}
	return out
}

// buildFamily constructs the ProviderFamily for a descriptor, branching on the
// PROTOCOL (ADR-0010 wiring / BD-02): WireCloudCode gets the CloudCode family
// (the Antigravity connector), every other dialect gets the OpenAI-compatible
// one. The family, not the caller, then builds the correct executor in
// BuildExecutor, so the two dialects can never share a transport by accident.
func buildFamily(desc contracts.ProviderDescriptor, pc config.ProviderConfig) (contracts.ProviderFamily, error) {
	models := familyModels(pc.Models)
	switch desc.Protocol {
	case contracts.WireCloudCode:
		return providers.NewCloudCode(providers.CloudCodeOptions{
			ID:                    desc.ID,
			Descriptor:            desc,
			AuthModes:             auth.AuthModesFor(desc.ID),
			Models:                models,
			BaseURL:               pc.BaseURL,
			AllowLoopback:         pc.AllowLoopback,
			ResponseHeaderTimeout: pc.TTFT,
			IdleTimeout:           pc.Idle,
		})
	default:
		return providers.NewOpenAICompat(providers.OpenAICompatOptions{
			ID:                    desc.ID,
			Descriptor:            desc,
			AuthModes:             auth.AuthModesFor(desc.ID),
			Models:                models,
			BaseURL:               pc.BaseURL,
			AllowLoopback:         pc.AllowLoopback,
			AuthHeader:            authHeaderStyle(pc.AuthHeader),
			ResponseHeaderTimeout: pc.TTFT,
			IdleTimeout:           pc.Idle,
		})
	}
}

// authHeaderStyle maps the config string onto the executor's auth-header style.
// "" and "bearer" both mean Bearer; "x-api-key" selects the Anthropic-style
// header. Config.Validate already rejected any other value.
func authHeaderStyle(s string) executors.AuthHeaderStyle {
	if s == "x-api-key" {
		return executors.AuthAPIKeyHeader
	}
	return executors.AuthBearer
}

// ImportCredentials runs the read-only harness importers into the vault. It
// requires a live SecretStore: without a KEK the credentials cannot be sealed,
// so the call fails closed with config.secret_missing.
func (a *App) ImportCredentials(ctx context.Context) ([]importers.Result, error) {
	if a.Secrets == nil {
		return nil, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	im := &importers.Importer{
		Store: a.Credentials,
		// Secrets is the real SecretStore; its Seal never returns plaintext.
		Sealer: a.Secrets,
		Env:    a.env,
		// Home comes from the environment snapshot so a systemd unit with a
		// different HOME reads the right files, and a test can isolate it.
		Home: a.env["HOME"],
	}
	return im.ImportAll(ctx)
}

// ProviderList returns the registered provider summaries, deterministically
// ordered. It needs no key. Each row carries the HONEST readiness (Ready /
// ReasonCode) so `provider list` does not show a misleading "ready" for a
// provider that has no usable credential (see providerReadiness).
func (a *App) ProviderList(ctx context.Context) []ProviderSummary {
	creds, listErr := a.credentialsByProvider(ctx)
	var out []ProviderSummary
	for _, id := range a.Providers.IDs() {
		summary := ProviderSummary{ID: id}
		var modes []contracts.AuthMode
		if family, err := a.Providers.Get(id); err == nil {
			modes = family.AuthModes()
			for _, m := range modes {
				summary.AuthModes = append(summary.AuthModes, m.String())
			}
			summary.Protocol = string(family.Protocol())
		}
		summary.PendingEndpoints = auth.PendingFields(id)
		summary.Ready, summary.ReasonCode, _ = a.providerReadiness(id, modes, creds, listErr)
		// The ToS risk notice (ADR-0003 §4) and the future marker are descriptor
		// data; expose them so the CLI/GUI can warn (risk) or label a planned
		// provider (future). Both are i18n codes, not prose.
		if desc, err := a.descriptorOf(id); err == nil {
			summary.RiskNotice = desc.RiskNotice
			summary.Future = desc.Future
		}
		out = append(out, summary)
	}
	return out
}

// ProviderStatus reports each provider's REAL readiness. A buildable flow is NOT
// enough: a provider is ready only when the vault holds a credential whose auth
// mode the family supports. Concretely (ADR-0002 codes):
//
//   - flow not buildable (pending endpoints, …) -> blocked(auth.provider_pending_endpoints);
//   - no credential, provider supports OAuth    -> blocked(provider.login_required);
//   - no credential, API-key provider           -> blocked(provider.no_credential);
//   - credential mode not supported by the family -> blocked(credential.invalid_auth_mode);
//   - usable credential present                 -> ready.
//
// This makes `provider status` agree with `provider test`: an OAuth provider with
// no stored credential is never reported ready while `heimdall login` does not
// exist.
func (a *App) ProviderStatus(ctx context.Context) []ProviderStatus {
	creds, listErr := a.credentialsByProvider(ctx)
	var out []ProviderStatus
	for _, id := range a.Providers.IDs() {
		status := ProviderStatus{ID: id}
		var modes []contracts.AuthMode
		if family, err := a.Providers.Get(id); err == nil {
			modes = family.AuthModes()
		}
		status.Ready, status.ReasonCode, status.Reason = a.providerReadiness(id, modes, creds, listErr)
		if desc, err := a.descriptorOf(id); err == nil {
			status.RiskNotice = desc.RiskNotice
			status.Future = desc.Future
		}
		out = append(out, status)
	}
	return out
}

// credentialsByProvider lists the vault once and indexes the first credential
// per provider (id only; never the secret). A list failure is returned so every
// provider is reported not-ready rather than falsely ready.
func (a *App) credentialsByProvider(ctx context.Context) (map[domain.ProviderID]contracts.Credential, error) {
	creds, err := a.Credentials.List(ctx)
	if err != nil {
		return nil, err
	}
	byProvider := make(map[domain.ProviderID]contracts.Credential, len(creds))
	for _, c := range creds {
		if _, ok := byProvider[c.Provider]; !ok {
			byProvider[c.Provider] = c
		}
	}
	return byProvider, nil
}

// providerReadiness is the single readiness rule both list and status use. It
// returns (ready, i18n code, reason). See ProviderStatus for the taxonomy.
func (a *App) providerReadiness(id domain.ProviderID, modes []contracts.AuthMode, creds map[domain.ProviderID]contracts.Credential, listErr error) (bool, string, string) {
	// A FUTURE provider is not-ready because the FEATURE is not shipped, which
	// outranks every credential/endpoint check: no amount of user action makes
	// it usable in this build, so it must never be reported as a user-fixable
	// "blocked" state. It is reported with provider.future.
	if desc, err := a.descriptorOf(id); err == nil && desc.Future {
		note := desc.FutureNote
		if note == "" {
			note = "planned provider; not usable yet"
		}
		return false, domain.CodeProviderFuture, note
	}
	// The flow must be buildable next (pending endpoints outrank credentials):
	// a provider that cannot construct a flow can never execute.
	if _, err := a.Flows.Build(id); err != nil {
		return false, domainErrorCode(err), err.Error()
	}
	if listErr != nil {
		return false, domainErrorCode(listErr), listErr.Error()
	}
	cred, ok := creds[id]
	if !ok {
		if supportsAuthMode(modes, contracts.AuthOAuth) {
			return false, domain.CodeProviderLoginRequired, "no credential: interactive login required"
		}
		return false, domain.CodeProviderNoCredential, "no credential stored"
	}
	if !supportsAuthMode(modes, cred.AuthMode) {
		return false, domain.CodeCredentialInvalidAuthMode, "credential auth mode is not supported by this provider"
	}
	return true, "", ""
}

// supportsAuthMode reports whether modes contains want.
func supportsAuthMode(modes []contracts.AuthMode, want contracts.AuthMode) bool {
	for _, m := range modes {
		if m == want {
			return true
		}
	}
	return false
}

// descriptorOf resolves a provider's descriptor through the injectable seam,
// falling back to the real catalog when the App was built without one.
func (a *App) descriptorOf(id domain.ProviderID) (contracts.ProviderDescriptor, error) {
	if a.descriptor != nil {
		return a.descriptor(id)
	}
	return auth.Descriptor(id)
}

// domainErrorCode extracts the i18n code from a *domain.DomainError, or "".
func domainErrorCode(err error) string {
	if de, ok := err.(*domain.DomainError); ok {
		return de.Code
	}
	return ""
}

// ProviderTestResult reports one `provider test` run. It carries no secret.
type ProviderTestResult struct {
	// Provider is the tested family.
	Provider domain.ProviderID
	// CredentialID is the vault credential used (its id only, never the value).
	CredentialID domain.CredentialID
	// Status is the upstream HTTP status of the minimal probe (0 when the call
	// never reached the upstream, e.g. a transport or config error).
	Status int
}

// ProviderTest probes a provider end to end WITHOUT a chat completion: it loads
// the provider's API-key credential from the vault, builds the family's executor
// (transport + auth through the ADR-SEC-05 EgressPolicy) and issues a minimal
// authenticated `GET {base}/models`. It is the observable, OAuth-free integration
// path for the API-key providers.
//
// It fails closed and typed:
//   - no credential in the vault          -> provider.no_credential;
//   - an OAuth credential                 -> provider.login_required (no OAuth);
//   - a family without a base_url         -> provider.invalid (BuildExecutor);
//   - an upstream non-2xx                 -> the ADR-0002 mapping (credential/
//     provider/request scope), so the caller sees the real failure class.
func (a *App) ProviderTest(ctx context.Context, id domain.ProviderID) (ProviderTestResult, error) {
	family, err := a.Providers.Get(id)
	if err != nil {
		return ProviderTestResult{}, err
	}

	cred, err := a.credentialFor(ctx, id)
	if err != nil {
		return ProviderTestResult{}, err
	}
	if cred.AuthMode != contracts.AuthAPIKey {
		return ProviderTestResult{}, domain.New(domain.CodeProviderLoginRequired,
			domain.WithHTTPStatus(401),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	if a.Secrets == nil {
		// The vault needs a KEK to open the sealed key.
		return ProviderTestResult{}, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}

	deps := contracts.ExecutorDeps{
		Clock:    systemClock{},
		IDs:      domainIDGen{},
		Redactor: i18n.Redacter{},
		Secrets:  a.Secrets,
		Egress:   egress.New(),
	}
	exec, err := family.BuildExecutor(cred, deps)
	if err != nil {
		return ProviderTestResult{}, err
	}
	prober, ok := exec.(interface {
		Probe(context.Context, contracts.Credential) (int, error)
	})
	if !ok {
		// A family whose executor does not implement Probe cannot be tested.
		return ProviderTestResult{}, domain.New(domain.CodeProviderNoExecutor,
			domain.WithHTTPStatus(501),
			domain.WithParams(map[string]string{"provider": string(id), "reason": "executor has no probe"}),
		)
	}
	status, err := prober.Probe(ctx, cred)
	if err != nil {
		return ProviderTestResult{Provider: id, CredentialID: cred.ID, Status: status}, err
	}
	return ProviderTestResult{Provider: id, CredentialID: cred.ID, Status: status}, nil
}

// credentialFor returns the first vault credential for provider id, or
// provider.no_credential. It never returns the secret value.
func (a *App) credentialFor(ctx context.Context, id domain.ProviderID) (contracts.Credential, error) {
	creds, err := a.Credentials.List(ctx)
	if err != nil {
		return contracts.Credential{}, err
	}
	for _, c := range creds {
		if c.Provider == id {
			return c, nil
		}
	}
	return contracts.Credential{}, domain.New(domain.CodeProviderNoCredential,
		domain.WithHTTPStatus(404),
		domain.WithParams(map[string]string{"provider": string(id)}),
	)
}

// APIKeyResult reports one `provider add-key` run. It carries no secret.
type APIKeyResult struct {
	Provider     domain.ProviderID
	CredentialID domain.CredentialID
	Label        string
	// Upserted is true when an existing credential for this provider+label was
	// replaced (idempotent re-add), false when a new one was created.
	Upserted bool
	// CreatedAt is when the stored row was written, so a caller (the management
	// API) can render the credential view without a second read.
	CreatedAt time.Time
}

// AddAPIKey seals a plaintext API key and stores it in the vault for provider id.
// The plaintext comes from the CALLER (the CLI reads it from stdin) and never
// appears in an argument, a log, an error or the returned result.
//
// It is fail-closed and typed:
//   - an unknown provider                        -> provider.not_found;
//   - a provider that does not accept AuthAPIKey -> credential.invalid_auth_mode
//     (an OAuth provider must use the login flow, not a static key);
//   - a provider with no configured base_url     -> provider.invalid (BuildExecutor);
//   - no KEK configured                          -> config.secret_missing;
//   - a key rejected by the offline shape check  -> auth.api_key_invalid_format.
//
// It performs NO network I/O. It is idempotent per provider+label: re-adding the
// same label updates the same row (its deterministic id), so a second run does
// not create a duplicate.
func (a *App) AddAPIKey(ctx context.Context, id domain.ProviderID, label, key string) (APIKeyResult, error) {
	family, err := a.Providers.Get(id)
	if err != nil {
		return APIKeyResult{}, err
	}
	if !supportsAuthMode(family.AuthModes(), contracts.AuthAPIKey) {
		// This is about the PROVIDER not accepting API keys (it is OAuth), not a
		// stored credential with an unknown mode: use the provider-scoped code
		// and name the modes it DOES support.
		modes := make([]string, 0, len(family.AuthModes()))
		for _, m := range family.AuthModes() {
			modes = append(modes, m.String())
		}
		return APIKeyResult{}, domain.New(domain.CodeProviderAPIKeyNotSupported,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{
				"provider": string(id),
				"modes":    strings.Join(modes, ", "),
			}),
		)
	}
	if a.Secrets == nil {
		return APIKeyResult{}, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	// Validate the key's SHAPE offline (reuses the API-key flow's checks: empty,
	// whitespace/control chars, implausible length). This never contacts the
	// network.
	if _, err := auth.NewAPIKeyFlow(id, systemClock{}).KeyResult(key, contracts.AccountMeta{}); err != nil {
		return APIKeyResult{}, err
	}

	if label == "" {
		label = string(id)
	}
	credID := apiKeyCredentialID(id, label)
	_, getErr := a.Credentials.Get(ctx, credID)
	existed := getErr == nil

	// sealer is the app's SecretStore in production; a test injects a fake to
	// reach the seal-failure branch (which the real Store cannot fail once the
	// nil/empty-KEK guard above has passed).
	var sealer apiKeySealer = a.Secrets
	if a.sealer != nil {
		sealer = a.sealer
	}
	sealed, err := sealer.Seal([]byte(key))
	if err != nil {
		return APIKeyResult{}, domain.New(domain.CodeCredentialStoreFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "seal failed"}),
		)
	}
	cred := contracts.Credential{
		ID:       credID,
		Provider: id,
		AuthMode: contracts.AuthAPIKey,
		Label:    label,
		Meta:     contracts.AccountMeta{DisplayName: label},
		Sealed:   []byte(sealed),
	}
	if err := a.Credentials.Upsert(ctx, cred); err != nil {
		return APIKeyResult{}, err
	}
	return APIKeyResult{Provider: id, CredentialID: credID, Label: label, Upserted: existed, CreatedAt: time.Now().UTC()}, nil
}

// apiKeySealer is the narrow seal port add-key needs. *secret.Store satisfies
// it; a test injects a failing fake to cover the seal-error branch.
type apiKeySealer interface {
	Seal(plaintext []byte) (string, error)
}

// apiKeyCredentialID derives a deterministic, non-secret CredentialID from
// provider+label, so add-key is idempotent (a second add updates the same row).
// The hash is over non-secret inputs only.
func apiKeyCredentialID(provider domain.ProviderID, label string) domain.CredentialID {
	sum := sha256.Sum256([]byte("addkey:" + string(provider) + ":" + label))
	return domain.CredentialID(fmt.Sprintf("key-%s-%s", provider, hex.EncodeToString(sum[:8])))
}

// domainIDGen adapts domain.NewRequestID to contracts.IDGen.
type domainIDGen struct{}

func (domainIDGen) NewRequestID() domain.RequestID { return domain.NewRequestID() }

// ProviderSummary is one row of `provider list`.
type ProviderSummary struct {
	ID               domain.ProviderID
	Protocol         string
	AuthModes        []string
	PendingEndpoints []string
	// Ready is the HONEST readiness: true only when the vault holds a usable
	// credential for this provider. It is the same rule as ProviderStatus, so
	// `provider list` and `provider status` cannot disagree.
	Ready bool
	// ReasonCode is the i18n code explaining a not-ready provider (empty when
	// Ready). It mirrors ProviderStatus.ReasonCode.
	ReasonCode string
	// Future marks a planned provider (descriptor.Future). Reported as a
	// distinct "future" state, never as a user-fixable "blocked".
	Future bool
	// RiskNotice is the i18n code of the ToS warning for an obfuscated provider
	// (ADR-0003 §4); empty for a provider with no obfuscation.
	RiskNotice string
}

// ProviderStatus is one row of `provider status`.
type ProviderStatus struct {
	ID         domain.ProviderID
	Ready      bool
	Reason     string
	ReasonCode string
	// Future mirrors ProviderSummary.Future.
	Future bool
	// RiskNotice mirrors ProviderSummary.RiskNotice.
	RiskNotice string
}

// wireGates builds the gate engine (ADR-0014): it registers the built-in gates
// that config enables, orders them by the data-dependency graph (once, at boot),
// logs the EFFECTIVE chain with each gate's failure policy (so disabling a
// FailClosed gate is visible, §4), and builds the ordered chain.
//
// The logger gate is the only F4-wave-1 gate; the token/memory/security gates
// land in later waves and register here the same way. A gate disabled by config
// is never constructed (its factory is not called) and never enters the graph.
func (a *App) wireGates() error {
	reg := appSeam.NewRegistry()

	// The logger gate is always available (observability, FailOpen). It is pure
	// observability: it is on unless explicitly disabled per-gate.
	if a.Config.Features.Gates.GateEnabled("logger", true) {
		if err := reg.RegisterGate("logger", func() contracts.Gate {
			return gates.NewLogger(a.gateSink())
		}); err != nil {
			return err
		}
	}

	// The token gate (ADR-0015) runs only when the token feature is on (its
	// group switch) and not individually disabled. Its engines are resolved from
	// the per-engine config; a disabled engine never enters the registry.
	if a.Config.Features.Gates.GateEnabled("token", a.Config.Features.Gates.Token) {
		tokenGate, err := a.buildTokenGate()
		if err != nil {
			return err
		}
		if err := reg.RegisterGate("token", func() contracts.Gate { return tokenGate }); err != nil {
			return err
		}
	}

	// The security gates (F4 wave 4, ADR-SEC-03/04/05): containment (credential
	// masker, rate limit, SSRF) and final verification (injection guard, PII
	// masker). EACH gate's enablement is GateEnabled(id, group): an explicit
	// per-gate entry wins over the group switch in both directions, so the
	// block always runs and Assemble simply omits every disabled gate.
	for _, g := range a.buildSecurityGates() {
		if err := reg.RegisterGate(g.ID(), func() contracts.Gate { return g }); err != nil {
			return err
		}
	}

	// The memory gates (F4 wave 3, ADR-SEC-07): the synchronous retriever
	// (PreRequest, ordered before the token engine through the context edge)
	// and the asynchronous writer (PostResponse, off the response path). The
	// SQLite store is shared; the vector mode stays OFF unless the embeddings
	// opt-in is configured — its absence never fails the boot.
	retrieverOn := a.Config.Features.Gates.GateEnabled("memory-retriever", a.Config.Features.Gates.Memory)
	writerOn := a.Config.Features.Gates.GateEnabled("memory-writer", a.Config.Features.Gates.Memory)
	if retrieverOn || writerOn {
		memCfg := a.buildMemoryGateConfig()
		if retrieverOn {
			// Cannot be nil here: Disabled is false and the store is wired.
			retriever := memory.NewRetriever(memCfg)
			if err := reg.RegisterGate(retriever.ID(), func() contracts.Gate { return retriever }); err != nil {
				return err
			}
		}
		if writerOn {
			writer := memory.NewWriter(memCfg)
			if err := reg.RegisterGate(writer.ID(), func() contracts.Gate { return writer }); err != nil {
				return err
			}
		}
	}

	order, err := appSeam.BuildGateOrder(reg)
	if err != nil {
		return err
	}
	a.GateOrder = order

	chain, err := appSeam.NewOrderedChain(order.PreRequest, order.OnResponseChunk, order.PostResponse)
	if err != nil {
		return err
	}
	a.Gates = chain
	a.logEffectiveChain(order)
	return nil
}

// buildTokenGate resolves the token gate's engines from config and builds it
// (ADR-0015). Each built-in engine is registered through the ADR-0015 §1
// validation; a disabled engine is skipped (never registered), and an engine's
// prefix-rewrite opt-in is passed only when the operator set it.
//
// A registration failure (an incoherent engine metadata pair, which the
// built-ins never produce but a future engine might) fails the boot: the engine
// registry refuses the lying declaration rather than running a misdeclared
// engine.
func (a *App) buildTokenGate() (contracts.Gate, error) {
	gfeat := a.Config.Features.Gates
	engReg := token.NewRegistry()
	for _, e := range appSeam.TokenEngines() {
		if !gfeat.TokenEngineEnabled(e.ID()) {
			continue
		}
		if err := engReg.Register(e, gfeat.TokenEngineAllowPrefixRewrite(e.ID())); err != nil {
			return nil, err
		}
	}
	// The opt-in map is derived from the registry so it can only contain engines
	// actually registered with opt-in.
	optIn := make(map[string]bool)
	for _, e := range engReg.Enabled() {
		if engReg.AllowPrefixRewrite(e.ID()) {
			optIn[e.ID()] = true
		}
	}
	return token.New(token.Config{
		Engines: engReg.Enabled(),
		OptIn:   optIn,
		Record:  a.tokenStatSink(),
	}), nil
}

// buildSecurityGates maps the security parameter block onto the security
// package's Config and assembles the ENABLED gates (F4 wave 4). The family
// switch and the per-gate switches both apply: a gate whose per-gate switch is
// false is disabled in the Config and never constructed (ADR-0014 §4). The
// policies were validated at config load; unknown values cannot reach here.
func (a *App) buildSecurityGates() []contracts.Gate {
	g := a.Config.Features.Gates
	sec := g.SecurityParams
	on := func(id string) bool { return g.GateEnabled(id, g.Security) }

	piiPolicy := piiPolicyOf(sec.PIIPolicy)
	if !on("pii-masker") {
		// The PII gate's "off" IS its PiiOff policy: the constructor returns
		// nil and Assemble omits it.
		piiPolicy = security.PiiOff
	}
	cfg := security.Config{
		DisableCredentialMasker: !on("credential-masker"),
		PIIMasker:               security.PiiConfig{Policy: piiPolicy},
		Injection: security.InjectConfig{
			Disabled: !on("injection-guard"),
			Policy:   injectPolicyOf(sec.InjectPolicy),
		},
		DisableSSRF: !on("ssrf-guard"),
	}
	// The throttle joins only when BOTH the switch allows it and the operator
	// configured a capacity (its burst size has no safe default).
	if on("rate-limit") && sec.RateLimit.Rate > 0 && sec.RateLimit.Interval > 0 {
		cfg.RateLimit = security.RateLimitConfig{
			Rate:     sec.RateLimit.Rate,
			Interval: sec.RateLimit.Interval,
			Clock:    systemClock{},
		}
	}
	return security.Assemble(cfg)
}

// piiPolicyOf maps the validated policy string onto the gate's enum. The
// empty value is the safe default (mask); anything else was rejected by
// config.Validate at load.
func piiPolicyOf(v string) security.PiiPolicy {
	switch strings.ToLower(v) {
	case "block":
		return security.PiiBlock
	case "off":
		return security.PiiOff
	default:
		return security.PiiMask
	}
}

// injectPolicyOf maps the validated policy string onto the guard's enum. The
// empty value is the safe default (block).
func injectPolicyOf(v string) security.InjectPolicy {
	if strings.ToLower(v) == "flag" {
		return security.InjectFlag
	}
	return security.InjectBlock
}

// buildMemoryGateConfig builds the memory gates' Config over the shared
// SQLite store (ADR-SEC-07). The clock is the app's injected clock; the
// embeddings opt-in builds an HTTP engine only when the operator configured
// one — its absence leaves the vector mode OFF (FTS5-only) and never fails
// the boot; a misconfigured destination that slipped past validation is
// logged (without credentials) and downgraded to off.
func (a *App) buildMemoryGateConfig() memory.Config {
	g := a.Config.Features.Gates
	mp := g.MemoryParams
	cfg := memory.Config{
		Store:          store.NewMemoryStore(a.Store),
		Clock:          systemClock{},
		TTL:            mp.TTL,
		RetrievalLimit: mp.RetrievalLimit,
		Budget:         mp.Budget,
		MaxContent:     mp.MaxContent,
		SinkCapacity:   mp.SinkCapacity,
		Record:         a.memoryEventSink(),
	}
	if emb := mp.Embeddings; strings.TrimSpace(emb.BaseURL) != "" {
		engine := memory.NewHTTPEmbedder(memory.EmbedderConfig{
			BaseURL:   emb.BaseURL,
			Model:     emb.Model,
			APIKeyEnv: emb.APIKeyEnv,
			Dim:       emb.Dim,
			Policy:    egress.New(),
		})
		if engine == nil {
			// Unreachable after Validate, but the fail-safe is OFF (never a
			// boot failure): only the lexical retrieval runs.
			a.Logger.Warn("memory embeddings opt-in is misconfigured; vector mode stays off",
				"base_url", emb.BaseURL, "model", emb.Model)
		} else {
			cfg.Embedder = engine
		}
	}
	return cfg
}

// memoryEventSink records memory gate events (kinds only, never content) into
// the bounded gate record and the structured logger.
func (a *App) memoryEventSink() func(kind string) {
	return func(kind string) {
		record := map[string]string{"stage": "memory", "event": kind}
		a.gateMu.Lock()
		if len(a.gateRecords) < gateRecordCap {
			a.gateRecords = append(a.gateRecords, record)
		}
		a.gateMu.Unlock()
		a.Logger.Debug("gate.memory", "event", kind)
	}
}

// tokenStatSink records token-engine stats as metadata only (counts, never
// content). It reuses the same bounded gate record buffer as the logger gate so
// the audit surface is one place.
func (a *App) tokenStatSink() func(token.Stats) {
	return func(s token.Stats) {
		record := map[string]string{
			"stage":              "token_engine",
			"engine":             s.ID,
			"bytes_in":           strconv.Itoa(s.BytesIn),
			"bytes_out":          strconv.Itoa(s.BytesOut),
			"tokens_saved":       strconv.Itoa(s.TokensSaved),
			"prefix_invalidated": strconv.FormatBool(s.PrefixInvalidated),
		}
		a.gateMu.Lock()
		if len(a.gateRecords) < gateRecordCap {
			a.gateRecords = append(a.gateRecords, record)
		}
		a.gateMu.Unlock()
		a.Logger.Debug("gate.token_engine", "fields", record)
	}
}

// gateSink builds the logger gate's sink: a bounded in-memory record for tests,
// mirrored to the structured logger. It is metadata only (never a body or a
// header value).
func (a *App) gateSink() func(stage string, fields map[string]string) {
	return func(stage string, fields map[string]string) {
		record := map[string]string{"stage": stage}
		for k, v := range fields {
			record[k] = v
		}
		// Serialize the bounded buffer against concurrent request goroutines.
		a.gateMu.Lock()
		if len(a.gateRecords) < gateRecordCap {
			a.gateRecords = append(a.gateRecords, record)
		}
		a.gateMu.Unlock()
		a.Logger.Debug("gate."+stage, "fields", record)
	}
}

// logEffectiveChain records the effective chain and each gate's policy at boot
// (ADR-0014 §4): disabling a FailClosed gate changes the security posture, so
// the resulting chain is visible, never silent.
func (a *App) logEffectiveChain(order gates.Order) {
	for _, g := range order.All {
		a.Logger.Info("gate enabled",
			"id", g.ID(),
			"policy", g.FailurePolicy().String(),
			"stages", stagesString(g.Stages()))
	}
}

// stagesString renders a stage set deterministically for the boot log.
func stagesString(s contracts.GateStageSet) string {
	var names []string
	for _, st := range []contracts.GateStage{
		contracts.StagePreRequest, contracts.StageOnResponseChunk, contracts.StagePostResponse,
	} {
		if s.Has(st) {
			names = append(names, stageName(st))
		}
	}
	return strings.Join(names, ",")
}

// stageName names a gate stage.
func stageName(st contracts.GateStage) string {
	switch st {
	case contracts.StagePreRequest:
		return "pre_request"
	case contracts.StageOnResponseChunk:
		return "on_response_chunk"
	case contracts.StagePostResponse:
		return "post_response"
	default:
		return "unknown"
	}
}

// wireRouting builds the F3 routing layer (ADR-0009/0010/0011/0012/0013): the
// combo store, the Router over the provider catalog, the durable quota recorder
// and filter, the in-memory breaker, the Dispatcher and the inference gateway.
//
// The quota state is DURABLE (SQLite, ADR-0011 §4): a restart must not forget a
// spent short window. The breaker is IN-MEMORY (ADR-0012 §6): a restart reopens
// transient circuits, which is intentional and opposite in kind.
func (a *App) wireRouting() error {
	a.Combos = store.NewComboStore(a.Store, a.Providers)

	catalog := providers.NewCatalog(a.Providers)
	quotaCfg := quota.DefaultConfig(systemClock{})
	a.QuotaStore = store.NewQuotaStore(a.Store)
	a.QuotaRec = quota.NewRecorder(a.QuotaStore, quotaCfg)
	a.QuotaFilt = quota.NewFilter(a.QuotaRec, quotaCfg)
	a.Breaker = breaker.New(systemClock{})

	// The Router resolves a fusion combo into Panels + Judge. A Judge needs its
	// OWN route (ADR-0009 §3: "o juiz é resolvido por um combo/rota próprio"),
	// which is operator DATA no build exposes a config knob for yet; without it
	// the fusion plan carries the panels and the Dispatcher uses the documented
	// first-successful-panel fallback. Pipeline (Chain) needs no port.
	resolver, err := newRouter(a.Combos, catalog,
		router.WithPreflight(preflight{a.QuotaFilt, a.Breaker}),
	)
	if err != nil {
		return err
	}
	a.Router = resolver

	creds := credentialSource{store: a.Credentials, registry: a.Providers}
	a.Dispatcher = dispatcher.New(
		executorFactory{registry: a.Providers, secrets: a.Secrets},
		creds,
		a.Breaker,
		a.QuotaFilt,
		a.QuotaRec,
		dispatcher.Config{Clock: systemClock{}, IDs: domainIDGen{}},
	)
	a.Gateway = gateway.New(a.Router, a.Dispatcher, a.Combos, a.Gates, a.Bundle, domainIDGen{})
	return nil
}

// newRouter is a seam over router.New. The built-in strategy set is always
// valid, so the constructor's error branch is only reachable by injection; the
// seam lets a test prove wireRouting propagates it (fail-closed at boot).
var newRouter = router.New

// executorFactory adapts the provider registry to the Dispatcher's
// ExecutorFactory port. It resolves the family by the candidate's ProviderID and
// calls its BuildExecutor; the family decides the protocol (the registry holds
// OpenAICompat vs CloudCode instances, chosen at registration).
type executorFactory struct {
	registry *providers.Registry
	secrets  *secret.Store
}

// Build implements dispatcher.ExecutorFactory.
func (f executorFactory) Build(ctx context.Context, c contracts.Candidate, cred contracts.Credential) (contracts.Executor, error) {
	family, err := f.registry.Get(c.Provider)
	if err != nil {
		return nil, err
	}
	deps := contracts.ExecutorDeps{
		Clock:    systemClock{},
		IDs:      domainIDGen{},
		Redactor: i18n.Redacter{},
		Egress:   egress.New(),
	}
	if f.secrets != nil {
		deps.Secrets = f.secrets
	}
	return family.BuildExecutor(cred, deps)
}

// credentialSource adapts the vault's CredentialStore to the Dispatcher's
// CredentialSource port: it loads a credential by id and lists the credentials
// of a provider (deterministically ordered so the Dispatcher's pick is
// reproducible).
type credentialSource struct {
	store    *store.CredentialStore
	registry *providers.Registry
}

// Get implements dispatcher.CredentialSource.
func (c credentialSource) Get(ctx context.Context, id domain.CredentialID) (contracts.Credential, error) {
	return c.store.Get(ctx, id)
}

// Credentials implements dispatcher.CredentialSource. The ids are returned in a
// deterministic order (the vault's List order is by created_at DESC, id ASC; it
// is re-sorted by id here so the pick does not depend on wall-clock insertion).
func (c credentialSource) Credentials(ctx context.Context, provider domain.ProviderID) ([]domain.CredentialID, error) {
	all, err := c.store.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []domain.CredentialID
	for _, cred := range all {
		if cred.Provider != provider {
			continue
		}
		if !supportsAuthMode(c.registryAuthModes(provider), cred.AuthMode) {
			continue
		}
		out = append(out, cred.ID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// registryAuthModes reports a family's supported auth modes, or nil when the
// provider is unknown.
func (c credentialSource) registryAuthModes(provider domain.ProviderID) []contracts.AuthMode {
	family, err := c.registry.Get(provider)
	if err != nil {
		return nil
	}
	return family.AuthModes()
}

// preflight composes the quota filter and the breaker for the Router's preflight
// port (ADR-0009 §1.3). A candidate is admitted only when the breaker allows it
// and the quota filter keeps it.
type preflight struct {
	quota *quota.Filter
	br    *breaker.Breaker
}

// AllowCandidate implements router.Preflight.
func (p preflight) AllowCandidate(ctx context.Context, c contracts.Candidate) (bool, string) {
	if !p.br.Allow(c) {
		return false, "breaker_open"
	}
	filtered, skips := p.quota.Filter(ctx, contracts.RoutePlan{Attempts: []contracts.Candidate{c}, MaxRounds: 1})
	if len(filtered.Attempts) == 0 {
		return false, quotaSkipReason(skips)
	}
	return true, ""
}

// quotaSkipReason names the reason a quota filter removed a candidate. The real
// filter always emits a Skip when it removes one, so the empty case is defensive
// (a filter contract a fake could violate) and is tested directly.
func quotaSkipReason(skips []contracts.Skip) string {
	if len(skips) == 0 {
		return "quota_exhausted"
	}
	return skips[0].Reason
}

// gateRecordCap bounds the in-memory gate record so a long-running daemon does
// not accumulate unbounded metadata.
const gateRecordCap = 1024

// contracts assertion: the credential store is usable through the frozen seam.
var _ contracts.CredentialStore = (*store.CredentialStore)(nil)

// Handler builds the full HTTP handler graph.
//
// The assembly order is the security contract:
//
//	Recoverer → RequestID → LocalOnly(catch-all) → mux
//
// LocalOnly wraps the mux, not individual routes, so a route registered later
// is protected without touching this function.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()

	openai.New(a.Bundle).Register(mux)
	// The embedded management GUI (a Svelte SPA) is served from the same mux
	// under /web/, so it inherits the catch-all LocalOnly and HostGuard guards
	// by construction (ADR-SEC-06). It is a READ-class asset surface: the
	// browser must load the login screen before it can present a token, and the
	// assets carry no secret. The SPA authenticates every /api/mgmt/* call with
	// the management token in the Authorization header (never a cookie).
	webui.New().Register(mux)
	// The management API is built over the App's own adapter: every /api/mgmt/
	// route (the whole subtree) requires the management token, mounted as ONE
	// authenticated sub-mux so a route added later inherits the guard by
	// construction (ADR-SEC-06 §1.2).
	mgmt.New(middleware.ManagementAuth{
		Verify:   a.Store.VerifyManagementToken,
		Throttle: a.loginThrottle,
	}, a.NewManagementService()).WithRotationThrottle(a.rotationThrottle).Register(mux)

	// The F3 gateway owns POST /v1/chat/completions: it routes through the
	// Router, executes through the Dispatcher and runs the GateChain. The legacy
	// passthrough is wired ONLY when the gateway is absent (a build without the
	// routing layer), so the two never contend for the same route.
	if a.Gateway != nil {
		a.Gateway.Register(mux)
	} else if apiKey := a.Config.Passthrough.Resolve(a.env); apiKey != "" && a.Config.Passthrough.BaseURL != "" {
		// Passthrough is wired only when an upstream is configured, so an
		// unconfigured instance does not advertise a route that can only 502.
		client, err := passthrough.NewClient(passthrough.ClientConfig{
			BaseURL:               a.Config.Passthrough.BaseURL,
			APIKey:                apiKey,
			ResponseHeaderTimeout: 60 * time.Second,
		})
		if err != nil {
			// A misconfigured egress policy must not be silently ignored: the
			// passthrough route is simply not registered, and the reason is
			// logged (without the credential).
			a.Logger.Warn("passthrough disabled: " + err.Error())
		} else {
			passthrough.NewHandler(client).Register(mux)
		}
	}

	// ErrorEnvelope sits between the guards and the mux, so the mux's own
	// plain-text 404/405 responses are rewritten into the same JSON i18n
	// envelope every handler uses. RequestID is outside it, so X-Request-ID is
	// already set when the envelope is written.
	handler := middleware.ErrorEnvelope(mux)

	// The gate chain observes the INFERENCE surface (/v1/*) through the
	// metadata-only observer, outside the mux so a new /v1/* route is covered
	// (F5-2: management/health/GUI are NOT run through the inference chain, so
	// an inference rate-limit cannot throttle the operator's control surface).
	// It is wired here so the F1 logger gate actually runs in production, not
	// only in tests.
	if a.Gates != nil {
		if observer, err := appSeam.NewObserver(a.Gates); err == nil {
			// The gateway drives the chain itself (PreRequest with the body it
			// declared, the chunk stage and PostResponse); the observer must
			// not run the same chain over those requests, or a stateful gate
			// (the rate limiter) would observe every request twice.
			observer.Skip = func(r *http.Request) bool {
				return a.Gateway != nil &&
					r.Method == http.MethodPost &&
					r.URL.Path == gateway.ChatCompletionsPath
			}
			handler = observer.Handler(handler)
		} else {
			a.Logger.Warn("gate chain observer disabled: " + err.Error())
		}
	}

	// F5.1 HTTP trust guards (ADR-SEC-06 §3), all CATCH-ALL over the mux so a
	// route registered later is protected by construction:
	//
	//   CORS        — closed cross-origin policy for /v1/* (never a wildcard);
	//   OriginGuard — anti-CSRF for mutating management/GUI requests;
	//   ClientAuth  — client-key auth of mutating /v1/* routes;
	//   HostGuard   — anti-DNS-rebinding for EVERY route.
	//
	// HostGuard is outermost so an unacceptable Host is refused before any of
	// the others run (the same "before authentication" rule LocalOnly follows);
	// ClientAuth runs before the observer's chain pass so the authenticated
	// ClientID is already on the context when the gateway reads it. None of
	// these is per-route: the classification lives INSIDE each guard, keyed on
	// the path/method, which is what keeps a new /v1/* route protected without
	// an edit here.
	if a.ClientKeys != nil {
		handler = middleware.ClientAuth(a.verifyClientKey, a.Config.Security.RequireClientKey)(handler)
	}
	handler = middleware.OriginGuard(a.Config.Security.CORSAllowedOrigins)(handler)
	handler = middleware.CORS(a.Config.Security.CORSAllowedOrigins)(handler)
	handler = middleware.HostGuard(a.hostAllowlist())(handler)

	handler = middleware.LocalOnly(handler)
	handler = middleware.RequestID(domain.NewRequestID)(handler)
	handler = middleware.Recoverer(a.Logger)(handler)
	return handler
}

// verifyClientKey adapts the client-key store to the middleware verifier,
// binding the request context so a DB read honours cancellation.
func (a *App) verifyClientKey(ctx context.Context, presented string) (domain.ClientID, bool) {
	rec, ok := a.ClientKeys.Verify(ctx, presented)
	if !ok {
		return "", false
	}
	return rec.ID, true
}

// hostAllowlist returns the accepted Host values for the anti-rebinding guard.
//
// It always includes the operator's security.host_allowlist, and — per
// ADR-SEC-06 §3.1 — ALSO the configured server.host when server.allow_remote is
// set and that host is a NAME (or non-loopback IP) rather than a bare bind
// address. The ADR says: "Se allow-remote=true estiver configurado, adiciona-se
// o hostname ou IP local configurado em server.host". Without this, an operator
// who binds e.g. a LAN address and reaches the GUI by name would be refused by
// the Host guard despite allow_remote.
//
// A wildcard bind is deliberately NOT added: "0.0.0.0"/"::" is not a name a
// browser sends as Host, so adding it would only weaken the guard. An empty host
// adds nothing.
func (a *App) hostAllowlist() []string {
	out := append([]string(nil), a.Config.Security.HostAllowlist...)
	if !a.Config.Server.AllowRemote {
		return out
	}
	h := strings.TrimSpace(a.Config.Server.Host)
	switch h {
	case "", "0.0.0.0", "::", "[::]":
		// A wildcard/unspecified bind is not a Host value a client presents.
		return out
	}
	out = append(out, h)
	return out
}

// GateRecords returns a DEEP COPY of the metadata records the logger gate has
// emitted. The copy is mandatory: the internal slice is appended to by
// concurrent request goroutines, so returning it directly would hand the caller
// a slice header that can be reallocated under it. Each map is copied too, since
// a shallow slice copy would still share the inner maps and let the caller
// mutate the internal state.
func (a *App) GateRecords() []map[string]string {
	a.gateMu.Lock()
	defer a.gateMu.Unlock()
	out := make([]map[string]string, len(a.gateRecords))
	for i, rec := range a.gateRecords {
		clone := make(map[string]string, len(rec))
		for k, v := range rec {
			clone[k] = v
		}
		out[i] = clone
	}
	return out
}

// Run starts the listener and blocks until ctx is cancelled, then drains.
func (a *App) Run(ctx context.Context) error {
	a.Logger.InfoContext(ctx, a.Bundle.Format(i18n.DefaultLanguage,
		domain.CodeStartupListening, map[string]string{"address": a.Config.Server.Addr()}))

	errCh := make(chan error, 1)
	go func() {
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := appSeam.ShutdownServer(a.server, shutdownCtx); err != nil {
		return err
	}
	a.Logger.InfoContext(shutdownCtx, a.Bundle.Format(i18n.DefaultLanguage,
		domain.CodeStartupShutdown, nil))
	return nil
}

// Close releases the resources Build acquired. Every resource is attempted, and
// the errors are joined so one failure does not strand the others.
func (a *App) Close() error {
	var errs []error
	if a.Gates != nil {
		if err := a.Gates.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.Store != nil {
		if err := appSeam.CloseStore(a.Store); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RotateManagementToken generates a new token, persists only its hash and writes
// the plaintext to the configured 0600 file exactly once. It returns the file
// path so the CLI can report it without ever handling the secret itself.
// ClientKeyVerifier is the App-level client-key verifier the middleware uses.
// It is exposed as a method so the composition root can pass a value bound to
// the store without leaking the store type into the middleware package.

// CreateClientKey issues a new client key, storing only its hash, and returns
// the non-secret record plus the plaintext key EXACTLY ONCE. The caller (the
// CLI) prints the key and never persists it.
func (a *App) CreateClientKey(ctx context.Context, label string) (store.ClientKey, string, error) {
	if a.ClientKeys == nil {
		return store.ClientKey{}, "", domain.New(domain.CodeInternal,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "client key store not wired"}))
	}
	return a.ClientKeys.Create(ctx, label)
}

// ListClientKeys returns every client key's non-secret metadata, oldest first.
func (a *App) ListClientKeys(ctx context.Context) ([]store.ClientKey, error) {
	if a.ClientKeys == nil {
		return nil, domain.New(domain.CodeInternal,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "client key store not wired"}))
	}
	return a.ClientKeys.List(ctx)
}

// RevokeClientKey soft-deletes a client key by id. An unknown id is
// clientkey.not_found; an already-revoked id succeeds idempotently.
func (a *App) RevokeClientKey(ctx context.Context, id domain.ClientID) error {
	if a.ClientKeys == nil {
		return domain.New(domain.CodeInternal,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "client key store not wired"}))
	}
	return a.ClientKeys.Revoke(ctx, id)
}

func (a *App) RotateManagementToken() (tokenPath string, err error) {
	_, _, err = a.rotateManagementTokenValue()
	if err != nil {
		return "", err
	}
	return a.Config.Store.TokenPath, nil
}

// RotateManagementTokenValue rotates the management token and returns the new
// plaintext EXACTLY ONCE, alongside the path it was written to. It is the
// management-API path: the CLI uses RotateManagementToken (path only) so its
// output never has to handle the secret. The plaintext is never logged.
func (a *App) RotateManagementTokenValue() (token, tokenPath string, err error) {
	return a.rotateManagementTokenValue()
}

// rotateManagementTokenValue is the shared implementation: rotate, persist the
// hash (inside RotateManagementToken), write the 0600 token file, return the
// plaintext. The plaintext exists only in this call's return.
func (a *App) rotateManagementTokenValue() (token, tokenPath string, err error) {
	token, _, err = a.Store.RotateManagementToken()
	if err != nil {
		return "", "", err
	}
	if err := store.WriteTokenFile(a.Config.Store.TokenPath, token); err != nil {
		return "", "", err
	}
	return token, a.Config.Store.TokenPath, nil
}
