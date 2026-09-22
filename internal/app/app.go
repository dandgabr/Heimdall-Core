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
	"strings"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/api/mgmt"
	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/api/openai"
	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
	"github.com/dandgabr/heimdall-core/internal/executors"
	"github.com/dandgabr/heimdall-core/internal/gates"
	"github.com/dandgabr/heimdall-core/internal/i18n"
	"github.com/dandgabr/heimdall-core/internal/importers"
	"github.com/dandgabr/heimdall-core/internal/observability"
	"github.com/dandgabr/heimdall-core/internal/passthrough"
	"github.com/dandgabr/heimdall-core/internal/pipeline"
	"github.com/dandgabr/heimdall-core/internal/providers"
	"github.com/dandgabr/heimdall-core/internal/secret"
	"github.com/dandgabr/heimdall-core/internal/store"
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
	Providers   *providers.Registry
	Flows       *auth.FlowFactory
	// Gates is the frozen gate chain, wired with the F1 logger gate.
	Gates *pipeline.Chain

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
	NewObserver func(*pipeline.Chain) (*pipeline.Observer, error)
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
}

var defaultAppSeams = appSeams{
	LoadBundle:  i18n.New,
	OpenStore:   store.Open,
	EnsureToken: func(s *store.Store) (string, bool, error) { return s.EnsureManagementTokenHash() },
	NewChain:    pipeline.New,
	NewObserver: pipeline.NewObserver,
	Descriptors: auth.Descriptors,
	HasCredentials: func(cs *store.CredentialStore) (bool, error) {
		creds, err := cs.List(context.Background())
		if err != nil {
			return false, err
		}
		return len(creds) > 0, nil
	},
	ShutdownServer: func(s *http.Server, ctx context.Context) error { return s.Shutdown(ctx) },
	CloseStore:     func(s *store.Store) error { return s.Close() },
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

	app := &App{
		Config:     cfg,
		Store:      st,
		Logger:     logger,
		Bundle:     bundle,
		env:        opts.Env,
		descriptor: auth.Descriptor,
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
		family, err := providers.NewOpenAICompat(providers.OpenAICompatOptions{
			ID:         desc.ID,
			Descriptor: desc,
			// Declare the real modes so listing and routing agree.
			AuthModes:             auth.AuthModesFor(desc.ID),
			BaseURL:               pc.BaseURL,
			AllowLoopback:         pc.AllowLoopback,
			AuthHeader:            authHeaderStyle(pc.AuthHeader),
			ResponseHeaderTimeout: pc.TTFT,
			IdleTimeout:           pc.Idle,
		})
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
	a.Flows = auth.NewFlowFactory(flowDeps)

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
		Env:              a.env,
		KeyFilePath:      secret.DefaultKeyFilePath(),
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
	return APIKeyResult{Provider: id, CredentialID: credID, Label: label, Upserted: existed}, nil
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

// wireGates builds the gate chain with the trivial logger gate. The sink keeps
// a bounded in-memory record for tests and mirrors the metadata to the
// structured logger, so the gate runs in production and is assertable.
func (a *App) wireGates() error {
	loggerGate := gates.NewLogger(func(stage string, fields map[string]string) {
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
	})
	chain, err := appSeam.NewChain([]contracts.Gate{loggerGate})
	if err != nil {
		return err
	}
	a.Gates = chain
	return nil
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
	mgmt.New(middleware.ManagementAuth{
		Verify: a.Store.VerifyManagementToken,
	}).Register(mux)

	// Passthrough is wired only when an upstream is configured, so an
	// unconfigured instance does not advertise a route that can only 502.
	apiKey := a.Config.Passthrough.Resolve(a.env)
	if apiKey != "" && a.Config.Passthrough.BaseURL != "" {
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

	// The gate chain observes every request through the metadata-only observer,
	// outside the mux so a route added later is covered. It is wired here so the
	// F1 logger gate actually runs in production, not only in tests.
	if a.Gates != nil {
		if observer, err := appSeam.NewObserver(a.Gates); err == nil {
			handler = observer.Handler(handler)
		} else {
			a.Logger.Warn("gate chain observer disabled: " + err.Error())
		}
	}

	handler = middleware.LocalOnly(handler)
	handler = middleware.RequestID(domain.NewRequestID)(handler)
	handler = middleware.Recoverer(a.Logger)(handler)
	return handler
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
func (a *App) RotateManagementToken() (tokenPath string, err error) {
	token, _, err := a.Store.RotateManagementToken()
	if err != nil {
		return "", err
	}
	if err := store.WriteTokenFile(a.Config.Store.TokenPath, token); err != nil {
		return "", err
	}
	return a.Config.Store.TokenPath, nil
}
