// Package app is the composition root.
//
// It is the ONLY package allowed to import every other internal package; the
// leaves (domain, i18n, contracts) never import it, which is what keeps the
// dependency graph acyclic. Everything a phase adds is wired here and nowhere
// else.
package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/dandgabr/heimdall-core/internal/api/mgmt"
	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/api/openai"
	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
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

	env         map[string]string
	server      *http.Server
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
		Config: cfg,
		Store:  st,
		Logger: logger,
		Bundle: bundle,
		env:    opts.Env,
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
	registry := providers.NewRegistry()
	for _, desc := range appSeam.Descriptors() {
		family, err := providers.NewOpenAICompat(providers.OpenAICompatOptions{
			ID:         desc.ID,
			Descriptor: desc,
			// Declare the real modes so listing and routing agree.
			AuthModes: auth.AuthModesFor(desc.ID),
		})
		if err != nil {
			return err
		}
		if err := registry.Register(family); err != nil {
			return err
		}
	}
	a.Providers = registry

	// The flow factory needs only HTTP deps; it is not key material. Injected
	// deps (tests) win; production uses the real clock.
	flowDeps := oauth.ClientDeps{Clock: systemClock{}}
	if opts.FlowDeps != nil {
		flowDeps = *opts.FlowDeps
		if flowDeps.Clock == nil {
			flowDeps.Clock = systemClock{}
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
// ordered. It needs no key.
func (a *App) ProviderList() []ProviderSummary {
	var out []ProviderSummary
	for _, id := range a.Providers.IDs() {
		summary := ProviderSummary{ID: id}
		if family, err := a.Providers.Get(id); err == nil {
			for _, m := range family.AuthModes() {
				summary.AuthModes = append(summary.AuthModes, m.String())
			}
			summary.Protocol = string(family.Protocol())
		}
		summary.PendingEndpoints = auth.PendingFields(id)
		out = append(out, summary)
	}
	return out
}

// ProviderStatus reports each provider's readiness: whether its flow can be
// built now (endpoints confirmed) or it is pending.
func (a *App) ProviderStatus() []ProviderStatus {
	var out []ProviderStatus
	for _, id := range a.Providers.IDs() {
		status := ProviderStatus{ID: id}
		if _, err := a.Flows.Build(id); err != nil {
			status.Ready = false
			status.Reason = err.Error()
			if de, ok := err.(*domain.DomainError); ok {
				status.ReasonCode = de.Code
			}
		} else {
			status.Ready = true
		}
		out = append(out, status)
	}
	return out
}

// ProviderSummary is one row of `provider list`.
type ProviderSummary struct {
	ID               domain.ProviderID
	Protocol         string
	AuthModes        []string
	PendingEndpoints []string
}

// ProviderStatus is one row of `provider status`.
type ProviderStatus struct {
	ID         domain.ProviderID
	Ready      bool
	Reason     string
	ReasonCode string
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
		if len(a.gateRecords) < gateRecordCap {
			a.gateRecords = append(a.gateRecords, record)
		}
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

// GateRecords returns the metadata records the logger gate has emitted. It is
// the observation surface tests assert on; production reads them through the
// structured logger sink.
func (a *App) GateRecords() []map[string]string {
	return a.gateRecords
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
