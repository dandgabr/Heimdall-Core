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
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
	"github.com/dandgabr/heimdall-core/internal/observability"
	"github.com/dandgabr/heimdall-core/internal/passthrough"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// App holds the assembled components of a running instance.
type App struct {
	Config config.Config
	Store  *store.Store
	Logger *slog.Logger
	Bundle *i18n.Bundle

	env    map[string]string
	server *http.Server
}

// Options are the inputs to Build.
type Options struct {
	Config config.Config
	// Env is the environment snapshot used to resolve passthrough credentials.
	Env map[string]string
	// LogOutput overrides the logger destination (tests, CLI).
	LogOutput io.Writer
}

// Build constructs the application: store, logger, i18n bundle and the HTTP
// handler graph, without starting the listener.
func Build(opts Options) (*App, error) {
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	bundle, err := i18n.New()
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

	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return nil, err
	}

	// The management token is generated once and written to a 0600 file. Neither
	// the value nor a recoverable form of it is ever logged: the database stores
	// only its SHA-256 hash (store.EnsureManagementTokenHash). The i18n message
	// carries the file path, never the token.
	token, created, err := st.EnsureManagementTokenHash()
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
	app.server = &http.Server{
		Addr:              cfg.Server.Addr(),
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return app, nil
}

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
	var handler http.Handler = middleware.ErrorEnvelope(mux)
	handler = middleware.LocalOnly(handler)
	handler = middleware.RequestID(domain.NewRequestID)(handler)
	handler = middleware.Recoverer(a.Logger)(handler)
	return handler
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
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return err
	}
	a.Logger.InfoContext(shutdownCtx, a.Bundle.Format(i18n.DefaultLanguage,
		domain.CodeStartupShutdown, nil))
	return nil
}

// Close releases the resources Build acquired.
func (a *App) Close() error {
	if a.Store != nil {
		return a.Store.Close()
	}
	return nil
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
