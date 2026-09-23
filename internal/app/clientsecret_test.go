package app

import (
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/auth"
	"github.com/dandgabr/heimdall-core/internal/auth/oauth"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// buildSecretApp builds an app with a given list of provider configs, so the
// wiring's secret injection can be exercised without a full provider app.
func buildSecretApp(t *testing.T, env map[string]string, providers []config.ProviderConfig) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = filepath.Join(dir, "heimdall.db")
	cfg.Store.TokenPath = filepath.Join(dir, "management-token")
	cfg.Providers = providers

	salt, _ := secret.NewSalt()
	a, err := Build(Options{
		Config: cfg,
		Env:    env,
		SecretOptions: &secret.Options{
			Salt:   salt,
			Params: secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32},
			Custody: secret.Custody{
				KeyFilePath:      filepath.Join(dir, "master-key"),
				AllowEnvOverride: true,
				Env:              map[string]string{"HEIMDALL_MASTER_KEY": "secret-test-material"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestWiringInjectsClientSecretFromConfig proves the composition root resolves
// the per-provider client secret from the config and the flow builds.
func TestWiringInjectsClientSecretFromConfig(t *testing.T) {
	a := buildSecretApp(t, map[string]string{}, []config.ProviderConfig{
		{ID: "antigravity", ClientSecret: "config-supplied-secret"},
	})
	flow, err := a.Flows.Build("antigravity")
	if err != nil {
		t.Fatalf("Build(antigravity): %v", err)
	}
	if _, ok := flow.(*oauth.AntigravityFlow); !ok {
		t.Fatalf("flow = %T, want *oauth.AntigravityFlow", flow)
	}
}

// TestWiringInjectsClientSecretFromEnv proves the env-named form works end to
// end: the config names a variable, the injected env supplies the value.
func TestWiringInjectsClientSecretFromEnv(t *testing.T) {
	a := buildSecretApp(t, map[string]string{"AG_CLIENT_SECRET": "from-env-secret"}, []config.ProviderConfig{
		{ID: "antigravity", ClientSecretEnv: "AG_CLIENT_SECRET"},
	})
	if _, err := a.Flows.Build("antigravity"); err != nil {
		t.Fatalf("Build(antigravity): %v", err)
	}
}

// TestWiringMissingClientSecretFailsClosed proves the app's flow factory refuses
// Antigravity when no secret was configured, with the typed code — never a
// placeholder.
func TestWiringMissingClientSecretFailsClosed(t *testing.T) {
	a := buildSecretApp(t, map[string]string{}, nil)
	_, err := a.Flows.Build("antigravity")
	if err == nil {
		t.Fatal("Build(antigravity) succeeded without a configured secret")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeAuthProviderClientSecretMissing {
		t.Fatalf("err = %v, want %s", err, domain.CodeAuthProviderClientSecretMissing)
	}
}

// TestWiringSecretNotOnDescriptor proves the package-level descriptor stays
// secret-free after the app injects one: injection must not mutate the shared
// descriptor map.
func TestWiringSecretNotOnDescriptor(t *testing.T) {
	a := buildSecretApp(t, map[string]string{}, []config.ProviderConfig{
		{ID: "antigravity", ClientSecret: "injected-secret"},
	})
	if _, err := a.Flows.Build("antigravity"); err != nil {
		t.Fatalf("Build(antigravity): %v", err)
	}
	desc, err := auth.Descriptor("antigravity")
	if err != nil {
		t.Fatalf("Descriptor: %v", err)
	}
	if desc.ClientSecret != "" {
		t.Fatalf("the shared descriptor was mutated with a secret: %q", desc.ClientSecret)
	}
}
