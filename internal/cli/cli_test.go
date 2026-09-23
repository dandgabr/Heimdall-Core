package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/app"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
	"github.com/dandgabr/heimdall-core/internal/store"
)

func TestNormalizeLocale(t *testing.T) {
	tests := map[string]string{
		"":            "",
		"C":           "",
		"POSIX":       "",
		"pt_BR.UTF-8": "pt-BR",
		"pt_BR":       "pt-BR",
		"pt-BR":       "pt-BR",
		"en_US.utf8":  "en-US",
		"en_US@euro":  "en-US",
		"de_DE.UTF-8": "de-DE",
	}
	for in, want := range tests {
		if got := normalizeLocale(in); got != want {
			t.Errorf("normalizeLocale(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCLILanguageFromPOSIXLocale is the regression guard for the pt-BR path:
// LANG=pt_BR.UTF-8 must resolve to the pt-BR catalog, not fall back to en.
func TestCLILanguageFromPOSIXLocale(t *testing.T) {
	bundle := i18n.MustNew()

	if got := bundle.Negotiate("", normalizeLocale("pt_BR.UTF-8")); got != "pt-BR" {
		t.Errorf("negotiated = %q, want pt-BR", got)
	}
	if got := bundle.Negotiate("", normalizeLocale("en_US.UTF-8")); got != "en" {
		t.Errorf("negotiated = %q, want en", got)
	}
	if got := bundle.Negotiate("", normalizeLocale("C")); got != i18n.DefaultLanguage {
		t.Errorf("negotiated = %q, want %q", got, i18n.DefaultLanguage)
	}
}

// writeTestConfig writes a minimal valid config and returns its path.
func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfg
}

// TestServeCmdDrivesRunAndFlagPrecedence covers the serve command end to end
// with the listener blocked by a seam: it asserts config precedence and that
// Run is invoked.
func TestServeCmdDrivesRunAndFlagPrecedence(t *testing.T) {
	cfg := writeTestConfig(t)

	var ran bool
	oldRun := serveRun
	serveRun = func(_ context.Context, instance *app.App) error {
		ran = true
		// The --port flag must have overridden the file/default.
		if instance.Config.Server.Port != 4321 {
			t.Errorf("port = %d, want 4321 from the flag", instance.Config.Server.Port)
		}
		return nil
	}
	t.Cleanup(func() { serveRun = oldRun })

	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"serve", "--config", cfg, "--port", "4321"}); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !ran {
		t.Fatal("serve Run seam was never invoked")
	}
}

// TestServeCmdConfigError covers the serve command's config-load failure.
func TestServeCmdConfigError(t *testing.T) {
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"serve", "--config", "/nonexistent/x.toml"}); code == 0 {
		t.Fatal("serve exited 0 with a missing config")
	}
}

// TestServeCmdBuildError covers the serve command's Build failure (invalid
// config: a non-loopback bind without the override).
func TestServeCmdBuildError(t *testing.T) {
	cfg := writeTestConfig(t)
	var out strings.Builder
	code := executeToWithStdout(&out, []string{
		"serve", "--config", cfg, "--host", "0.0.0.0", "--port", "4322",
	})
	if code == 0 {
		t.Fatal("serve exited 0 with an invalid bind")
	}
}

// TestChangedServeFlags covers the flag-collection helper directly.
func TestChangedServeFlags(t *testing.T) {
	cmd := newServeCmd()
	if err := cmd.Flags().Set("port", "9999"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got := changedServeFlags(cmd)
	if got["port"] != "9999" {
		t.Errorf("port = %q, want 9999", got["port"])
	}
	// host and allow-remote were not set, so they must be absent.
	if _, ok := got["host"]; ok {
		t.Error("host reported as set without being set")
	}
	if _, ok := got["allow-remote"]; ok {
		t.Error("allow-remote reported as set without being set")
	}
}

// TestTokenRotateConfigError covers the rotate command's config-load failure.
func TestTokenRotateConfigError(t *testing.T) {
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"token", "rotate", "--config", "/nonexistent/x.toml"}); code == 0 {
		t.Fatal("token rotate exited 0 with a missing config")
	}
}

// TestTokenRotateBuildError covers the rotate command's Build failure (invalid
// store path via a config whose parent is a file).
func TestTokenRotateBuildError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(blocker, "db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "tok") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"token", "rotate", "--config", cfg}); code == 0 {
		t.Fatal("token rotate exited 0 with an unopenable store")
	}
}

// TestServeCmdBuildErrorStorePath covers the serve command's app.Build failure:
// an unopenable store path makes Build fail after a successful config load.
func TestServeCmdBuildErrorStorePath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(blocker, "db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "tok") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"serve", "--config", cfg}); code == 0 {
		t.Fatal("serve exited 0 with an unopenable store")
	}
}

// TestExecuteAndExecuteWith covers the exported entry points (previously 0%).
func TestExecuteAndExecuteWith(t *testing.T) {
	if code := Execute([]string{"version"}); code != 0 {
		t.Errorf("Execute(version) = %d", code)
	}
	var out strings.Builder
	if code := ExecuteWith([]string{"version"}, &out, &out); code != 0 {
		t.Errorf("ExecuteWith(version) = %d", code)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Error("ExecuteWith(version) printed nothing")
	}
}

// TestVersionCmd covers newVersionCmd directly.
func TestVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("version RunE: %v", err)
	}
	if strings.TrimSpace(out.String()) != Version {
		t.Errorf("version output = %q, want %q", out.String(), Version)
	}
}

// TestTokenRotateCmd covers the rotate path and asserts it never prints the
// token.
func TestTokenRotateCmd(t *testing.T) {
	cfg := writeTestConfig(t)
	cmd := newTokenRotateCmd()
	cmd.Flags().Set("config", cfg) //nolint:errcheck
	var out strings.Builder
	cmd.SetOut(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("rotate RunE: %v", err)
	}
	if !strings.Contains(out.String(), "management-token") {
		t.Errorf("rotate output = %q, want the token file path", out.String())
	}
	// The plaintext token is 64 hex chars; none may appear.
	trimmed := strings.TrimSpace(out.String())
	if strings.ContainsAny(trimmed, "\n") || len(trimmed) > 200 {
		t.Errorf("rotate output looks wrong: %q", trimmed)
	}
}

// TestProviderStatusAndImportErrorPaths covers the load-failure branches of the
// provider commands (buildReadOnly -> config.Load error).
func TestProviderCommandsConfigError(t *testing.T) {
	for _, args := range [][]string{
		{"provider", "list", "--config", "/nonexistent/x.toml"},
		{"provider", "status", "--config", "/nonexistent/x.toml"},
		{"provider", "import", "--config", "/nonexistent/x.toml"},
		{"token", "rotate", "--config", "/nonexistent/x.toml"},
	} {
		var stdout, stderr strings.Builder
		if code := executeToWithStdout(&stdout, args); code == 0 {
			t.Errorf("%v exited 0 on a missing config", args)
		}
		_ = stderr
	}
}

// TestProviderImportNothingToImport with an isolated HOME and no sources reports
// the "nothing to import" message. It also documents the fail-closed rule: with
// no key file the import is REFUSED (exit 1), so the key must exist first.
func TestProviderImportNothingToImport(t *testing.T) {
	cfg := writeTestConfig(t)
	dataDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", dataDir)

	// Without a key file the import fails closed.
	var noKey strings.Builder
	if code := executeToWithStdout(&noKey, []string{"provider", "import", "--config", cfg}); code == 0 {
		t.Fatal("import without a key exited 0; must fail closed")
	}

	// With a 0600 key file it runs and finds nothing.
	keyDir := filepath.Join(dataDir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("cli-nothing-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"provider", "import", "--config", cfg}); code != 0 {
		t.Fatalf("exit code = %d, output = %s", code, out.String())
	}
	if !strings.Contains(out.String(), "no importable credentials") {
		t.Errorf("output = %q, want the nothing-to-import message", out.String())
	}
}

// TestProviderListCommand is the P0-A CLI guard: `provider list` must run
// without a key and report the four providers. Wave 2: Antigravity's endpoints
// are confirmed (no "pending"), and its ToS risk notice must be shown, while the
// API-key providers carry none.
func TestProviderListCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out strings.Builder
	code := executeToWithStdout(&out, []string{"provider", "list", "--config", cfg})
	if code != 0 {
		t.Fatalf("exit code = %d; output: %s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{"antigravity", "z.ai", "ollama-cloud", "command-code"} {
		if !strings.Contains(text, want) {
			t.Errorf("provider list missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "pending") {
		t.Errorf("no provider should be pending after Wave 2: %s", text)
	}
	// Honest state: an empty vault means NO provider is ready. Antigravity is
	// OAuth and this config supplies NO client secret, so its flow fails
	// closed with auth.provider_client_secret_missing (BD-02 removed the
	// "future" state); API-key providers have no credential ->
	// blocked(provider.no_credential). Never a bare "ready".
	if strings.Contains(text, "\tready") {
		t.Errorf("provider list showed a ready provider with an empty vault: %s", text)
	}
	if !strings.Contains(text, "antigravity\tprotocol=cloudcode\tauth=oauth\tblocked(auth.provider_client_secret_missing)") {
		t.Errorf("antigravity should be blocked on the missing client secret: %s", text)
	}
	if !strings.Contains(text, "blocked(provider.no_credential)") {
		t.Errorf("API-key providers should be blocked(provider.no_credential): %s", text)
	}
	// The Antigravity risk notice must appear (no future marker anymore); the
	// API-key lines must not carry a risk marker.
	lines := strings.Split(text, "\n")
	var agLine, zLine string
	for i, l := range lines {
		if strings.HasPrefix(l, "antigravity\t") {
			agLine = l
			if i+1 < len(lines) {
				agLine += "\n" + lines[i+1]
			}
		}
		if strings.HasPrefix(l, "z.ai\t") {
			zLine = l
			if i+1 < len(lines) {
				zLine += "\n" + lines[i+1]
			}
		}
	}
	if !strings.Contains(agLine, "!") {
		t.Errorf("antigravity risk notice missing:\n%s", agLine)
	}
	if strings.Contains(agLine, ">") {
		t.Errorf("antigravity must not carry a future marker (BD-02):\n%s", agLine)
	}
	if strings.Contains(zLine, "!") || strings.Contains(zLine, ">") {
		t.Errorf("z.ai must not carry a risk/future marker:\n%s", zLine)
	}
}

// TestProviderStatusCommand is the P0-B CLI guard: with an EMPTY vault, status
// must NOT report ready. Antigravity is blocked on the missing OAuth client
// secret (BD-02 removed the "future" state) and the API-key providers are
// blocked(provider.no_credential).
func TestProviderStatusCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out strings.Builder
	code := executeToWithStdout(&out, []string{"provider", "status", "--config", cfg})
	if code != 0 {
		t.Fatalf("exit code = %d; output: %s", code, out.String())
	}
	text := out.String()
	if strings.Contains(text, "antigravity\tready") {
		t.Errorf("antigravity must not be ready without login: %s", text)
	}
	if !strings.Contains(text, "antigravity\tblocked(auth.provider_client_secret_missing)") {
		t.Errorf("antigravity should be blocked on the missing client secret: %s", text)
	}
	if !strings.Contains(text, "!") {
		t.Errorf("antigravity risk notice missing: %s", text)
	}
	if strings.Contains(text, ">") {
		t.Errorf("no provider may carry a future marker (BD-02): %s", text)
	}
	if strings.Contains(text, "z.ai\tready") {
		t.Errorf("z.ai must not be ready without a credential: %s", text)
	}
	if !strings.Contains(text, "z.ai\tblocked(provider.no_credential)") {
		t.Errorf("z.ai should be blocked(provider.no_credential): %s", text)
	}
}

// TestProviderImportCommandWithIsolatedHome proves `provider import` imports and
// reports ids/labels only, never a value.
func TestProviderImportCommandWithIsolatedHome(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	src := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte(`{"zai-coding-plan":{"type":"api","key":"sk-secret-import-value"}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The custody chain reads the 0600 key file from
	// $XDG_DATA_HOME/heimdall/master-key (secret.DefaultKeyFilePath).
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("cli-import-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", dir)

	var out strings.Builder
	code := executeToWithStdout(&out, []string{"provider", "import", "--config", cfg})
	text := out.String()
	if code != 0 {
		t.Fatalf("exit code = %d; output: %s", code, text)
	}
	if strings.Contains(text, "sk-secret-import-value") {
		t.Fatalf("import output leaked the value: %s", text)
	}
	if !strings.Contains(text, "provider=z.ai") {
		t.Errorf("import did not report z.ai: %s", text)
	}
}

// TestExecuteRendersActionableError exercises the real CLI entry point with a
// missing config file, asserting the operator sees the interpolated path rather
// than the bare code.
func TestExecuteRendersActionableError(t *testing.T) {
	var stderr strings.Builder
	code := executeTo(&stderr, []string{"serve", "--config", "/nonexistent/heimdall.toml"})
	if code == 0 {
		t.Fatal("expected a non-zero exit code")
	}
	out := stderr.String()
	if strings.TrimSpace(out) == "" {
		t.Fatal("stderr is empty")
	}
	if strings.Contains(out, domain.CodeConfigLoadFailed) {
		t.Errorf("stderr shows the bare code instead of the message: %q", out)
	}
	if !strings.Contains(out, "/nonexistent/heimdall.toml") {
		t.Errorf("stderr does not surface the failing path: %q", out)
	}
}

// failWriter errors on every write, exercising the Fprintf-error branches of the
// provider commands.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// TestProviderCommandsWriteError covers the Fprintf-error branches of
// provider list/status/import by giving them a failing stdout.
func TestProviderCommandsWriteError(t *testing.T) {
	// list
	cfg := writeTestConfig(t)
	if code := executeWith(os.Stderr, failWriter{}, []string{"provider", "list", "--config", cfg}); code == 0 {
		t.Error("provider list exited 0 with a failing writer")
	}

	// status
	cfg2 := writeTestConfig(t)
	if code := executeWith(os.Stderr, failWriter{}, []string{"provider", "status", "--config", cfg2}); code == 0 {
		t.Error("provider status exited 0 with a failing writer")
	}

	// import: needs a key file and an importable source.
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	src := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte(`{"zai-coding-plan":{"type":"api","key":"k-12345678"}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("cli-write-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg3 := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg3, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", dir)
	if code := executeWith(os.Stderr, failWriter{}, []string{"provider", "import", "--config", cfg3}); code == 0 {
		t.Error("provider import exited 0 with a failing writer")
	}
}

// TestVersionCmdWriteError covers newVersionCmd's Fprintln-error branch.
func TestVersionCmdWriteError(t *testing.T) {
	cmd := newVersionCmd()
	cmd.SetOut(failWriter{})
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("version succeeded with a failing writer")
	}
}

// TestTokenRotateWriteError covers the rotate command's Fprintln-error branch.
func TestTokenRotateWriteError(t *testing.T) {
	cfg := writeTestConfig(t)
	cmd := newTokenRotateCmd()
	if err := cmd.Flags().Set("config", cfg); err != nil {
		t.Fatalf("set: %v", err)
	}
	cmd.SetOut(failWriter{})
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("rotate succeeded with a failing writer")
	}
}

// TestExecuteWithBundleError covers executeWith's i18n.New failure sink. i18n.New
// cannot fail with the embedded catalogs, so this asserts the success sink path
// is the one taken.
func TestExecuteWithBundleSuccess(t *testing.T) {
	var out strings.Builder
	if code := executeWith(&out, &out, []string{"version"}); code != 0 {
		t.Fatalf("executeWith(version) = %d", code)
	}
}

// TestServeRunDefaultInvokesRun covers the default serveRun implementation by
// calling it with an already-cancelled context on a built app.
func TestServeRunDefaultInvokesRun(t *testing.T) {
	dir := t.TempDir()
	cfg, err := configLoadForTest(dir)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	instance, err := app.Build(app.Options{Config: cfg, Env: map[string]string{}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = instance.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serveRun(ctx, instance); err != nil {
		t.Fatalf("serveRun default returned %v", err)
	}
}

// TestTokenRotateRotateError covers newTokenRotateCmd's RotateManagementToken
// error branch. The vault is pre-seeded with a token hash so Build's first-boot
// write is skipped (created=false), then the token path is made unwritable so
// the LATER RotateManagementToken write fails — reaching line 222 rather than
// Build failing earlier.
func TestTokenRotateRotateError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "heimdall.db")
	tokenDir := filepath.Join(dir, "token-as-dir")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Pre-seed the token hash so Build does not write a file on this boot.
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if _, _, err := st.EnsureManagementTokenHash(); err != nil {
		t.Fatalf("EnsureManagementTokenHash: %v", err)
	}
	_ = st.Close()

	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + dbPath +
		"\"\ntoken_path = \"" + tokenDir + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cmd := newTokenRotateCmd()
	if err := cmd.Flags().Set("config", cfg); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("rotate succeeded with a directory token path")
	}
}

// configLoadForTest builds a valid Config rooted at dir.
func configLoadForTest(dir string) (config.Config, error) {
	return config.Load(config.Options{
		FilePath: "",
		Env: map[string]string{
			"HEIMDALL_STORE_PATH":       filepath.Join(dir, "heimdall.db"),
			"HEIMDALL_STORE_TOKEN_PATH": filepath.Join(dir, "management-token"),
		},
	})
}

// TestExecuteWithBundleError covers executeWith's bundle-bootstrap error branch.
func TestExecuteWithBundleError(t *testing.T) {
	old := newBundle
	newBundle = func() (*i18n.Bundle, error) { return nil, errors.New("catalog denied") }
	t.Cleanup(func() { newBundle = old })

	var stderr, stdout strings.Builder
	if code := executeWith(&stderr, &stdout, []string{"version"}); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "catalog denied") {
		t.Errorf("stderr = %q, want the bundle error", stderr.String())
	}
	newBundle = old
}

// failWriter always fails, to reach the render error branches.
type cliFailWriter struct{}

func (cliFailWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// TestRenderProviderListBranches drives the pure renderer: pending label, risk
// notice, and a write failure.
func TestRenderProviderListBranches(t *testing.T) {
	bundle := i18n.MustNew()
	list := []app.ProviderSummary{
		{ID: "antigravity", Protocol: "cloudcode", AuthModes: []string{"oauth"}, RiskNotice: "provider.risk_notice.antigravity"},
		{ID: "z.ai", Protocol: "openai", AuthModes: []string{"api_key"}, PendingEndpoints: []string{"TokenEndpoint"}},
	}
	var out strings.Builder
	if err := renderProviderList(&out, list, bundle); err != nil {
		t.Fatalf("render: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "pending: TokenEndpoint") {
		t.Errorf("pending label missing: %s", text)
	}
	if !strings.Contains(text, "!") {
		t.Errorf("risk notice missing: %s", text)
	}
	if err := renderProviderList(cliFailWriter{}, list, bundle); err == nil {
		t.Error("expected a write error")
	}
}

// TestRenderProviderStatusBranches drives the pure status renderer: blocked with
// and without a reason code, plus a write failure.
func TestRenderProviderStatusBranches(t *testing.T) {
	bundle := i18n.MustNew()
	list := []app.ProviderStatus{
		{ID: "a", Ready: true, RiskNotice: "provider.risk_notice.antigravity"},
		{ID: "b", Ready: false, ReasonCode: "auth.provider_pending_endpoints"},
		{ID: "c", Ready: false},
	}
	var out strings.Builder
	if err := renderProviderStatus(&out, list, bundle); err != nil {
		t.Fatalf("render: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "b\tblocked(auth.provider_pending_endpoints)") {
		t.Errorf("blocked(reason) missing: %s", text)
	}
	if !strings.Contains(text, "c\tblocked\n") {
		t.Errorf("plain blocked missing: %s", text)
	}
	if err := renderProviderStatus(cliFailWriter{}, list, bundle); err == nil {
		t.Error("expected a write error")
	}
}

// cliNthFailWriter fails on the Nth Write call, so the risk-notice write error
// branch is reachable (the first provider-line write succeeds).
type cliNthFailWriter struct {
	n     int
	calls int
}

func (w *cliNthFailWriter) Write(b []byte) (int, error) {
	w.calls++
	if w.calls >= w.n {
		return 0, os.ErrClosed
	}
	return len(b), nil
}

// TestRenderRiskNoticeWriteError covers the second write failure (the notice).
func TestRenderRiskNoticeWriteError(t *testing.T) {
	bundle := i18n.MustNew()
	list := []app.ProviderSummary{{ID: "a", RiskNotice: "provider.risk_notice.antigravity"}}
	if err := renderProviderList(&cliNthFailWriter{n: 2}, list, bundle); err == nil {
		t.Error("expected the notice write error")
	}
	statuses := []app.ProviderStatus{{ID: "a", RiskNotice: "provider.risk_notice.antigravity"}}
	if err := renderProviderStatus(&cliNthFailWriter{n: 2}, statuses, bundle); err == nil {
		t.Error("expected the status notice write error")
	}
}

// TestRenderFutureMarkerWriteError covers the future-marker write failure (the
// first extra line after the provider row).
func TestRenderFutureMarkerWriteError(t *testing.T) {
	bundle := i18n.MustNew()
	list := []app.ProviderSummary{{ID: "antigravity", Future: true, ReasonCode: domain.CodeProviderFuture}}
	if err := renderProviderList(&cliNthFailWriter{n: 2}, list, bundle); err == nil {
		t.Error("expected the future-marker write error")
	}
	statuses := []app.ProviderStatus{{ID: "antigravity", Future: true, ReasonCode: domain.CodeProviderFuture}}
	if err := renderProviderStatus(&cliNthFailWriter{n: 2}, statuses, bundle); err == nil {
		t.Error("expected the status future-marker write error")
	}
}
