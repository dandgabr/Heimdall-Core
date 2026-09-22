package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
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

// TestProviderListCommand is the P0-A CLI guard: `provider list` must run
// without a key and report the providers plus the pending Antigravity fields.
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
	for _, want := range []string{"antigravity", "z.ai", "ollama-cloud", "command-code", "pending"} {
		if !strings.Contains(text, want) {
			t.Errorf("provider list missing %q: %s", want, text)
		}
	}
}

// TestProviderStatusCommand reports readiness honestly.
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
	if !strings.Contains(text, "antigravity\tblocked") {
		t.Errorf("antigravity should be blocked: %s", text)
	}
	if !strings.Contains(text, "z.ai\tready") {
		t.Errorf("z.ai should be ready: %s", text)
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
