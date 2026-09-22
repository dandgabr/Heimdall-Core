package cli

import (
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
