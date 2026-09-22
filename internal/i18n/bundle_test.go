package i18n

import (
	"errors"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestFormatDomainErrorInterpolatesAndLocalises is the P2 regression guard: the
// rendered message must contain the interpolated params, not the bare code.
func TestFormatDomainErrorInterpolatesAndLocalises(t *testing.T) {
	b := MustNew()

	err := domain.New(domain.CodeStoreVaultPermissions, domain.WithParams(map[string]string{
		"path": "/home/u/.local/share/heimdall/heimdall.db",
		"mode": "0644",
	}))

	tests := []struct {
		name string
		lang string
		want []string
	}{
		{
			name: "en",
			lang: "en",
			want: []string{"/home/u/.local/share/heimdall/heimdall.db", "0644", "0600", "chmod 600"},
		},
		{
			name: "pt-BR",
			lang: "pt-BR",
			want: []string{"/home/u/.local/share/heimdall/heimdall.db", "0644", "0600", "chmod 600", "recusando"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := b.FormatDomainError(err, tt.lang)
			if got == err.Code {
				t.Fatalf("returned the bare code %q", got)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("message %q missing %q", got, want)
				}
			}
		})
	}
}

func TestFormatDomainErrorUnknownCodeFallsBackToCode(t *testing.T) {
	b := MustNew()
	err := domain.New("totally.unknown.code", domain.WithParams(map[string]string{"x": "y"}))
	if got := b.FormatDomainError(err, "en"); got != "totally.unknown.code" {
		t.Errorf("FormatDomainError = %q, want the code", got)
	}
}

func TestFormatDomainErrorKnownCodeWithoutParamsFallsBackToCode(t *testing.T) {
	b := MustNew()
	// error.invalid_request needs {reason}; with no params the template would
	// render a broken sentence, so the code is returned instead.
	err := domain.New(domain.CodeInvalidRequest)
	if got := b.FormatDomainError(err, "en"); got != domain.CodeInvalidRequest {
		t.Errorf("FormatDomainError = %q, want the code", got)
	}
}

func TestFormatDomainErrorNonDomainErrorUsesText(t *testing.T) {
	b := MustNew()
	got := b.FormatDomainError(errors.New("plain failure"), "en")
	if got != "plain failure" {
		t.Errorf("FormatDomainError = %q, want the error text", got)
	}
}

func TestFormatDomainErrorRedactsParamsAndMessage(t *testing.T) {
	b := MustNew()
	secret := strings.Repeat("ab", 32)
	err := domain.New(domain.CodeConfigLoadFailed, domain.WithParams(map[string]string{
		"reason": "token=" + secret,
	}))
	got := b.FormatDomainError(err, "en")
	if strings.Contains(got, secret) {
		t.Fatalf("secret leaked through FormatDomainError: %q", got)
	}
	if !strings.Contains(got, Redacted) {
		t.Errorf("no redaction marker: %q", got)
	}
}

func TestFormatDomainErrorNil(t *testing.T) {
	b := MustNew()
	if got := b.FormatDomainError(nil, "en"); got != "" {
		t.Errorf("FormatDomainError(nil) = %q, want empty", got)
	}
}

func TestFormatNamedPlaceholders(t *testing.T) {
	b := MustNew()

	got := b.Format("en", "error.invalid_request", map[string]string{"reason": "missing model"})
	want := "Invalid request: missing model"
	if got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func TestFormatMissingPlaceholderLeftLiteral(t *testing.T) {
	b := MustNew()
	got := b.Format("en", "error.invalid_request", nil)
	want := "Invalid request: {reason}"
	if got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func TestFormatUnknownCodeReturnsCode(t *testing.T) {
	b := MustNew()
	if got := b.Format("en", "nope.missing", nil); got != "nope.missing" {
		t.Errorf("Format = %q, want the code back", got)
	}
}

func TestFallbackToDefaultLanguage(t *testing.T) {
	b := MustNew()
	// pt-BR catalog is missing this key in the fixture below only if removed;
	// here the fallback path is exercised by asking for a catalog tag that does
	// not exist.
	got := b.Format("de-DE", "api.health_ok", nil)
	want := "Service is healthy."
	if got != want {
		t.Errorf("Format = %q, want %q (fallback to en)", got, want)
	}
}

func TestNegotiatePrecedence(t *testing.T) {
	b := MustNew()

	tests := []struct {
		name       string
		accept     string
		preference string
		want       string
	}{
		{name: "accept-language wins", accept: "pt-BR,en;q=0.8", preference: "en", want: "pt-BR"},
		{name: "preference when no header", accept: "", preference: "pt-BR", want: "pt-BR"},
		{name: "fallback to en", accept: "", preference: "", want: "en"},
		{name: "unknown header falls to preference", accept: "zz", preference: "pt-BR", want: "pt-BR"},
		{name: "region matches base catalog", accept: "pt-PT", preference: "", want: "pt-BR"},
		{name: "en-US matches en", accept: "en-US", preference: "", want: "en"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := b.Negotiate(tt.accept, tt.preference); got != tt.want {
				t.Errorf("Negotiate(%q, %q) = %q, want %q", tt.accept, tt.preference, got, tt.want)
			}
		})
	}
}
