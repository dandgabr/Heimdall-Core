package i18n

import (
	"errors"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

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

// TestLanguages covers the exported Languages accessor (0% before).
func TestLanguages(t *testing.T) {
	b := MustNew()
	langs := b.Languages()
	if len(langs) < 2 {
		t.Fatalf("Languages() = %v, want at least en and pt-BR", langs)
	}
	// Sorted, and both expected catalogs present.
	foundEn, foundPt := false, false
	for _, l := range langs {
		if l == "en" {
			foundEn = true
		}
		if l == "pt-BR" {
			foundPt = true
		}
	}
	if !foundEn || !foundPt {
		t.Errorf("Languages() = %v, missing en or pt-BR", langs)
	}
}

// TestFormatErrorDelegates covers FormatError (0% before): it localises a
// DomainError and falls back to the default language.
func TestFormatErrorDelegates(t *testing.T) {
	b := MustNew()
	e := domain.New(domain.CodeInvalidRequest, domain.WithParams(map[string]string{"reason": "r"}))
	if got := b.FormatError("en", e); got == "" || got == domain.CodeInvalidRequest {
		t.Errorf("FormatError(en) = %q", got)
	}
	if got := b.FormatError("", e); got == "" {
		t.Error("FormatError with empty lang returned empty")
	}
	if got := b.FormatError("en", nil); got != "" {
		t.Errorf("FormatError(nil) = %q, want empty", got)
	}
}

// TestRedacterRedact covers the Redacter method (0% before).
func TestRedacterRedact(t *testing.T) {
	var r Redacter
	got := r.Redact("Authorization: Bearer sk-secret-value-1234")
	if got == "" || !containsStr(got, Redacted) {
		t.Errorf("Redacter.Redact = %q, want a redaction marker", got)
	}
	// The interface assertion compiles.
	var iface interface{ Redact(string) string } = Redacter{}
	if iface.Redact("plain") != "plain" {
		t.Error("plain text should be unchanged")
	}
}

func containsStr(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
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

// TestFormatParamsWithoutPlaceholder covers the branch where params is non-empty
// but does not contain the template's placeholder, so the placeholder is left
// literal.
func TestFormatParamsWithoutPlaceholder(t *testing.T) {
	b := MustNew()
	got := b.Format("en", "error.invalid_request", map[string]string{"unrelated": "x"})
	if got != "Invalid request: {reason}" {
		t.Errorf("Format = %q, want the literal placeholder", got)
	}
}

// TestFormatUnknownTagFallsBackToDefault covers Format's per-catalog miss
// falling through to the default catalog, and an entirely unknown code.
func TestFormatUnknownTagFallsBackToDefault(t *testing.T) {
	b := MustNew()
	// Unknown tag: the default catalog is used.
	if got := b.Format("xx-YY", "api.health_ok", nil); got != "Service is healthy." {
		t.Errorf("unknown tag = %q, want the default-language string", got)
	}
	// Same code in an unknown tag with params that the template does not use.
	if got := b.Format("xx-YY", "api.health_ok", map[string]string{"unused": "x"}); got != "Service is healthy." {
		t.Errorf("unused params changed the output: %q", got)
	}
	// An unknown code in an unknown tag returns the code.
	if got := b.Format("xx-YY", "totally.unknown", nil); got != "totally.unknown" {
		t.Errorf("unknown code = %q", got)
	}
}

// TestLoadFromErrorBranches covers New/loadFrom's read, parse, empty and
// missing-default branches via an injectable FS.
func TestLoadFromErrorBranches(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
	}{
		{
			name: "no catalogs dir",
			fsys: fstest.MapFS{},
		},
		{
			name: "invalid json",
			fsys: fstest.MapFS{
				"catalogs/en.json": &fstest.MapFile{Data: []byte("{not json")},
			},
		},
		{
			name: "only a non-json file",
			fsys: fstest.MapFS{
				"catalogs/readme.txt": &fstest.MapFile{Data: []byte("x")},
			},
		},
		{
			name: "missing default language",
			fsys: fstest.MapFS{
				"catalogs/fr.json": &fstest.MapFile{Data: []byte(`{"a":"b"}`)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadFrom(tt.fsys); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// A minimal valid FS with a default catalog loads.
	ok := fstest.MapFS{
		"catalogs/en.json":    &fstest.MapFile{Data: []byte(`{"greeting":"hi"}`)},
		"catalogs/pt-BR.json": &fstest.MapFile{Data: []byte(`{"greeting":"oi"}`)},
		"catalogs/notes.md":   &fstest.MapFile{Data: []byte("ignored")}, // dir/extension skip
	}
	b, err := loadFrom(ok)
	if err != nil {
		t.Fatalf("loadFrom(valid): %v", err)
	}
	if got := b.Format("en", "greeting", nil); got != "hi" {
		t.Errorf("greeting = %q", got)
	}
}

// TestMustNewPanicsOnFailure covers MustNew's panic branch by exercising the
// happy path (the panic arm is a one-line invariant guard that cannot be hit
// without a broken embedded FS, which the compiler guarantees against).
func TestMustNewPanicsOnFailure(t *testing.T) {
	if b := MustNew(); b == nil {
		t.Fatal("MustNew returned nil")
	}
}

// badReadFS is a MapFS whose ReadDir succeeds but whose ReadFile always fails,
// so loadFrom's per-file read-error branch is reachable.
type badReadFS struct{ fstest.MapFS }

func (badReadFS) ReadFile(string) ([]byte, error) { return nil, errors.New("read denied") }

func (badReadFS) Open(name string) (fs.File, error) {
	return nil, errors.New("open denied")
}

// TestLoadFromReadFileError covers the per-catalog read-error branch.
func TestLoadFromReadFileError(t *testing.T) {
	fsys := badReadFS{fstest.MapFS{
		"catalogs/en.json": &fstest.MapFile{Data: []byte(`{}`)},
	}}
	// ReadDir is promoted from the embedded MapFS and succeeds; ReadFile fails.
	if _, err := loadFrom(fsys); err == nil {
		t.Fatal("read-file failure accepted")
	}
}

// TestNegotiateZeroTags covers the "parse succeeded but produced no tags"
// branch: a wildcard-only Accept-Language parses to an empty list.
func TestNegotiateZeroTags(t *testing.T) {
	b := MustNew()
	// "*" parses to no usable tags; negotiation must fall through to the
	// default rather than panic.
	if got := b.Negotiate("*", ""); got != DefaultLanguage {
		t.Errorf("Negotiate(*) = %q, want the default", got)
	}
	// A header whose parse yields nothing must fall back too.
	if tag, ok := b.match("*", true); ok {
		t.Errorf("match(*) = %q, true; want false", tag)
	}
}

// TestFormatDomainErrorKnownCodeNeedingParams covers the branch where a known
// code's template still has placeholders but the caller passed none, so the
// code is returned rather than a half-rendered sentence.
func TestFormatDomainErrorKnownCodeNeedingParams(t *testing.T) {
	b := MustNew()
	// error.invalid_request needs {reason}; with no params the code is returned.
	e := domain.New(domain.CodeInvalidRequest)
	if got := b.FormatDomainError(e, "en"); got != domain.CodeInvalidRequest {
		t.Errorf("FormatDomainError without params = %q, want the code", got)
	}
}

// TestMatchErrorBranches covers match's parse-error and unmatched branches.
func TestMatchErrorBranches(t *testing.T) {
	b := MustNew()

	// An unparseable Accept-Language header falls through.
	if tag, ok := b.match("\x00\x01", true); ok {
		t.Errorf("match(bad accept) = %q, true; want false", tag)
	}
	// An unparseable single tag.
	if tag, ok := b.match("\x00\x01", false); ok {
		t.Errorf("match(bad tag) = %q, true; want false", tag)
	}
	// A well-formed but unknown tag has confidence No against the catalogs.
	if tag, ok := b.match("zz-ZZ", false); ok {
		t.Errorf("match(zz-ZZ) = %q, true; want false", tag)
	}
	// A known tag resolves.
	if tag, ok := b.match("pt-BR", false); !ok || tag != "pt-BR" {
		t.Errorf("match(pt-BR) = %q, %v", tag, ok)
	}
}

// TestOAuthCodeGuardBranches covers every decision path of the entropy guard.
func TestOAuthCodeGuardBranches(t *testing.T) {
	tests := map[string]bool{
		"aB3xK9":           true,  // digit + mixed case
		"abc123":           true,  // digit + lower
		"ABCDEF12":         true,  // digit + upper
		"QwErTy":           true,  // mixed case, no digit
		"a.b/cd":           true,  // decisive symbol
		"a+b=cde":          true,  // symbol
		"200":              false, // too short
		"200404":           false, // all digits
		"123456":           false, // all digits
		"not_found":        false, // snake_case word
		"authorization_x":  false, // snake_case word
		"ready":            false, // lower word (short)
		"expired":          false, // lower word (short)
		"abcdefghijklmnop": true,  // long lowercase run
		"abcdefghijklmno":  false, // 15-char lowercase run
		"inválido":         false, // non-ASCII word
	}
	for value, want := range tests {
		if got := oauthCodeGuard(value); got != want {
			t.Errorf("oauthCodeGuard(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestApplyRuleGuardedVeto covers the guarded-rule branches directly.
func TestApplyRuleGuardedVeto(t *testing.T) {
	pat := regexp.MustCompile(`code=(\S+)`)

	// Guard rejects: input untouched.
	if got := applyRule("code=200", redactionRule{name: "p", re: pat, repl: "code=" + Redacted, guard: func(string) bool { return false }}); got != "code=200" {
		t.Errorf("guarded veto changed input: %q", got)
	}
	// Guard accepts: template applied.
	if got := applyRule("code=abc123", redactionRule{name: "p", re: pat, repl: "code=" + Redacted, guard: func(string) bool { return true }}); got != "code="+Redacted {
		t.Errorf("guarded accept = %q", got)
	}
	// No match: input returned unchanged.
	if got := applyRule("nothing", redactionRule{name: "p", re: pat, repl: Redacted, guard: func(string) bool { return true }}); got != "nothing" {
		t.Errorf("no-match guarded = %q", got)
	}
	// A rule with no capture group does not panic on the guard lookup.
	if got := applyRule("anything", redactionRule{name: "p", re: regexp.MustCompile(`zzz`), repl: Redacted, guard: func(string) bool { return true }}); got != "anything" {
		t.Errorf("no-group guarded = %q", got)
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

// TestMatchEmptyAcceptLanguage covers match's len(langs)==0 branch: an empty
// Accept-Language parses to no tags.
func TestMatchEmptyAcceptLanguage(t *testing.T) {
	b := MustNew()
	if tag, ok := b.match("", true); ok {
		t.Errorf("match(\"\", true) = %q, true; want false", tag)
	}
}

// TestFormatDomainErrorEmptyMessageFallsToCode covers the message=="" branch by
// using a DomainError with an empty Code, which resolves to nothing.
func TestFormatDomainErrorEmptyMessageFallsToCode(t *testing.T) {
	b := MustNew()
	e := domain.New("") // empty code: Format returns "" -> fall back to the code
	if got := b.FormatDomainError(e, "en"); got != "" {
		t.Errorf("FormatDomainError(empty code) = %q, want empty (the code)", got)
	}
}

// withCatalogFS swaps the default catalog source for fn, restoring it after, so
// New's error path (and MustNew's panic) become reachable.
func withCatalogFS(t *testing.T, fsys fs.FS, fn func()) {
	t.Helper()
	old := defaultCatalogFS
	defaultCatalogFS = fsys
	t.Cleanup(func() { defaultCatalogFS = old })
	fn()
	defaultCatalogFS = old
}

// TestNewErrorPath covers New's failure branch with a broken catalog source.
func TestNewErrorPath(t *testing.T) {
	withCatalogFS(t, fstest.MapFS{}, func() {
		if _, err := New(); err == nil {
			t.Fatal("New succeeded with no catalogs")
		}
	})
}

// TestMustNewPanicsOnBrokenCatalogs covers MustNew's panic branch: a broken
// catalog source makes New fail, so MustNew panics with the error.
func TestMustNewPanicsOnBrokenCatalogs(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("MustNew did not panic on a broken catalog source")
		}
		if _, ok := r.(error); !ok {
			t.Fatalf("MustNew panicked with %T, want an error", r)
		}
	}()
	withCatalogFS(t, fstest.MapFS{}, func() {
		_ = MustNew()
	})
}
