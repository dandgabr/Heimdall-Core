package security

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// mustBundle loads the embedded catalogs for catalog-coverage assertions.
func mustBundle(t *testing.T) *i18n.Bundle {
	t.Helper()
	b, err := i18n.New()
	if err != nil {
		t.Fatalf("i18n.New: %v", err)
	}
	return b
}

// TestMapJSONStringsRewritesOnlyChangedTokens pins the scanner contract: the
// walk is byte-faithful for unchanged tokens (escapes included) and rewrites
// only what fn changed.
func TestMapJSONStringsRewritesOnlyChangedTokens(t *testing.T) {
	original := `{"model":"g","notes":["say \"hi\" to Bearer abc123def","café \u00e9 ok"],"n":12,"nested":{"k":"clean"}}`
	want := `{"model":"g","notes":["say \"hi\" to @@MASKED@@","café \u00e9 ok"],"n":12,"nested":{"k":"clean"}}`

	out, hits, err := mapJSONStrings([]byte(original), func(s string) string {
		return strings.ReplaceAll(s, "Bearer abc123def", RedactedSentinel)
	})
	if err != nil {
		t.Fatalf("mapJSONStrings: %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if string(out) != want {
		t.Fatalf("output mismatch:\n got %s\nwant %s", out, want)
	}
}

// RedactedSentinel is a test-local replacement value with no relation to the
// i18n literal, so an accidental pass-through cannot satisfy the assertion.
const RedactedSentinel = "@@MASKED@@"

// TestMapJSONStringsByteIdenticalWhenClean proves a no-match body is returned
// byte-identical (the prefix-freeze friendship property).
func TestMapJSONStringsByteIdenticalWhenClean(t *testing.T) {
	body := []byte(`{"a":"x","b":1,"c":[true,null,"y"],"d":"z"}`)
	out, hits, err := mapJSONStrings(body, func(s string) string { return s })
	if err != nil {
		t.Fatalf("mapJSONStrings: %v", err)
	}
	if hits != 0 {
		t.Fatalf("hits = %d, want 0", hits)
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("clean body changed: %s", out)
	}
	if len(out) > 0 && &out[0] != &body[0] {
		t.Fatal("clean body was copied instead of returned as-is")
	}
}

// TestMapJSONStringsEmptyAndInvalid covers the entry guards: an empty body is
// a no-op and invalid JSON fails closed with error.invalid_request.
func TestMapJSONStringsEmptyAndInvalid(t *testing.T) {
	if out, hits, err := mapJSONStrings(nil, func(s string) string { return s }); err != nil || hits != 0 || out != nil {
		t.Fatalf("empty body: out=%s hits=%d err=%v", out, hits, err)
	}

	out, hits, err := mapJSONStrings([]byte(`{"a":`), func(s string) string { return s })
	if err == nil {
		t.Fatal("invalid body: want error")
	}
	if out != nil || hits != 0 {
		t.Fatalf("invalid body: out=%s hits=%d", out, hits)
	}
	if !strings.Contains(err.Error(), "error.invalid_request") {
		t.Fatalf("error = %v, want code error.invalid_request", err)
	}
}

// TestMapJSONStringsInfallibleDecode pins the invariant that lets the scanner
// carry no dead error path: for every body that passes json.Valid — including
// escaped quotes, unicode escapes, lone surrogates and invalid UTF-8 inside
// strings — the walk returns nil error.
func TestMapJSONStringsInfallibleDecode(t *testing.T) {
	cases := []string{
		`{"a":"\u00e9 \ud800 lone","b":"tab\there"}`,
		`{"raw":"` + string([]byte{0xff, 0xfe}) + `","w":"\\ backslash"}`,
		`["quote\"inside","multi\nline"]`,
		`{"key with \"escape\"":"value"}`,
	}
	for _, body := range cases {
		if !json.Valid([]byte(body)) {
			t.Fatalf("test corpus bug: %q is not valid JSON", body)
		}
		if _, _, err := mapJSONStrings([]byte(body), func(s string) string { return s }); err != nil {
			t.Errorf("valid body %q errored: %v", body, err)
		}
	}
}

// TestEnvelopeJSONDeterministic pins byte-stability of the refusal envelope.
func TestEnvelopeJSONDeterministic(t *testing.T) {
	a := envelopeJSON("security.pii_blocked", map[string]string{"types": "email,cpf", "aaa": "1"})
	b := envelopeJSON("security.pii_blocked", map[string]string{"aaa": "1", "types": "email,cpf"})
	if !bytes.Equal(a, b) {
		t.Fatalf("envelope not deterministic:\n%s\n%s", a, b)
	}
	var dec envelope
	if err := json.Unmarshal(a, &dec); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if dec.Error.Code != "security.pii_blocked" || dec.Error.Params["types"] != "email,cpf" {
		t.Fatalf("envelope body = %s", a)
	}
}

// TestI18nCatalogCoversSecurityCodes proves the refusal codes render in both
// catalogs (an unknown code would surface as a raw key to clients).
func TestI18nCatalogCoversSecurityCodes(t *testing.T) {
	bundle := mustBundle(t)
	codes := map[string]map[string]string{
		"security.rate_limited":       {"retry_after": "3"},
		"security.destination_denied": {"host": "169.254.169.254"},
		"security.injection_detected": nil,
		"security.pii_blocked":        {"types": "email"},
	}
	for _, lang := range bundle.Languages() {
		for code, params := range codes {
			msg := bundle.Format(lang, code, params)
			if msg == code {
				t.Errorf("catalog %s is missing %s", lang, code)
			}
			if strings.Contains(msg, "{") {
				t.Errorf("catalog %s: %s rendered with a literal placeholder: %s", lang, code, msg)
			}
		}
	}
}
