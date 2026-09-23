package auth

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file is the regression guard against a CLIENT SECRET (or any raw API key)
// being committed into the repository. A hardcoded `GOCSPX-…` in the Antigravity
// descriptor blocked a push via GitHub secret scanning; the value now comes from
// config/env, and this test stops it (or a peer) from ever returning.
//
// Scope: every tracked source file under internal/ and docs/. It is deliberately
// precise rather than entropy-shaped, so legitimate code (a `ClientSecret string`
// field, the OAuth form key `client_secret`, a fake value in a _test.go) does not
// trip it. The patterns target the ACTUAL leak shapes:
//
//   - `GOCSPX-` — the Google OAuth client-secret prefix (the leaked value);
//   - a NON-TEST Go file assigning `ClientSecret` a quoted literal — the field
//     must stay empty and be injected from config;
//   - a NON-TEST Go file containing an `sk-…` API-key literal.
//
// A _test.go may hold a fake literal (e.g. `ClientSecret: "SEC"`); that is test
// data, not a shipped secret. A real secret in a test is still caught if it
// carries the `GOCSPX-` prefix, which is scanned in EVERY file.

// gocspxRe matches the Google client-secret prefix anywhere.
var gocspxRe = regexp.MustCompile(`GOCSPX-[A-Za-z0-9_-]+`)

// hardcodedClientSecretRe matches a NON-TEST Go assignment of a quoted literal
// of plausible secret length to ClientSecret. The descriptor must not carry one.
var hardcodedClientSecretRe = regexp.MustCompile(`ClientSecret\s*[:=]\s*"[^"]{20,}"`)

// skLiteralRe matches an API-key-looking `sk-…` literal (excluding the redactor's
// short, obviously-fake fixtures).
var skLiteralRe = regexp.MustCompile(`"sk-[A-Za-z0-9_-]{16,}"`)

// secretScanExempt lists file path suffixes that legitimately mention these
// strings: the redactor defines the patterns, and this guard defines them.
var secretScanExempt = []string{
	"internal/i18n/redact.go",
	"internal/auth/secret_scan_test.go",
}

func TestNoCommittedClientSecret(t *testing.T) {
	root := filepath.Join("..", "..")
	var violations []string

	for _, dir := range []string{"internal", "docs"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				// Skip VCS/build noise if any slipped under a scanned dir.
				if info.Name() == ".git" || info.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			// Only text sources can carry a literal; skip binaries.
			switch filepath.Ext(path) {
			case ".go", ".md", ".json", ".toml", ".yaml", ".yml", ".mjs", ".js":
			default:
				return nil
			}
			rel := filepath.ToSlash(mustRel(t, root, path))
			for _, ex := range secretScanExempt {
				if strings.HasSuffix(rel, ex) {
					return nil
				}
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			text := string(raw)
			isTest := strings.HasSuffix(rel, "_test.go") || strings.Contains(rel, "/test")

			if loc := gocspxRe.FindString(text); loc != "" && !strings.Contains(loc, "REDACTED") {
				violations = append(violations, rel+": contains a GOCSPX client-secret literal")
			}
			if !isTest {
				if hardcodedClientSecretRe.MatchString(text) {
					violations = append(violations, rel+": hardcodes ClientSecret with a literal (must come from config)")
				}
				if skLiteralRe.MatchString(text) {
					violations = append(violations, rel+": contains an sk- API-key literal")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	for _, v := range violations {
		t.Errorf("committed-secret guard: %s", v)
	}
}

func mustRel(t *testing.T, base, path string) string {
	t.Helper()
	rel, err := filepath.Rel(base, path)
	if err != nil {
		t.Fatalf("rel %s: %v", path, err)
	}
	return rel
}
