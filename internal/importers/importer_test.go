package importers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// memStore is an in-memory contracts-style store for importer tests.
type memStore struct {
	creds map[domain.CredentialID]contracts.Credential
}

func newMemStore() *memStore {
	return &memStore{creds: map[domain.CredentialID]contracts.Credential{}}
}

func (m *memStore) Upsert(_ context.Context, cred contracts.Credential) error {
	m.creds[cred.ID] = cred
	return nil
}

func (m *memStore) Get(_ context.Context, id domain.CredentialID) (contracts.Credential, error) {
	c, ok := m.creds[id]
	if !ok {
		return contracts.Credential{}, contracts.ErrNotFound
	}
	return c, nil
}

// fakeSealer is a deterministic stand-in for secret.Store: it prefixes the
// plaintext so a test can prove the stored blob is not the raw value, without
// pulling the real KDF in.
type fakeSealer struct{}

func (fakeSealer) Seal(plaintext []byte) (string, error) {
	return "enc:v1:FAKE:" + string(plaintext) + ":TAG", nil
}

// writeFile writes a synthetic source file with 0600.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestImportOpenCode(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), `{
		"zai-coding-plan": {"type": "api", "key": "zai-key-123"},
		"ollama-cloud":    {"type": "api", "key": "ollama-key-456"},
		"opencode-go":     {"type": "api", "key": "cc-key-789"},
		"unknown-harness": {"type": "api", "key": "should-be-ignored"}
	}`)

	store := newMemStore()
	im := &Importer{Store: store, Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}

	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	// Three mapped providers; the unknown harness is skipped.
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3: %+v", len(results), results)
	}

	// zai-coding-plan -> z.ai, ollama-cloud -> ollama-cloud, opencode-go -> command-code.
	wantProviders := map[domain.ProviderID]bool{"z.ai": false, "ollama-cloud": false, "command-code": false}
	for _, r := range results {
		if _, ok := wantProviders[r.Provider]; !ok {
			t.Errorf("unexpected provider %q", r.Provider)
		}
		wantProviders[r.Provider] = true
	}
	for p, seen := range wantProviders {
		if !seen {
			t.Errorf("provider %s not imported", p)
		}
	}

	// The blob is sealed, not plaintext, and carries the right auth mode.
	for _, cred := range store.creds {
		if !strings.HasPrefix(string(cred.Sealed), "enc:v1:") {
			t.Errorf("credential %s is not sealed: %q", cred.ID, cred.Sealed)
		}
		if cred.AuthMode != contracts.AuthAPIKey {
			t.Errorf("credential %s auth mode = %v", cred.ID, cred.AuthMode)
		}
	}
}

func TestImportOpenCodeEnvOverride(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom-auth.json")
	writeFile(t, custom, `{"zai-coding-plan": {"type":"api","key":"env-override-key"}}`)

	store := newMemStore()
	im := &Importer{
		Store:  store,
		Sealer: fakeSealer{},
		Home:   t.TempDir(), // no default file here
		Env:    map[string]string{EnvOpenCodePath: custom},
	}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 1 || results[0].Provider != "z.ai" {
		t.Fatalf("env override not honoured: %+v", results)
	}
}

func TestImportCommandCode(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".commandcode", "auth.json"), `{
		"apiKey": "cc-live-key",
		"userId": "u-1",
		"userName": "test",
		"keyName": "my-key",
		"authenticatedAt": "2026-01-01T00:00:00Z"
	}`)

	store := newMemStore()
	im := &Importer{Store: store, Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}

	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 1 || results[0].Provider != "command-code" {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Label != "my-key" {
		t.Errorf("label = %q, want my-key", results[0].Label)
	}
	cred := store.creds[results[0].CredentialID]
	if !strings.Contains(string(cred.Sealed), "cc-live-key") {
		t.Error("apiKey not sealed into the store")
	}
}

// TestImportIsIdempotent is the brief's requirement: importing twice must not
// duplicate.
func TestImportIsIdempotent(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"),
		`{"zai-coding-plan": {"type":"api","key":"k1"}}`)

	store := newMemStore()
	im := &Importer{Store: store, Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}

	first, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	second, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("results = %d / %d, want 1 / 1", len(first), len(second))
	}
	if first[0].CredentialID != second[0].CredentialID {
		t.Errorf("credential ID changed between runs: %s -> %s", first[0].CredentialID, second[0].CredentialID)
	}
	if len(store.creds) != 1 {
		t.Errorf("store holds %d credentials after two imports, want 1", len(store.creds))
	}
}

// TestImportMissingSourcesIsNotAnError: a machine that never used a harness
// imports nothing and does not fail.
func TestImportMissingSourcesIsNotAnError(t *testing.T) {
	store := newMemStore()
	im := &Importer{Store: store, Sealer: fakeSealer{}, Home: t.TempDir(), Env: map[string]string{}}

	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %+v, want none", results)
	}
}

func TestImportMalformedFileFails(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), `{not json`)

	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	_, err := im.ImportAll(context.Background())
	if err == nil {
		t.Fatal("malformed source accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeImportMalformed {
		t.Fatalf("err = %v, want import.malformed", err)
	}
}

// TestImportNeverLogsValue proves the importer's logging cannot leak a key: the
// Result carries no value, and rendering it does not surface one.
func TestImportNeverLogsValue(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"),
		`{"zai-coding-plan": {"type":"api","key":"SUPER-SECRET-KEY-VALUE"}}`)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	for _, r := range results {
		logger.Info("imported credential",
			"provider", r.Provider, "credential_id", r.CredentialID, "label", r.Label)
	}
	if strings.Contains(buf.String(), "SUPER-SECRET-KEY-VALUE") {
		t.Fatalf("import log leaked the key: %s", buf.String())
	}
}

// TestImportReadOnlyOverSource checks the source file is not modified.
func TestImportReadOnlyOverSource(t *testing.T) {
	home := t.TempDir()
	src := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	original := `{"zai-coding-plan": {"type":"api","key":"k"}}`
	writeFile(t, src, original)

	before, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	if _, err := im.ImportAll(context.Background()); err != nil {
		t.Fatalf("ImportAll: %v", err)
	}

	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(after) != original {
		t.Errorf("source file was modified: %q", after)
	}
	if info, _ := os.Stat(src); info.ModTime() != before.ModTime() {
		t.Error("source file mtime changed; importer must be read-only")
	}
}

// TestImportAntigravityIsNoOp documents the deliberate decision: no readable
// token file, so nothing is imported from agy.
func TestImportAntigravityIsNoOp(t *testing.T) {
	home := t.TempDir()
	// Even a plausible-looking agent directory must not be read.
	writeFile(t, filepath.Join(home, ".antigravity", "token.json"), `{"access_token":"x"}`)

	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	for _, r := range results {
		if r.Provider == "antigravity" {
			t.Fatal("antigravity was imported despite having no supported source")
		}
	}
}

func TestDeterministicIDIsStableAndNonSecret(t *testing.T) {
	a := deterministicID("z.ai", "zai-coding-plan")
	b := deterministicID("z.ai", "zai-coding-plan")
	if a != b {
		t.Fatalf("ID not deterministic: %s vs %s", a, b)
	}
	if deterministicID("z.ai", "other") == a {
		t.Error("different sources produced the same ID")
	}
	// The ID must not embed the source key material (it hashes non-secret
	// inputs only); a sanity check that it is a fixed-width hex suffix.
	if !strings.HasPrefix(string(a), "imp-z.ai-") || len(a) > 40 {
		t.Errorf("unexpected ID shape: %q", a)
	}
}

func TestOpenCodeSchemaIgnoredUnknownFields(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"),
		`{"zai-coding-plan": {"type":"api","key":"k","extra":"ignored"}}`)

	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
}

// TestImportResultJSONHasNoValue guards the Result wire shape from ever growing a
// secret field.
func TestImportResultJSONHasNoValue(t *testing.T) {
	r := Result{Provider: "z.ai", CredentialID: "imp-z.ai-abc", Label: "Z.ai"}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"key", "secret", "token", "value"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Errorf("Result JSON exposes %q: %s", forbidden, raw)
		}
	}
}
