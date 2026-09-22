package importers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestImportAllPropagatesOpenCodeError covers ImportAll's error propagation from
// the first source.
func TestImportAllPropagatesOpenCodeError(t *testing.T) {
	home := t.TempDir()
	// A malformed opencode file makes importOpenCode fail; ImportAll must return
	// the error (and the partial results so far, which are empty).
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), `{bad`)
	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("malformed opencode file accepted")
	}
}

// TestImportAllPropagatesCommandCodeError covers the command-code branch.
func TestImportAllPropagatesCommandCodeError(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".commandcode", "auth.json"), `{bad`)
	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("malformed command-code file accepted")
	}
}

// TestImportCommandCodeEmptyKey covers the "no apiKey" skip.
func TestImportCommandCodeEmptyKey(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".commandcode", "auth.json"), `{"userId":"u"}`)
	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %+v, want none for an empty key", results)
	}
}

// TestImportCommandCodeDefaultLabel covers the label fallback when keyName is
// empty.
func TestImportCommandCodeDefaultLabel(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".commandcode", "auth.json"), `{"apiKey":"k-12345678"}`)
	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	results, err := im.ImportAll(context.Background())
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(results) != 1 || results[0].Label != "Command Code" {
		t.Fatalf("results = %+v, want the default label", results)
	}
}

// TestImportOpenCodeReadError covers a non-ENOENT read failure (the path is a
// directory).
func TestImportOpenCodeReadError(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("directory-as-file accepted")
	}
}

// TestImporterEnvAndHome covers the env/home resolution branches.
func TestImporterEnvAndHome(t *testing.T) {
	// An injected Env map is consulted.
	im := &Importer{Env: map[string]string{"HOME": "/env/home"}}
	if got := im.home(); got != "/env/home" {
		t.Errorf("home() = %q, want /env/home", got)
	}
	if got := im.env("HOME"); got != "/env/home" {
		t.Errorf("env(HOME) = %q", got)
	}

	// Explicit Home wins over Env.
	im2 := &Importer{Home: "/explicit", Env: map[string]string{"HOME": "/env/home"}}
	if got := im2.home(); got != "/explicit" {
		t.Errorf("home() = %q, want /explicit", got)
	}

	// No Env: falls back to the process environment via os.Getenv. Unset HOME
	// cannot be simulated safely, so assert it returns something non-empty.
	im3 := &Importer{}
	if got := im3.home(); got == "" {
		t.Error("home() returned empty with no configuration")
	}
}

// TestImportCommandCodeReadError covers the non-ENOENT read failure for the
// command-code source (the path is a directory).
func TestImportCommandCodeReadError(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".commandcode", "auth.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("directory-as-file accepted for command-code")
	}
}

// TestImportersHomeDotFallback covers the "." fallback when neither Home, env
// HOME, nor os.UserHomeDir resolve. Clearing HOME makes UserHomeDir error.
func TestImportersHomeDotFallback(t *testing.T) {
	t.Setenv("HOME", "")
	im := &Importer{Env: map[string]string{}}
	if got := im.home(); got != "." {
		t.Errorf("home() with no HOME = %q, want %q", got, ".")
	}
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this environment resolves a home directory without HOME")
	}
}

// TestStoreSealedError covers the seal-failure branch.
func TestStoreSealedError(t *testing.T) {
	im := &Importer{Store: newMemStore(), Sealer: failingSealer{}, Env: map[string]string{}}
	_, err := im.storeSealed(context.Background(), "z.ai", "L", "src", "value")
	if err == nil {
		t.Fatal("seal failure accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeImportFailed {
		t.Fatalf("err = %v, want import.failed", err)
	}
}

// TestImportErrorIsTyped covers the importError helper (0% before).
func TestImportErrorIsTyped(t *testing.T) {
	err := importError("opencode", context.Canceled)
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeImportFailed {
		t.Fatalf("importError = %v", err)
	}
	if de.Params["reason"] != "opencode" {
		t.Errorf("reason = %q", de.Params["reason"])
	}
}

type failingSealer struct{}

func (failingSealer) Seal([]byte) (string, error) {
	return "", context.DeadlineExceeded
}

// failingStore fails every Upsert, to cover the store-error branch.
type failingStore struct{ err error }

func (f failingStore) Upsert(context.Context, contracts.Credential) error { return f.err }
func (f failingStore) Get(context.Context, domain.CredentialID) (contracts.Credential, error) {
	return contracts.Credential{}, contracts.ErrNotFound
}

// TestStoreSealedUpsertError covers the Store.Upsert failure branch.
func TestStoreSealedUpsertError(t *testing.T) {
	im := &Importer{
		Store:  failingStore{err: errors.New("disk full")},
		Sealer: fakeSealer{},
		Env:    map[string]string{},
	}
	if _, err := im.storeSealed(context.Background(), "z.ai", "L", "src", "value"); err == nil {
		t.Fatal("upsert failure swallowed")
	}
}

// TestImportOpenCodeUpsertError covers ImportAll propagating a store error from
// the opencode source.
func TestImportOpenCodeUpsertError(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"),
		`{"zai-coding-plan":{"type":"api","key":"k"}}`)
	im := &Importer{
		Store:  failingStore{err: errors.New("disk full")},
		Sealer: fakeSealer{},
		Home:   home,
		Env:    map[string]string{},
	}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("import succeeded despite an upsert failure")
	}
}

// TestImporterHomeFallbacks covers home()'s env and os.UserHomeDir branches.
func TestImporterHomeFallbacks(t *testing.T) {
	// Env HOME is used when Home is empty.
	if got := (&Importer{Env: map[string]string{"HOME": "/env-home"}}).home(); got != "/env-home" {
		t.Errorf("home via env = %q", got)
	}
	// With an empty Env map and no Home, os.UserHomeDir is consulted; whatever
	// it returns must be non-empty or the "." fallback.
	got := (&Importer{Env: map[string]string{}}).home()
	if got == "" {
		t.Error("home returned empty with no configuration")
	}
}

// TestImportAntigravityReturnsNothing covers the documented no-op directly.
func TestImportAntigravityReturnsNothing(t *testing.T) {
	im := &Importer{Env: map[string]string{}}
	results, err := im.importAntigravity(context.Background())
	if err != nil {
		t.Fatalf("importAntigravity: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("importAntigravity = %+v, want none", results)
	}
}

// TestImportCommandCodeUpsertError covers importCommandCode's storeSealed error
// branch (a command-code source with a failing store).
func TestImportCommandCodeUpsertError(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".commandcode", "auth.json"), `{"apiKey":"k-12345678"}`)
	im := &Importer{
		Store:  failingStore{err: errors.New("disk full")},
		Sealer: fakeSealer{},
		Home:   home,
		Env:    map[string]string{},
	}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("import tolerated a command-code upsert failure")
	}
}

// TestImportAllAntigravityError covers ImportAll's propagation of an Antigravity
// error via the seam (the real source is a deliberate no-op that never errors).
func TestImportAllAntigravityError(t *testing.T) {
	old := antigravityImport
	antigravityImport = func(*Importer, context.Context) ([]Result, error) {
		return nil, errors.New("antigravity denied")
	}
	t.Cleanup(func() { antigravityImport = old })

	im := &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: t.TempDir(), Env: map[string]string{}}
	if _, err := im.ImportAll(context.Background()); err == nil {
		t.Fatal("ImportAll swallowed an Antigravity error")
	}
	antigravityImport = old
}
