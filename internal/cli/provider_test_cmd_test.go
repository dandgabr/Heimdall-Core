package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// setupProviderTestCLI writes a config pointing z.ai at srvURL (loopback,
// allow_loopback) plus a custody key, and imports an API key into the vault via
// the opencode source. It returns the config path.
func setupProviderTestCLI(t *testing.T, srvURL string) string {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	src := filepath.Join(home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte(`{"zai-coding-plan":{"type":"api","key":"sk-secret-import-value"}}`), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	// Custody key file at $XDG_DATA_HOME/heimdall/master-key.
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("provider-test-cli-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + filepath.Join(dir, "heimdall.db") + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"z.ai\"\nbase_url = \"" + srvURL + "\"\n" +
		"auth_header = \"bearer\"\nallow_loopback = true\nenabled = true\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("LC_ALL", "C") // deterministic (English) CLI messages

	// Seed the vault with the imported z.ai key.
	var importOut strings.Builder
	if code := executeToWithStdout(&importOut, []string{"provider", "import", "--config", cfg}); code != 0 {
		t.Fatalf("import exit=%d: %s", code, importOut.String())
	}
	return cfg
}

// TestProviderTestCommandHappyPath is the observable end-to-end CLI path: the
// executor is built with the configured BaseURL, the imported key is injected as
// Bearer, the upstream is probed, and the credential VALUE never appears.
func TestProviderTestCommandHappyPath(t *testing.T) {
	var hits int32
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	cfg := setupProviderTestCLI(t, srv.URL+"/v1")

	var out strings.Builder
	code := executeToWithStdout(&out, []string{"provider", "test", "z.ai", "--config", cfg})
	text := out.String()
	if code != 0 {
		t.Fatalf("exit=%d; output: %s", code, text)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	if gotAuth != "Bearer sk-secret-import-value" {
		t.Fatalf("Authorization = %q, want the injected bearer", gotAuth)
	}
	if strings.Contains(text, "sk-secret-import-value") {
		t.Fatalf("provider test leaked the credential: %s", text)
	}
	if !strings.Contains(text, "z.ai") || !strings.Contains(text, "status=200") {
		t.Fatalf("output = %q, want provider + status", text)
	}
}

// TestProviderTestCommandUpstreamError proves an upstream failure exits non-zero
// and is reported by code, without leaking the upstream body.
func TestProviderTestCommandUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream-secret-detail"))
	}))
	defer srv.Close()

	cfg := setupProviderTestCLI(t, srv.URL+"/v1")
	stderr, code := executeToCaptureStderr([]string{"provider", "test", "z.ai", "--config", cfg})
	if code == 0 {
		t.Fatal("expected a non-zero exit for an upstream 500")
	}
	if strings.Contains(stderr, "upstream-secret-detail") {
		t.Fatalf("stderr leaked the upstream body: %s", stderr)
	}
	if !strings.Contains(stderr, "unavailable") {
		t.Fatalf("stderr = %q, want the mapped outage message", stderr)
	}
}

// TestProviderTestCommandNoCredential proves the no-credential refusal.
func TestProviderTestCommandNoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	// A fresh config with NO imported credential.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + filepath.Join(dir, "heimdall.db") + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"z.ai\"\nbase_url = \"" + srv.URL + "\"\n" +
		"allow_loopback = true\nenabled = true\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("LC_ALL", "C")
	stderr, code := executeToCaptureStderr([]string{"provider", "test", "z.ai", "--config", cfg})
	if code == 0 {
		t.Fatal("expected a non-zero exit with no credential")
	}
	if !strings.Contains(stderr, "No stored credential") {
		t.Fatalf("stderr = %q, want the no-credential refusal", stderr)
	}
}

// TestProviderTestCommandUnknownProvider covers the registry lookup failure.
func TestProviderTestCommandUnknownProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("LC_ALL", "C")
	stderr, code := executeToCaptureStderr([]string{"provider", "test", "nope", "--config", cfg})
	if code == 0 {
		t.Fatal("expected a non-zero exit for an unknown provider")
	}
	if !strings.Contains(stderr, "Unknown provider") {
		t.Fatalf("stderr = %q, want the not-found refusal", stderr)
	}
}

// executeToCaptureStderr runs the CLI capturing stderr, for error assertions.
func executeToCaptureStderr(args []string) (string, int) {
	var buf strings.Builder
	code := executeWith(&buf, &strings.Builder{}, args)
	return buf.String(), code
}

// TestProviderTestCommandBadConfig covers the buildReadOnly error branch: a
// config path that does not exist fails before any probe.
func TestProviderTestCommandBadConfig(t *testing.T) {
	_, code := executeToCaptureStderr([]string{"provider", "test", "z.ai", "--config", "/nonexistent/heimdall.toml"})
	if code == 0 {
		t.Fatal("expected a non-zero exit for a missing config")
	}
}

// TestProviderTestCommandWriteError covers the output-write error branch.
func TestProviderTestCommandWriteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	cfg := setupProviderTestCLI(t, srv.URL+"/v1")
	// The probe succeeds, but stdout fails on the result line.
	if code := executeWith(os.Stderr, failWriter{}, []string{"provider", "test", "z.ai", "--config", cfg}); code == 0 {
		t.Fatal("provider test exited 0 with a failing writer")
	}
}
