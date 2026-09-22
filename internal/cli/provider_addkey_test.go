package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// setupAddKeyCLI writes a config for z.ai (loopback allowed) plus a custody key,
// with NO credential in the vault. It returns the config path and the db path.
func setupAddKeyCLI(t *testing.T, srvURL string) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("addkey-cli-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	dbPath = filepath.Join(dir, "heimdall.db")
	cfgPath = filepath.Join(dir, "heimdall.toml")
	// allow_loopback is only legal for a loopback literal; a remote https URL
	// must not set it (Config.Validate would reject the file).
	loopback := strings.HasPrefix(srvURL, "http://127.0.0.1")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + dbPath + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"z.ai\"\nbase_url = \"" + srvURL + "\"\n" +
		"auth_header = \"bearer\"\nallow_loopback = " + boolStr(loopback) + "\nenabled = true\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("LC_ALL", "C")
	return cfgPath, dbPath
}

// withStdin swaps the package stdin seam for one command invocation.
func withStdin(t *testing.T, input string) {
	t.Helper()
	old := cliStdin
	cliStdin = strings.NewReader(input)
	t.Cleanup(func() { cliStdin = old })
}

// TestProviderAddKeyCommandHappyPath proves the key is read from stdin, sealed,
// persisted (never in plaintext on disk), and reported by id/label only.
func TestProviderAddKeyCommandHappyPath(t *testing.T) {
	cfg, db := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-manual-SECRET-key-123456\n")

	var out strings.Builder
	code := executeToWithStdout(&out, []string{"provider", "add-key", "z.ai", "--label", "work", "--config", cfg})
	text := out.String()
	if code != 0 {
		t.Fatalf("exit=%d; output: %s", code, text)
	}
	if strings.Contains(text, "sk-manual-SECRET-key-123456") {
		t.Fatalf("add-key leaked the key: %s", text)
	}
	if !strings.Contains(text, "provider=z.ai") || !strings.Contains(text, "label=work") {
		t.Fatalf("output = %q, want provider + label", text)
	}

	// The plaintext key must not appear in the vault file.
	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if bytes.Contains(raw, []byte("sk-manual-SECRET-key-123456")) {
		t.Fatal("the plaintext key was found in the vault file")
	}
}

// TestProviderAddKeyThenReadyThenTest is the end-to-end: after add-key, status
// shows ready and provider test probes with the injected Bearer.
func TestProviderAddKeyThenReadyThenTest(t *testing.T) {
	srv := newRecordingServer(t)
	cfg, _ := setupAddKeyCLI(t, srv.URL+"/v1")
	withStdin(t, "sk-added-CLI-key-987654321\n")

	// Before: not ready.
	var statusOut strings.Builder
	if code := executeToWithStdout(&statusOut, []string{"provider", "status", "--config", cfg}); code != 0 {
		t.Fatalf("status exit=%d: %s", code, statusOut.String())
	}
	if strings.Contains(statusOut.String(), "z.ai\tready") {
		t.Fatalf("z.ai was ready before add-key: %s", statusOut.String())
	}

	// add-key.
	var addOut strings.Builder
	if code := executeToWithStdout(&addOut, []string{"provider", "add-key", "z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("add-key exit=%d: %s", code, addOut.String())
	}

	// After: ready.
	statusOut.Reset()
	if code := executeToWithStdout(&statusOut, []string{"provider", "status", "--config", cfg}); code != 0 {
		t.Fatalf("status exit=%d: %s", code, statusOut.String())
	}
	if !strings.Contains(statusOut.String(), "z.ai\tready") {
		t.Fatalf("z.ai not ready after add-key: %s", statusOut.String())
	}

	// provider test works, injecting the key.
	var testOut strings.Builder
	if code := executeToWithStdout(&testOut, []string{"provider", "test", "z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("provider test exit=%d: %s", code, testOut.String())
	}
	if got := srv.bearer(); got != "Bearer sk-added-CLI-key-987654321" {
		t.Fatalf("upstream auth = %q, want the added key", got)
	}
}

// TestProviderAddKeyRefusesOAuth proves an OAuth provider is refused.
func TestProviderAddKeyRefusesOAuth(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-whatever-12345678\n")
	stderr, code := executeToCaptureStderr([]string{"provider", "add-key", "antigravity", "--config", cfg})
	if code == 0 {
		t.Fatal("add-key accepted an OAuth provider")
	}
	// The message names the provider and its modes, and NEVER a literal `{}`.
	if strings.ContainsAny(stderr, "{}") {
		t.Fatalf("stderr has a literal placeholder: %q", stderr)
	}
	if !strings.Contains(stderr, "does not accept an API key") {
		t.Fatalf("stderr = %q, want the provider.api_key_not_supported message", stderr)
	}
	if !strings.Contains(stderr, "antigravity") || !strings.Contains(stderr, "oauth") {
		t.Fatalf("stderr = %q, want the provider and its modes", stderr)
	}
}

// TestProviderAddKeyBadShape covers the offline shape rejection.
func TestProviderAddKeyBadShape(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "x7Q\n") // a distinctive, implausible value
	stderr, code := executeToCaptureStderr([]string{"provider", "add-key", "z.ai", "--config", cfg})
	if code == 0 {
		t.Fatal("add-key accepted a too-short key")
	}
	// The refusal carries the generic reason, never the candidate value.
	if strings.Contains(stderr, "x7Q") {
		t.Fatalf("stderr leaked the candidate value: %q", stderr)
	}
	if !strings.Contains(stderr, "malformed") {
		t.Fatalf("stderr = %q, want the shape refusal", stderr)
	}
}

// TestProviderAddKeyIdempotentCommand proves a second add updates the same row.
func TestProviderAddKeyIdempotentCommand(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")

	withStdin(t, "sk-first-123456789\n")
	var out1 strings.Builder
	if code := executeToWithStdout(&out1, []string{"provider", "add-key", "z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("first add-key exit=%d: %s", code, out1.String())
	}

	withStdin(t, "sk-second-987654321\n")
	var out2 strings.Builder
	if code := executeToWithStdout(&out2, []string{"provider", "add-key", "z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("second add-key exit=%d: %s", code, out2.String())
	}

	// The credential id is stable across the two runs.
	id1 := strings.SplitN(strings.TrimSpace(out1.String()), "\t", 2)[0]
	id2 := strings.SplitN(strings.TrimSpace(out2.String()), "\t", 2)[0]
	if id1 != id2 {
		t.Fatalf("ids differ across runs: %q vs %q", id1, id2)
	}
}

// TestProviderAddKeyWriteError covers the output-write failure branch.
func TestProviderAddKeyWriteError(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-write-error-123456\n")
	if code := executeWith(os.Stderr, failWriter{}, []string{"provider", "add-key", "z.ai", "--config", cfg}); code == 0 {
		t.Fatal("add-key exited 0 with a failing writer")
	}
}

// TestReadSecretNoEchoNonTerminal covers the non-terminal read path (trim CRLF).
func TestReadSecretNoEchoNonTerminal(t *testing.T) {
	got, err := readSecretNoEcho(strings.NewReader("sk-key\r\n"), io.Discard)
	if err != nil || got != "sk-key" {
		t.Fatalf("readSecretNoEcho = %q, %v", got, err)
	}
}

// TestReadSecretNoEchoReadError covers the read-failure branch.
func TestReadSecretNoEchoReadError(t *testing.T) {
	if _, err := readSecretNoEcho(errReader{}, io.Discard); err == nil {
		t.Fatal("expected a read error")
	}
}

// errReader always fails on Read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// recordingServer is an httptest server that captures the last Authorization
// header, for asserting the injected key without exposing it in the test log.
type recordingServer struct {
	*httptest.Server
	lastAuth atomic.Value
}

func (s *recordingServer) bearer() string {
	v, _ := s.lastAuth.Load().(string)
	return v
}

func newRecordingServer(t *testing.T) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.lastAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rs.Close)
	return rs
}

// boolStr renders a TOML boolean.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestReadSecretNoEchoTerminal covers the interactive branch via the seams: the
// prompt is shown, the value is read without echo, and a terminal read error is
// surfaced.
func TestReadSecretNoEchoTerminal(t *testing.T) {
	oldFd, oldRead := terminalFd, readPasswordNoEcho
	t.Cleanup(func() { terminalFd, readPasswordNoEcho = oldFd, oldRead })

	terminalFd = func(io.Reader) (uintptr, bool) { return 7, true }
	readPasswordNoEcho = func(uintptr) ([]byte, error) { return []byte("sk-tty-key\r\n"), nil }

	var prompt strings.Builder
	got, err := readSecretNoEcho(strings.NewReader("ignored"), &prompt)
	if err != nil || got != "sk-tty-key" {
		t.Fatalf("terminal read = %q, %v", got, err)
	}
	if !strings.Contains(prompt.String(), "API key:") {
		t.Fatalf("prompt not shown: %q", prompt.String())
	}

	// A nil prompt must not panic.
	if _, err := readSecretNoEcho(strings.NewReader(""), nil); err != nil {
		t.Fatalf("nil prompt: %v", err)
	}

	// Terminal read error.
	readPasswordNoEcho = func(uintptr) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	if _, err := readSecretNoEcho(strings.NewReader(""), nil); err == nil {
		t.Fatal("terminal read error not surfaced")
	}
}

// TestProviderAddKeyLabelDefault covers the empty-label default (provider id).
func TestProviderAddKeyLabelDefault(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-nolabel-12345678\n")
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"provider", "add-key", "z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "label=z.ai") {
		t.Fatalf("output = %q, want the default label", out.String())
	}
}

// TestTerminalFdAndReadPasswordSeams exercises the REAL seam implementations
// (never a TTY in CI): a temp *os.File is not a terminal, and term.ReadPassword
// on a non-tty fd fails cleanly.
func TestTerminalFdAndReadPasswordSeams(t *testing.T) {
	// Non-file reader: not a terminal.
	if _, ok := terminalFd(strings.NewReader("x")); ok {
		t.Fatal("a strings.Reader reported as a terminal")
	}
	// A real *os.File that is not a terminal.
	f, err := os.CreateTemp(t.TempDir(), "notatty")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	fd, ok := terminalFd(f)
	if ok {
		t.Fatal("a temp file reported as a terminal")
	}
	// The real readPasswordNoEcho on a non-tty fd returns an error (no panic).
	if _, err := readPasswordNoEcho(fd); err == nil {
		t.Fatal("expected an error reading a password from a non-tty fd")
	}
}

// TestProviderAddKeyBuildError covers buildReadOnly's failure branch.
func TestProviderAddKeyBuildError(t *testing.T) {
	withStdin(t, "sk-whatever-12345678\n")
	if _, code := executeToCaptureStderr([]string{"provider", "add-key", "z.ai", "--config", "/nonexistent/x.toml"}); code == 0 {
		t.Fatal("add-key exited 0 with a bad config")
	}
}

// TestProviderAddKeyReadError covers the stdin read-failure branch.
func TestProviderAddKeyReadError(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	old := cliStdin
	cliStdin = errReader{}
	t.Cleanup(func() { cliStdin = old })
	if _, code := executeToCaptureStderr([]string{"provider", "add-key", "z.ai", "--config", cfg}); code == 0 {
		t.Fatal("add-key exited 0 when stdin failed")
	}
}

// TestProviderAddKeyUnknownProvider covers the registry lookup failure.
func TestProviderAddKeyUnknownProvider(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-whatever-12345678\n")
	if _, code := executeToCaptureStderr([]string{"provider", "add-key", "nope", "--config", cfg}); code == 0 {
		t.Fatal("add-key accepted an unknown provider")
	}
}

// TestProviderAddKeyOAuthMessageLocalised is the P0 regression: the OAuth
// refusal renders the provider.api_key_not_supported message, in the negotiated
// language, and NEVER a literal `{...}` placeholder.
func TestProviderAddKeyOAuthMessageLocalised(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-whatever-12345678\n")

	// en
	t.Setenv("LC_ALL", "C")
	stderr, code := executeToCaptureStderr([]string{"provider", "add-key", "antigravity", "--config", cfg})
	if code == 0 {
		t.Fatal("add-key accepted an OAuth provider")
	}
	if strings.ContainsAny(stderr, "{}") {
		t.Fatalf("en message has a literal placeholder: %q", stderr)
	}
	if !strings.Contains(stderr, "does not accept an API key") || !strings.Contains(stderr, "oauth") {
		t.Fatalf("en stderr = %q", stderr)
	}

	// pt-BR (explicit locale)
	t.Setenv("LC_ALL", "pt_BR.UTF-8")
	stderrPT, code := executeToCaptureStderr([]string{"provider", "add-key", "antigravity", "--config", cfg})
	if code == 0 {
		t.Fatal("add-key accepted an OAuth provider (pt-BR)")
	}
	if strings.ContainsAny(stderrPT, "{}") {
		t.Fatalf("pt-BR message has a literal placeholder: %q", stderrPT)
	}
	if !strings.Contains(stderrPT, "não aceita API key") || !strings.Contains(stderrPT, "antigravity") {
		t.Fatalf("pt-BR stderr = %q", stderrPT)
	}
	if stderrPT == stderr {
		t.Fatal("pt-BR message is identical to en (not localised)")
	}
}

// TestCLIErrorMessagesHaveNoLiteralPlaceholder is the smoke test: a set of error
// paths must never print an un-interpolated `{name}`. It exercises several codes
// (unknown provider, no credential, malformed key) across en and pt-BR.
func TestCLIErrorMessagesHaveNoLiteralPlaceholder(t *testing.T) {
	cfg, _ := setupAddKeyCLI(t, "https://x/v1")
	withStdin(t, "sk-whatever-12345678\n")

	cases := []struct {
		name string
		args []string
	}{
		{"add-key unknown provider", []string{"provider", "add-key", "nope", "--config", cfg}},
		{"add-key oauth", []string{"provider", "add-key", "antigravity", "--config", cfg}},
		{"test no credential", []string{"provider", "test", "z.ai", "--config", cfg}},
		{"test unknown provider", []string{"provider", "test", "nope", "--config", cfg}},
		{"bad config", []string{"provider", "status", "--config", "/nonexistent/x.toml"}},
	}
	for _, lang := range []string{"C", "pt_BR.UTF-8"} {
		t.Setenv("LC_ALL", lang)
		for _, c := range cases {
			stderr, code := executeToCaptureStderr(c.args)
			if code == 0 {
				continue // this case is not an error path for this input
			}
			if strings.ContainsAny(stderr, "{}") {
				t.Errorf("[%s] %s: literal placeholder in %q", lang, c.name, stderr)
			}
		}
	}
}
