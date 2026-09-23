package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/dandgabr/heimdall-core/internal/app"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// setupInspectCLI writes a config with gates enabled and a custody key, so the
// quota/gate/config commands can build the app. It returns the config path.
func setupInspectCLI(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("inspect-cli-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + filepath.Join(dir, "heimdall.db") + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"z.ai\"\nbase_url = \"https://x/v1\"\n" +
		"auth_header = \"bearer\"\nenabled = true\nmodels = [\"glm-4.6\"]\n" +
		extra
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("LC_ALL", "C")
	return cfg
}

// TestInspectCommandWriteErrors covers the writer-error branch of each new
// command by directing stdout to a failing writer.
func TestInspectCommandWriteErrors(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	// Seed a provider credential so `quota list` has a row to write (an empty
	// vault writes nothing, so it cannot exercise the error branch).
	withStdin(t, "sk-seed-write-error-123456\n")
	if code := executeToWithStdout(&strings.Builder{}, []string{"provider", "add-key", "z.ai", "--config", cfg}); code != 0 {
		t.Fatal("seed credential failed")
	}
	for _, args := range [][]string{
		{"config", "show", "--config", cfg},
		{"config", "validate", "--config", cfg},
		{"config", "path", "--config", cfg},
		{"quota", "list", "--config", cfg},
		{"gate", "list", "--config", cfg},
		{"gate", "show", "logger", "--config", cfg},
	} {
		if code := executeWith(&strings.Builder{}, failingWriter{}, args); code == 0 {
			t.Errorf("%v exited 0 when the output write failed", args)
		}
	}
}

// --- quota ---

// TestQuotaListEmptyVault proves an empty vault prints nothing (a valid state).
func TestQuotaListEmptyVault(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"quota", "list", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("quota list on an empty vault = %q, want empty", out.String())
	}
}

// TestQuotaShowUnknown proves an unknown credential id is a typed not-found.
func TestQuotaShowUnknown(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	stderr, code := executeToCaptureStderr([]string{"quota", "show", "nope", "--config", cfg})
	if code == 0 {
		t.Fatal("quota show accepted an unknown id")
	}
	if !strings.Contains(stderr, "No stored credential") {
		t.Fatalf("stderr = %q, want the quota.unknown message", stderr)
	}
	if strings.ContainsAny(stderr, "{}") {
		t.Fatalf("stderr has a literal placeholder: %q", stderr)
	}
}

// TestQuotaShowSuccess covers the happy path: a seeded credential is found and
// its detail is rendered.
func TestQuotaShowSuccess(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	withStdin(t, "sk-quota-show-1234567890\n")
	if code := executeToWithStdout(&strings.Builder{}, []string{"provider", "add-key", "z.ai", "--label", "q", "--config", cfg}); code != 0 {
		t.Fatal("seed credential failed")
	}
	// Find the credential id from `quota list`.
	var listOut strings.Builder
	if code := executeToWithStdout(&listOut, []string{"quota", "list", "--config", cfg}); code != 0 {
		t.Fatalf("quota list exit=%d", code)
	}
	id := strings.SplitN(strings.TrimSpace(listOut.String()), "\t", 2)[0]
	if id == "" {
		t.Fatalf("no credential id in %q", listOut.String())
	}
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"quota", "show", id, "--config", cfg}); code != 0 {
		t.Fatalf("quota show exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "credential\t"+id) {
		t.Fatalf("quota show = %q, want the credential header", out.String())
	}
}

// TestQuotaShowNeedsArg covers the cobra arg-count validation.
func TestQuotaShowNeedsArg(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	if code := executeToWithStdout(&strings.Builder{}, []string{"quota", "show", "--config", cfg}); code == 0 {
		t.Fatal("quota show without an id exited 0")
	}
}

// TestQuotaCommandsBadConfig covers the buildReadOnly error branch.
func TestQuotaCommandsBadConfig(t *testing.T) {
	for _, args := range [][]string{
		{"quota", "list", "--config", "/nonexistent/x.toml"},
		{"quota", "show", "id", "--config", "/nonexistent/x.toml"},
	} {
		if code := executeToWithStdout(&strings.Builder{}, args); code == 0 {
			t.Errorf("%v exited 0 on a bad config", args)
		}
	}
}

// TestQuotaCommandsStoreError covers the QuotaInfos/QuotaInfoFor error branches
// by building a healthy app and then making its vault's credentials table
// unreadable (a fresh boot would fail closed before reaching the command).
func TestQuotaCommandsStoreError(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	withBrokenCredentialStore(t, cfg)
	if code := executeToWithStdout(&strings.Builder{}, []string{"quota", "list", "--config", cfg}); code == 0 {
		t.Error("quota list exited 0 without the credentials table")
	}
	if code := executeToWithStdout(&strings.Builder{}, []string{"quota", "show", "x", "--config", cfg}); code == 0 {
		t.Error("quota show exited 0 without the credentials table")
	}
}

// withBrokenCredentialStore swaps buildReadOnly for one that builds a healthy
// app ONCE and drops the credentials table, so a command's read fails at run
// time rather than at boot. The same instance is returned on every call (the
// first command closes the store, so a later command sees a closed/absent
// table), which is what reaches the per-credential read-error branch.
func withBrokenCredentialStore(t *testing.T, cfgPath string) {
	t.Helper()
	old := buildReadOnly
	t.Cleanup(func() { buildReadOnly = old })
	var cached *app.App
	buildReadOnly = func(_ string) (*app.App, error) {
		if cached != nil {
			return cached, nil
		}
		instance, err := old(cfgPath)
		if err != nil {
			return nil, err
		}
		_, _ = instance.Store.Writer().Exec(`DROP TABLE credentials`)
		cached = instance
		return instance, nil
	}
}

// TestRenderQuotaListBranches exercises the pure renderer's no-state and
// with-window branches plus a write error.
func TestRenderQuotaListBranches(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	bundle := i18n.MustNew()
	infos := []app.QuotaInfo{
		{Credential: "c1", Provider: "z.ai", HasState: false},
		{Credential: "c2", Provider: "z.ai", HasState: true, TerminalCode: domain.CodeQuotaExhausted,
			Windows: []app.QuotaWindowInfo{{Kind: "short", Limit: 100, Used: 10, Remaining: 0.9, Source: "header"}}},
		{Credential: "c3", Provider: "z.ai", HasState: true,
			Windows: []app.QuotaWindowInfo{{Kind: "long", Limit: 0, Used: 5, Remaining: 1, Source: "local_counter"}}},
	}
	var out strings.Builder
	if err := renderQuotaList(&out, infos, bundle); err != nil {
		t.Fatalf("renderQuotaList: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "no_state") && !strings.Contains(text, "No quota") {
		t.Errorf("missing no-state line: %s", text)
	}
	if !strings.Contains(text, "remaining=90.0%") {
		t.Errorf("missing remaining percent: %s", text)
	}
	if !strings.Contains(text, "remaining=n/a") {
		t.Errorf("unknown-limit window should show n/a: %s", text)
	}
	if !strings.Contains(text, "terminal=quota.exhausted") {
		t.Errorf("missing terminal marker: %s", text)
	}
	if err := renderQuotaList(failWriter{}, infos, bundle); err == nil {
		t.Error("renderQuotaList tolerated a write failure")
	}
	// The window-line write (third write: c1 no-state, c2 header, c2 window)
	// also propagates its error.
	if err := renderQuotaList(&cliNthFailWriter{n: 3}, infos, bundle); err == nil {
		t.Error("renderQuotaList tolerated a window-line write failure")
	}
	// The terminal-line write (second write of the credentialed row) too.
	if err := renderQuotaList(&cliNthFailWriter{n: 2}, infos, bundle); err == nil {
		t.Error("renderQuotaList tolerated a terminal-line write failure")
	}
}

// TestRenderQuotaDetailBranches exercises the detail renderer.
func TestRenderQuotaDetailBranches(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	bundle := i18n.MustNew()
	withState := app.QuotaInfo{Credential: "c1", Provider: "z.ai", HasState: true,
		Windows: []app.QuotaWindowInfo{{Kind: "short", Limit: 100, Used: 1, Remaining: 0.99, ResetsAt: "2026-01-01T00:00:00Z", Source: "header"}}}
	var out strings.Builder
	if err := renderQuotaDetail(&out, withState, bundle); err != nil {
		t.Fatalf("renderQuotaDetail: %v", err)
	}
	if !strings.Contains(out.String(), "resets_at=2026-01-01T00:00:00Z") {
		t.Errorf("missing reset: %s", out.String())
	}
	noState := app.QuotaInfo{Credential: "c2", Provider: "z.ai", HasState: false}
	out.Reset()
	if err := renderQuotaDetail(&out, noState, bundle); err != nil {
		t.Fatalf("renderQuotaDetail no-state: %v", err)
	}
	if !strings.Contains(out.String(), "No quota") {
		t.Errorf("missing no-state message: %s", out.String())
	}
	// With a terminal code AND a window, the terminal column is printed and the
	// window line is the third write.
	withTerminal := app.QuotaInfo{Credential: "c3", Provider: "z.ai", HasState: true, TerminalCode: domain.CodeQuotaExhausted,
		Windows: []app.QuotaWindowInfo{{Kind: "short", Limit: 100, Used: 1, Remaining: 0.99, Source: "header"}}}
	out.Reset()
	if err := renderQuotaDetail(&out, withTerminal, bundle); err != nil {
		t.Fatalf("renderQuotaDetail terminal: %v", err)
	}
	if !strings.Contains(out.String(), "terminal\t"+domain.CodeQuotaExhausted) {
		t.Errorf("missing terminal line: %s", out.String())
	}
	// Write failures at each successive write propagate.
	if err := renderQuotaDetail(failWriter{}, withState, bundle); err == nil {
		t.Error("renderQuotaDetail tolerated a write failure")
	}
	// withTerminal has three writes (credential, terminal, window); n:3 fails
	// the window line, n:2 the terminal line.
	if err := renderQuotaDetail(&cliNthFailWriter{n: 3}, withTerminal, bundle); err == nil {
		t.Error("renderQuotaDetail tolerated a window-line write failure")
	}
	if err := renderQuotaDetail(&cliNthFailWriter{n: 2}, withTerminal, bundle); err == nil {
		t.Error("renderQuotaDetail tolerated a terminal-line write failure")
	}
}

// --- gate ---

// TestGateListShowsLogger proves the effective chain lists the always-on logger
// gate with its stages and policy.
func TestGateListShowsLogger(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"gate", "list", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "logger") || !strings.Contains(out.String(), "fail_open") {
		t.Fatalf("gate list = %q, want the logger gate", out.String())
	}
}

// TestGateShowUnknown proves an unknown/disabled gate is a typed not-enabled.
func TestGateShowUnknown(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	stderr, code := executeToCaptureStderr([]string{"gate", "show", "nope", "--config", cfg})
	if code == 0 {
		t.Fatal("gate show accepted an unknown gate")
	}
	if !strings.Contains(stderr, "not in the effective chain") {
		t.Fatalf("stderr = %q, want the gate.not_enabled message", stderr)
	}
}

// TestGateShowLogger proves the detail includes stages, policy and the
// config-only note.
func TestGateShowLogger(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"gate", "show", "logger", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{"id\tlogger", "policy\tfail_open", "group\tlogger", "configuration file"} {
		if !strings.Contains(text, want) {
			t.Errorf("gate show missing %q: %s", want, text)
		}
	}
}

// TestGateCommandsBadConfig covers the buildReadOnly error branch.
func TestGateCommandsBadConfig(t *testing.T) {
	for _, args := range [][]string{
		{"gate", "list", "--config", "/nonexistent/x.toml"},
		{"gate", "show", "logger", "--config", "/nonexistent/x.toml"},
	} {
		if code := executeToWithStdout(&strings.Builder{}, args); code == 0 {
			t.Errorf("%v exited 0 on a bad config", args)
		}
	}
}

// TestRenderGateListAndDetailBranches exercises the pure renderers including the
// write-error branches.
func TestRenderGateListAndDetailBranches(t *testing.T) {
	bundle := i18n.MustNew()
	infos := []app.GateInfo{{ID: "logger", Stages: []string{"pre_request"}, FailurePolicy: "fail_open", Group: "logger"}}
	var out strings.Builder
	if err := renderGateList(&out, infos, bundle); err != nil {
		t.Fatalf("renderGateList: %v", err)
	}
	if !strings.Contains(out.String(), "logger") {
		t.Fatalf("renderGateList = %q", out.String())
	}
	if err := renderGateList(failWriter{}, infos, bundle); err == nil {
		t.Error("renderGateList tolerated a write failure")
	}

	detail := app.GateInfo{ID: "x", Stages: []string{"pre_request", "post_response"}, FailurePolicy: "fail_closed",
		Group: "security", RequiredCaps: "stream", Reads: []string{"prompt_text"}, Writes: []string{"pii"}, After: []string{"logger"}}
	out.Reset()
	if err := renderGateDetail(&out, detail, bundle); err != nil {
		t.Fatalf("renderGateDetail: %v", err)
	}
	for _, want := range []string{"reads\tprompt_text", "writes\tpii", "after\tlogger", "required_caps\tstream"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("gate detail missing %q: %s", want, out.String())
		}
	}
	if err := renderGateDetail(failWriter{}, detail, bundle); err == nil {
		t.Error("renderGateDetail tolerated a write failure")
	}

	// Empty dependency columns render "-".
	if got := joinOrDash(nil); got != "-" {
		t.Errorf("joinOrDash(nil) = %q, want -", got)
	}
	if got := joinOrDash([]string{"a", "b"}); got != "a,b" {
		t.Errorf("joinOrDash = %q", got)
	}
}

// --- config ---

// TestConfigShowRedactsSecrets is the anti-leak core for `config show`: a
// seeded passthrough key must never appear in the output, and the field must be
// the redaction literal.
func TestConfigShowRedactsSecrets(t *testing.T) {
	const secret = "sk-live-CONFIG-SHOW-SECRET-1234567890"
	cfg := setupInspectCLI(t, "[passthrough]\napi_key = \""+secret+"\"\napi_key_env = \"OPENAI_API_KEY\"\n")

	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"config", "show", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	text := out.String()
	if strings.Contains(text, secret) {
		t.Fatalf("config show leaked the passthrough key: %s", text)
	}
	if !strings.Contains(text, "passthrough.api_key\t"+config.Redacted) {
		t.Fatalf("config show missing the redacted passthrough key line: %s", text)
	}
	// The variable NAME is not a secret and is shown.
	if !strings.Contains(text, "passthrough.api_key_env\tOPENAI_API_KEY") {
		t.Fatalf("config show should show the env var name: %s", text)
	}
	// Provenance is shown for a file-set key.
	if !strings.Contains(text, "config_version\t1\tfile") {
		t.Fatalf("config show missing provenance: %s", text)
	}
}

// TestConfigShowNoFileWarns covers the no-file branch.
func TestConfigShowNoFileWarns(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	// An isolated CWD with no config file and no HEIMDALL_CONFIG.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Chdir(dir)
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"config", "show"}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "No configuration file found") {
		t.Fatalf("config show did not warn about the missing file: %s", out.String())
	}
}

// TestConfigValidate covers the ok path and the typed error path.
func TestConfigValidate(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"config", "validate", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "ok\tconfig_version=1") {
		t.Fatalf("config validate = %q", out.String())
	}

	// An invalid port is a typed config error.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("config_version = 1\n[server]\nport = 999999\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stderr, code := executeToCaptureStderr([]string{"config", "validate", "--config", bad})
	if code == 0 {
		t.Fatal("config validate accepted an invalid port")
	}
	if !strings.Contains(stderr, "port") && !strings.Contains(stderr, "Invalid port") {
		t.Fatalf("stderr = %q, want the invalid-port message", stderr)
	}
}

// TestConfigPath covers the file-found and no-file branches.
func TestConfigPath(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"config", "path", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if strings.TrimSpace(out.String()) != cfg {
		t.Fatalf("config path = %q, want %q", out.String(), cfg)
	}

	// No file: typed no-file error.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Chdir(dir)
	stderr, code := executeToCaptureStderr([]string{"config", "path"})
	if code == 0 {
		t.Fatal("config path exited 0 with no file")
	}
	if !strings.Contains(stderr, "No configuration file found") {
		t.Fatalf("stderr = %q, want the no-file message", stderr)
	}
}

// TestRenderConfigValidateWriteError covers the renderer's write-error branch.
func TestRenderConfigValidateWriteError(t *testing.T) {
	if err := renderConfigValidate(failWriter{}, config.Defaults()); err == nil {
		t.Error("renderConfigValidate tolerated a write failure")
	}
}

// TestRenderConfigShowWriteError covers the show renderer's write-error branch.
func TestRenderConfigShowWriteError(t *testing.T) {
	if err := renderConfigShow(failWriter{}, config.Defaults(), nil, true); err == nil {
		t.Error("renderConfigShow tolerated a write failure")
	}
	// The no-file warning is the first write; a failure there propagates too.
	if err := renderConfigShow(failWriter{}, config.Defaults(), nil, false); err == nil {
		t.Error("renderConfigShow tolerated the no-file warning write failure")
	}
}

// TestConfigShowLoadError covers newConfigShowCmd's LoadWithSources error branch.
func TestConfigShowLoadError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("this is not = valid toml ]"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code := executeToWithStdout(&strings.Builder{}, []string{"config", "show", "--config", bad}); code == 0 {
		t.Fatal("config show exited 0 on an invalid config")
	}
}

// TestRenderGateDetailAllWriteErrors covers each write in the gate detail
// renderer.
func TestRenderGateDetailAllWriteErrors(t *testing.T) {
	bundle := i18n.MustNew()
	g := app.GateInfo{ID: "x", Stages: []string{"pre_request"}, FailurePolicy: "fail_open", Group: "security"}
	// First write (the labelled block) fails with a plain failing writer.
	if err := renderGateDetail(failWriter{}, g, bundle); err == nil {
		t.Error("renderGateDetail tolerated a first-write failure")
	}
	// Second write (reads/writes/after) fails at n:2.
	if err := renderGateDetail(&cliNthFailWriter{n: 2}, g, bundle); err == nil {
		t.Error("renderGateDetail tolerated a second-write failure")
	}
	// Third write (the config-only note) fails at n:3.
	if err := renderGateDetail(&cliNthFailWriter{n: 3}, g, bundle); err == nil {
		t.Error("renderGateDetail tolerated a third-write failure")
	}
}

// TestLocalisedOutputPTBR proves the new commands respect the negotiated
// language (pt-BR) rather than emitting English prose.
func TestLocalisedOutputPTBR(t *testing.T) {
	cfg := setupInspectCLI(t, "")
	t.Setenv("LC_ALL", "pt_BR.UTF-8")
	// gate show prints the config-only note localised.
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"gate", "show", "logger", "--config", cfg}); code != 0 {
		t.Fatalf("exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "arquivo de configuração") {
		t.Fatalf("pt-BR gate show = %q, want the localised note", out.String())
	}
}

// TestNewCommandGroupsAreRegistered proves the three new groups are mounted on
// the root command.
func TestNewCommandGroupsAreRegistered(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"quota", "gate", "config"} {
		found := false
		for _, c := range root.Commands() {
			if c.Name() == name {
				found = true
			}
		}
		if !found {
			t.Errorf("root is missing the %q command group", name)
		}
	}
}

// TestNewCommandsHelpLocalisable proves the group help text is non-empty (cobra
// renders Short/Long from the command; the codes are localised at call sites).
func TestNewCommandsHelpLocalisable(t *testing.T) {
	for _, cmd := range []*cobra.Command{newQuotaCmd(), newGateCmd(), newConfigCmd()} {
		if strings.TrimSpace(cmd.Short) == "" {
			t.Errorf("command %q has an empty Short help", cmd.Name())
		}
	}
}
