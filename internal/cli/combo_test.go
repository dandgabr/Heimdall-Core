package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// setupComboCLI writes a config with no providers (combos need no credential)
// and a custody key, returning the config path. `combo` commands never perform
// network I/O, so no upstream is needed.
func setupComboCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("combo-cli-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + filepath.Join(dir, "heimdall.db") + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("LC_ALL", "C")
	return cfg
}

// TestComboCreateListDelete is the end-to-end CLI path: create validates and
// persists, list reads it back, delete removes it.
func TestComboCreateListDelete(t *testing.T) {
	cfg := setupComboCLI(t)

	var createOut strings.Builder
	if code := executeToWithStdout(&createOut, []string{
		"combo", "create", "fast", "provider:z.ai", "provider:ollama-cloud",
		"--strategy", "fallback", "--config", cfg,
	}); code != 0 {
		t.Fatalf("create exit=%d: %s", code, createOut.String())
	}
	if !strings.Contains(createOut.String(), "fast") || !strings.Contains(createOut.String(), "steps=2") {
		t.Fatalf("create output = %q", createOut.String())
	}

	var listOut strings.Builder
	if code := executeToWithStdout(&listOut, []string{"combo", "list", "--config", cfg}); code != 0 {
		t.Fatalf("list exit=%d: %s", code, listOut.String())
	}
	if !strings.Contains(listOut.String(), "fast") || !strings.Contains(listOut.String(), "strategy=fallback") {
		t.Fatalf("list output = %q", listOut.String())
	}

	var delOut strings.Builder
	if code := executeToWithStdout(&delOut, []string{"combo", "delete", "fast", "--config", cfg}); code != 0 {
		t.Fatalf("delete exit=%d: %s", code, delOut.String())
	}

	var listOut2 strings.Builder
	if code := executeToWithStdout(&listOut2, []string{"combo", "list", "--config", cfg}); code != 0 {
		t.Fatalf("list2 exit=%d: %s", code, listOut2.String())
	}
	if strings.Contains(listOut2.String(), "fast") {
		t.Fatalf("combo survived deletion: %q", listOut2.String())
	}
}

// TestComboCreateIsIdempotent proves a re-create updates rather than erroring.
func TestComboCreateIsIdempotent(t *testing.T) {
	cfg := setupComboCLI(t)
	for i := 0; i < 2; i++ {
		var out strings.Builder
		if code := executeToWithStdout(&out, []string{
			"combo", "create", "dup", "provider:z.ai", "--strategy", "priority", "--config", cfg,
		}); code != 0 {
			t.Fatalf("create %d exit=%d: %s", i, code, out.String())
		}
	}
}

// runComboErr runs a combo command and returns the exit code plus the captured
// STDERR, where the rendered i18n error lands.
func runComboErr(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var errBuf strings.Builder
	code := executeWith(&errBuf, nil, args)
	return code, errBuf.String()
}

// TestComboCreateRejectsCyclicReference proves a self-referencing combo is
// refused with route.cyclic_combo at SAVE time (ADR-0013 §3.3).
func TestComboCreateRejectsCyclicReference(t *testing.T) {
	cfg := setupComboCLI(t)
	// A combo named "loop" referencing "loop" is a self-cycle.
	code, stderr := runComboErr(t, "combo", "create", "loop", "combo:loop", "--strategy", "fallback", "--config", cfg)
	if code == 0 {
		t.Fatal("cyclic combo was accepted")
	}
	if !strings.Contains(stderr, "cycle") && !strings.Contains(stderr, "route.cyclic_combo") {
		t.Fatalf("stderr = %q, want a cyclic-combo refusal", stderr)
	}
}

// TestComboCreateRejectsUnknownStepKind proves the step grammar is validated.
func TestComboCreateRejectsUnknownStepKind(t *testing.T) {
	cfg := setupComboCLI(t)
	code, stderr := runComboErr(t, "combo", "create", "bad", "weird:ref", "--config", cfg)
	if code == 0 {
		t.Fatal("unknown step kind was accepted")
	}
	if !strings.Contains(stderr, "Invalid combo") {
		t.Fatalf("stderr = %q, want an invalid-combo refusal", stderr)
	}
}

// TestComboCreateRejectsBadStrategy proves an unknown strategy is refused.
func TestComboCreateRejectsBadStrategy(t *testing.T) {
	cfg := setupComboCLI(t)
	if code, _ := runComboErr(t, "combo", "create", "bad", "provider:z.ai", "--strategy", "nope", "--config", cfg); code == 0 {
		t.Fatal("unknown strategy was accepted")
	}
}

// TestComboCreateColonRefEndToEnd is the G-2 regression: a model id with a ':'
// (Ollama's `name:tag`) is stored as ONE step with the tag intact, and a
// trailing integer after the tag-less ref is the weight. The config declares the
// provider and its models so the save-time allowlist accepts the targets.
func TestComboCreateColonRefEndToEnd(t *testing.T) {
	cfg := setupComboCLIConfigured(t)

	var out strings.Builder
	if code := executeToWithStdout(&out, []string{
		"combo", "create", "oc", "model:gpt-oss:120b", "model:glm-4.6:5",
		"--strategy", "weighted", "--config", cfg,
	}); code != 0 {
		t.Fatalf("create exit=%d: %s", code, out.String())
	}

	// Read the persisted combo back through the store to assert the parsed refs.
	instance, err := buildReadOnly(cfg)
	if err != nil {
		t.Fatalf("buildReadOnly: %v", err)
	}
	defer func() { _ = instance.Close() }()
	combo, err := instance.Combos.Get(context.Background(), "oc")
	if err != nil {
		t.Fatalf("Combos.Get: %v", err)
	}
	if len(combo.Steps) != 2 {
		t.Fatalf("steps = %d, want 2: %+v", len(combo.Steps), combo.Steps)
	}
	if combo.Steps[0].Ref != "gpt-oss:120b" || combo.Steps[0].Weight != 0 {
		t.Errorf("step0 = %+v, want ref gpt-oss:120b weight 0", combo.Steps[0])
	}
	if combo.Steps[1].Ref != "glm-4.6" || combo.Steps[1].Weight != 5 {
		t.Errorf("step1 = %+v, want ref glm-4.6 weight 5", combo.Steps[1])
	}
}

// setupComboCLIConfigured is setupComboCLI plus a provider with declared models,
// so a model step passes the save-time allowlist.
func setupComboCLIConfigured(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "heimdall")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master-key"), []byte("combo-cli-material"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n" +
		"[store]\npath = \"" + filepath.Join(dir, "heimdall.db") + "\"\n" +
		"token_path = \"" + filepath.Join(dir, "management-token") + "\"\n" +
		"[[providers]]\nid = \"ollama-cloud\"\nbase_url = \"https://ollama.com/v1\"\n" +
		"enabled = true\nmodels = [\"gpt-oss:120b\"]\n" +
		"[[providers]]\nid = \"z.ai\"\nbase_url = \"https://api.z.ai/api/paas/v4\"\n" +
		"enabled = true\nmodels = [\"glm-4.6\"]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv("LC_ALL", "C")
	return cfg
}

// TestComboCreateUnknownModelErrorDistinctFromProvider is the G-3 regression: an
// unknown MODEL reports route.unknown_model (not route.unknown_provider), and an
// unknown PROVIDER still reports route.unknown_provider. The two causes no
// longer share a misleading message.
func TestComboCreateUnknownModelErrorDistinctFromProvider(t *testing.T) {
	cfg := setupComboCLIConfigured(t)

	_, stderr := runComboErr(t, "combo", "create", "m", "model:glm-5.3", "--config", cfg)
	if !strings.Contains(stderr, "references model") {
		t.Fatalf("unknown-model stderr = %q, want the route.unknown_model message", stderr)
	}
	if strings.Contains(stderr, "references an unknown provider") {
		t.Fatalf("unknown-model stderr = %q, misleadingly reported as an unknown provider", stderr)
	}

	_, stderr = runComboErr(t, "combo", "create", "p", "provider:ghost", "--config", cfg)
	if !strings.Contains(stderr, "references an unknown provider") {
		t.Fatalf("unknown-provider stderr = %q, want the route.unknown_provider message", stderr)
	}
}

// TestComboCreateRejectsMalformedStep covers the kind:ref shape guard.
func TestComboCreateRejectsMalformedStep(t *testing.T) {
	cfg := setupComboCLI(t)
	if code, _ := runComboErr(t, "combo", "create", "bad", "nocoLON", "--config", cfg); code == 0 {
		t.Fatal("a malformed step was accepted")
	}
}

// TestComboDeleteMissingIsError proves deleting a missing combo errors.
func TestComboDeleteMissingIsError(t *testing.T) {
	cfg := setupComboCLI(t)
	if code, _ := runComboErr(t, "combo", "delete", "ghost", "--config", cfg); code == 0 {
		t.Fatal("deleting a missing combo succeeded")
	}
}

// TestComboBuildError covers the buildReadOnly error branch for each command (a
// missing explicit config file fails Load).
func TestComboBuildError(t *testing.T) {
	missing := "/nonexistent/heimdall.toml"
	for _, args := range [][]string{
		{"combo", "create", "c", "provider:z.ai", "--config", missing},
		{"combo", "list", "--config", missing},
		{"combo", "delete", "c", "--config", missing},
	} {
		if code, _ := runComboErr(t, args...); code == 0 {
			t.Errorf("%v succeeded with a missing config", args)
		}
	}
}

// failingWriter always fails, so the output-write branches are covered.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write boom") }

// TestComboListWriteError covers the list-render write-error branch.
func TestComboListWriteError(t *testing.T) {
	cfg := setupComboCLI(t)
	// Seed a combo first.
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"combo", "create", "c", "provider:z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("create: %s", out.String())
	}
	var errBuf strings.Builder
	code := executeWith(&errBuf, failingWriter{}, []string{"combo", "list", "--config", cfg})
	if code == 0 {
		t.Fatal("list tolerated a write failure")
	}
}

// TestComboListStoreError covers the List error branch (the combos table is
// dropped, so the read fails).
func TestComboListStoreError(t *testing.T) {
	cfg := setupComboCLI(t)
	// Open the vault directly and drop the table.
	st, err := store.Open(readStorePath(cfg))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.Writer().Exec(`DROP TABLE combos`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	_ = st.Close()
	if code, _ := runComboErr(t, "combo", "list", "--config", cfg); code == 0 {
		t.Fatal("list succeeded without the combos table")
	}
}

// TestComboUpdateError covers the create-with-existing → Update error branch: a
// second create of the same name finds the combo (Get succeeds) but the update
// fails validation (an unknown provider).
func TestComboUpdateError(t *testing.T) {
	cfg := setupComboCLI(t)
	var out strings.Builder
	if code := executeToWithStdout(&out, []string{"combo", "create", "c", "provider:z.ai", "--config", cfg}); code != 0 {
		t.Fatalf("create: %s", out.String())
	}
	// The name exists, so Get succeeds and Update runs; the unknown provider
	// makes the update's validation fail.
	if code, _ := runComboErr(t, "combo", "create", "c", "provider:nonexistent", "--config", cfg); code == 0 {
		t.Fatal("update with an unknown provider succeeded")
	}
}

// readStorePath extracts the store path from the generated config file.
func readStorePath(cfgPath string) string {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "path = ") {
			return strings.Trim(strings.TrimPrefix(line, "path = "), "\"")
		}
	}
	return ""
}

// TestParseComboStepsUnits covers the pure parser directly.
func TestParseComboStepsUnits(t *testing.T) {
	steps, err := parseComboSteps([]string{"model:m1", "provider:p1", "combo:c1", "model:m2:5"})
	if err != nil {
		t.Fatalf("parseComboSteps: %v", err)
	}
	if len(steps) != 4 {
		t.Fatalf("steps = %d, want 4", len(steps))
	}
	if steps[3].Weight != 5 {
		t.Fatalf("weight = %d, want 5", steps[3].Weight)
	}
	if _, err := parseComboSteps([]string{"bad"}); err == nil {
		t.Fatal("parseComboSteps accepted a one-part step")
	}
	if _, err := parseComboSteps([]string{":ref"}); err == nil {
		t.Fatal("parseComboSteps accepted an empty kind")
	}
	if _, err := parseComboSteps([]string{"model:"}); err == nil {
		t.Fatal("parseComboSteps accepted an empty reference")
	}
}

// TestParseComboStepsColonInRef pins the grammar fix (G-2): a model id that
// itself contains ':' (Ollama's `name:tag`) keeps its tag. The weight is the
// LAST segment ONLY when it is a positive integer and a ref remains before it.
func TestParseComboStepsColonInRef(t *testing.T) {
	cases := []struct {
		item       string
		wantKind   combos.StepKind
		wantRef    string
		wantWeight int
	}{
		{"model:gpt-oss:120b", combos.StepModel, "gpt-oss:120b", 0},
		{"model:mistral-large-3:675b", combos.StepModel, "mistral-large-3:675b", 0},
		{"model:glm-4.6:5", combos.StepModel, "glm-4.6", 5},
		{"provider:z.ai", combos.StepProviderWildcard, "z.ai", 0},
		{"model:glm-5:5", combos.StepModel, "glm-5", 5},
		// A trailing non-integer is part of the ref, not an error.
		{"model:weird:tag", combos.StepModel, "weird:tag", 0},
		// A non-positive trailing integer is part of the ref, not a weight.
		{"model:x:0", combos.StepModel, "x:0", 0},
		// A trailing ':' (empty last segment) is part of the ref, not a weight.
		{"model:x:", combos.StepModel, "x:", 0},
	}
	for _, c := range cases {
		steps, err := parseComboSteps([]string{c.item})
		if err != nil {
			t.Errorf("parseComboSteps(%q): %v", c.item, err)
			continue
		}
		if len(steps) != 1 {
			t.Errorf("parseComboSteps(%q) = %d steps, want 1", c.item, len(steps))
			continue
		}
		if steps[0].Kind != c.wantKind || steps[0].Ref != c.wantRef || steps[0].Weight != c.wantWeight {
			t.Errorf("parseComboSteps(%q) = {kind:%s ref:%q weight:%d}, want {kind:%s ref:%q weight:%d}",
				c.item, steps[0].Kind, steps[0].Ref, steps[0].Weight, c.wantKind, c.wantRef, c.wantWeight)
		}
	}
}
