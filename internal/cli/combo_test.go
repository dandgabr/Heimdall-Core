package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// TestComboCreateRejectsBadWeight covers the weight parse branch.
func TestComboCreateRejectsBadWeight(t *testing.T) {
	cfg := setupComboCLI(t)
	if code, _ := runComboErr(t, "combo", "create", "bad", "provider:z.ai:notanint", "--strategy", "weighted", "--config", cfg); code == 0 {
		t.Fatal("a non-integer weight was accepted")
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
}
