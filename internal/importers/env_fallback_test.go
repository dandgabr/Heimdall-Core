package importers

import (
	"os"
	"testing"
)

// TestImporterNilEnvFallbacks covers the nil-Env branches: env() reads the
// process environment and home() falls back to os.UserHomeDir, with "." when
// neither resolves. These complement the hermetic injected-env paths (F5-1).
func TestImporterNilEnvFallbacks(t *testing.T) {
	t.Setenv("HEIMDALL_IMPORTER_PROBE", "probe-value")
	im := &Importer{}
	if got := im.env("HEIMDALL_IMPORTER_PROBE"); got != "probe-value" {
		t.Fatalf("nil-env env() = %q, want probe-value", got)
	}

	// With HOME cleared and a nil Env, os.UserHomeDir errors and home() returns
	// the "." fallback.
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this environment resolves a home without HOME")
	}
	if got := (&Importer{}).home(); got != "." {
		t.Fatalf("nil-env home() with no HOME = %q, want .", got)
	}
}
