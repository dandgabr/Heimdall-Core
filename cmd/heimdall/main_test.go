package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMainExecutesSubprocess covers main() itself via re-exec: main is the
// os.Exit wrapper around run, and the only honest way to exercise it is to spawn
// the test binary as the program and drive the real entry point.
func TestMainExecutesSubprocess(t *testing.T) {
	if os.Getenv("HEIMDALL_MAIN_SUBPROCESS") == "1" {
		// We are the child: main() will run and call os.Exit with run's code.
		os.Args = []string{"heimdall", "version"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainExecutesSubprocess")
	cmd.Env = append(os.Environ(), "HEIMDALL_MAIN_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess exited with an error: %v\noutput: %s", err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Error("subprocess printed nothing")
	}
}

// TestRunVersion drives the real entry point end to end and asserts the exit
// code and the output.
func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("version printed nothing")
	}
}

// TestRunUnknownFlag proves a flag error is a non-zero exit, not a panic.
func TestRunUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve", "--definitely-not-a-flag"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("unknown flag exited 0")
	}
	if strings.TrimSpace(stderr.String()) == "" {
		t.Error("unknown flag produced no diagnostic")
	}
}

// TestRunUnknownSubcommand proves an unknown command is a non-zero exit.
func TestRunUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"nope"}, &stdout, &stderr); code == 0 {
		t.Fatal("unknown subcommand exited 0")
	}
}

// TestRunProviderList exercises a real subcommand that touches the vault.
func TestRunProviderList(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.toml")
	body := "config_version = 1\n[store]\npath = \"" + filepath.Join(dir, "heimdall.db") +
		"\"\ntoken_path = \"" + filepath.Join(dir, "management-token") + "\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"provider", "list", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "z.ai") {
		t.Errorf("provider list output = %q", stdout.String())
	}
}
