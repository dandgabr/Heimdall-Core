package observability

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// TestContextHandlerWithAttrsAndGroup covers the slog.Handler passthrough
// methods, which had 0% coverage.
func TestContextHandlerWithAttrsAndGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf})

	// WithAttrs and WithGroup go through contextHandler's wrappers.
	logger = logger.With("component", "test").WithGroup("grp")
	ctx := WithRequestID(context.Background(), "req-xyz")
	logger.InfoContext(ctx, "hello", "k", "v")

	out := buf.String()
	if !strings.Contains(out, "req-xyz") {
		t.Errorf("request id not injected through WithAttrs/WithGroup: %s", out)
	}
	if !strings.Contains(out, "component") {
		t.Errorf("With attrs lost: %s", out)
	}
}

// TestLoggerRedactsAcrossVerbs covers ReplaceAttr's non-string branch by logging
// a value that stringifies to a secret.
func TestLoggerRedactsNonStringAttr(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf, Redactor: i18n.Redacter{}})
	// A []byte attr stringifies through slog; the redactor must still catch it.
	logger.Info("blob", "payload", []byte("Authorization: Bearer sk-secret-abcdef123456"))
	if strings.Contains(buf.String(), "sk-secret-abcdef123456") {
		t.Fatalf("secret leaked through a non-string attr: %s", buf.String())
	}
}

// TestNewDefaultsToStderr covers the nil-Output and nil-Redactor branches.
func TestNewDefaultsToStderr(t *testing.T) {
	logger := New(Options{})
	if logger == nil {
		t.Fatal("New returned nil with zero options")
	}
	// Enabled at the default (info) level, disabled below it.
	ctx := context.Background()
	if !logger.Enabled(ctx, 0) { // 0 == LevelInfo
		t.Error("default logger disabled at info")
	}
	if logger.Enabled(ctx, -4) { // LevelDebug
		t.Error("default logger enabled at debug")
	}
}

// TestLoggerServiceAttr covers the Service-attribute branch.
func TestLoggerServiceAttr(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf, Service: "heimdall"})
	logger.Info("hello")
	if !strings.Contains(buf.String(), `"service":"heimdall"`) {
		t.Errorf("service attr missing: %s", buf.String())
	}
}

// TestLoggerTextFormat covers the text-handler branch.
func TestLoggerTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "warn", Format: "text", Output: &buf})
	logger.Debug("suppressed") // below level
	logger.Warn("shown")
	out := buf.String()
	if strings.Contains(out, "suppressed") {
		t.Error("debug log emitted at warn level")
	}
	if !strings.Contains(out, "shown") {
		t.Errorf("warn log missing: %s", out)
	}
}

// TestLoggerRedactsErrorAttr covers ReplaceAttr's non-string branch: an error
// attr stringifies to text containing a secret, which must be redacted.
func TestLoggerRedactsErrorAttr(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf, Redactor: i18n.Redacter{}})
	logger.Info("failed", "err", errors.New("Bearer sk-secret-abcdef123456"))
	if strings.Contains(buf.String(), "sk-secret-abcdef123456") {
		t.Fatalf("secret leaked through an error attr: %s", buf.String())
	}
	if !strings.Contains(buf.String(), i18n.Redacted) {
		t.Errorf("no redaction marker: %s", buf.String())
	}
}
