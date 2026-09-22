package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

func TestLoggerRedactsSecretsInAttributes(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf, Redactor: i18n.Redacter{}})

	logger.Info("upstream call", "authorization", "Bearer sk-super-secret-123456")

	out := buf.String()
	if strings.Contains(out, "sk-super-secret-123456") {
		t.Fatalf("secret leaked into log: %s", out)
	}
	if !strings.Contains(out, i18n.Redacted) {
		t.Errorf("no redaction marker: %s", out)
	}
}

func TestLoggerInjectsRequestAndTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf})

	ctx := WithRequestID(context.Background(), domain.RequestID("req-123"))
	ctx = WithTraceID(ctx, "trace-456")
	logger.InfoContext(ctx, "hello")

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("decode record: %v (%s)", err, buf.String())
	}
	if record["request_id"] != "req-123" {
		t.Errorf("request_id = %v", record["request_id"])
	}
	if record["trace_id"] != "trace-456" {
		t.Errorf("trace_id = %v", record["trace_id"])
	}
}

func TestParseLevel(t *testing.T) {
	tests := map[string]string{
		"debug": "DEBUG",
		"info":  "INFO",
		"warn":  "WARN",
		"error": "ERROR",
		"bogus": "INFO",
	}
	for in, want := range tests {
		if got := parseLevel(in).String(); got != want {
			t.Errorf("parseLevel(%q) = %s, want %s", in, got, want)
		}
	}
}
