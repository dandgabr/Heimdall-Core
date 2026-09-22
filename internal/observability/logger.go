// Package observability provides the structured logger shared by every
// component.
//
// Two invariants (ADR-003):
//   - request/trace IDs are attached to every record, so one request can be
//     followed across the gateway, the dispatcher and the upstream call;
//   - every attribute value passes through the central redactor, and request or
//     response BODIES are never logged by default. The logger exposes no helper
//     that accepts a body; callers that need to trace payloads must do so
//     behind an explicit debug flag in a later phase.
package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// contextKey is unexported so only this package can populate the IDs.
type contextKey uint8

const (
	requestIDKey contextKey = iota
	traceIDKey
)

// WithRequestID returns a context carrying the request identifier.
func WithRequestID(ctx context.Context, id domain.RequestID) context.Context {
	return context.WithValue(ctx, requestIDKey, id.String())
}

// RequestIDFrom extracts the request identifier, or "".
func RequestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// WithTraceID returns a context carrying an external trace identifier.
func WithTraceID(ctx context.Context, trace string) context.Context {
	return context.WithValue(ctx, traceIDKey, trace)
}

// TraceIDFrom extracts the trace identifier, or "".
func TraceIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(traceIDKey).(string)
	return v
}

// Options configures the logger.
type Options struct {
	// Level is debug|info|warn|error.
	Level string
	// Format is text|json.
	Format string
	// Output defaults to os.Stderr.
	Output io.Writer
	// Redactor defaults to the central i18n redactor.
	Redactor contracts.Redactor
	// Service is attached as the "service" attribute.
	Service string
}

// New builds a *slog.Logger with redaction and ID injection baked into the
// handler chain.
func New(opts Options) *slog.Logger {
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}
	redactor := opts.Redactor
	if redactor == nil {
		redactor = i18n.Redacter{}
	}

	handlerOpts := &slog.HandlerOptions{
		Level: parseLevel(opts.Level),
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Redact every string that could carry a credential. Values are
			// stringified so a nested type cannot smuggle a secret past the
			// regex.
			switch a.Value.Kind() {
			case slog.KindString:
				a.Value = slog.StringValue(redactor.Redact(a.Value.String()))
			default:
				text := a.Value.String()
				if redacted := redactor.Redact(text); redacted != text {
					a.Value = slog.StringValue(redacted)
				}
			}
			return a
		},
	}

	var base slog.Handler
	if strings.EqualFold(opts.Format, "json") {
		base = slog.NewJSONHandler(out, handlerOpts)
	} else {
		base = slog.NewTextHandler(out, handlerOpts)
	}

	logger := slog.New(&contextHandler{inner: base})
	if opts.Service != "" {
		logger = logger.With(slog.String("service", opts.Service))
	}
	return logger
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// contextHandler injects the request/trace IDs on every record.
type contextHandler struct {
	inner slog.Handler
}

func (h *contextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestIDFrom(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	if trace := TraceIDFrom(ctx); trace != "" {
		r.AddAttrs(slog.String("trace_id", trace))
	}
	return h.inner.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{inner: h.inner.WithGroup(name)}
}
