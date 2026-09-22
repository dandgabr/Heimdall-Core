// Package translators implements the frozen contracts.Translator (F2.3).
//
// A translator converts between the CANONICAL pivot format (OpenAI-shaped JSON,
// per contracts.CanonicalFormat) and one provider's wire format. It is PURE by
// contract: no context, no I/O, no clock, no randomness. "Pure" here is not a
// style preference — it is what makes the golden files meaningful: the same
// input bytes MUST produce the same output bytes on every run and machine, so a
// translation bug is a reproducible diff, not a flaky integration failure.
//
// # Purity rules (enforced by review and by TestPurityIsDeterministic)
//
//   - No imports of net/http, net, time or any I/O package. The only imports are
//     encoding/json, errors, fmt, sort, strings, sync and internal/domain +
//     internal/contracts.
//   - No package-level mutable state. A translator value is immutable; two calls
//     with equal input return equal output.
//   - No clock: a timestamp the canonical schema requires but the provider does
//     not supply is emitted as created=0. Stamping the real time is the
//     pipeline's job, not the translator's.
//
// # Direction
//
// From() is the pivot (source), To() is the provider (target):
//
//	Request       pivot  -> provider
//	ResponseFull  provider -> pivot
//	ResponseChunk provider -> pivot   (one upstream frame)
//
// A translator whose From() == To() is the IDENTITY (the canonical OpenAI
// family): it returns its input verbatim.
//
// # Adding a golden file
//
// Golden files live under testdata/<translator>/<direction>/<case>.json, where
// translator is openai|anthropic|gemini and direction is
// request|response_full|response_chunk. Each file is a single JSON envelope:
//
//	{
//	  "model":  "claude-3-5-sonnet",   // passed to the translator verbatim
//	  "stream": true,                  // only used by the "request" direction
//	  "input":    { ... },             // the raw translator input
//	  "expected": { ... }              // the exact translator output
//	}
//
// To add a case: drop a new .json file in the right directory. The runner
// (TestGoldenFiles) discovers it automatically, calls the translator for that
// (translator, direction), compacts both the expected and the produced JSON and
// compares them byte for byte. To regenerate an expectation, run the translator
// once and paste its compact output into "expected" — do NOT hand-edit only one
// side. The envelope may be pretty-printed; comparison is on the compacted
// inner values, so formatting the file does not affect the result.
package translators

import (
	"bytes"
	"encoding/json"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// HTTP statuses used by translation errors. They are local constants rather than
// net/http imports: the purity rule forbids pulling net/http into this package,
// and the values are fixed by the HTTP spec.
const (
	statusBadGateway = 502
	statusInternal   = 500
)

// failed builds a translate.failed DomainError. translate.failed is classified
// as ScopeRequest (ADR-0002): a malformed or unmappable payload from the client
// side is the request's problem, so it never cools down a credential or triggers
// failover. cause may be nil.
func failed(reason string, cause error) error {
	return domain.New(domain.CodeTranslateFailed,
		domain.WithHTTPStatus(statusBadGateway),
		domain.WithScope(domain.ScopeRequest),
		domain.WithCause(cause),
		domain.WithParams(map[string]string{"reason": reason}),
	)
}

// providerShapeError builds a translate.failed DomainError for a malformed
// UPSTREAM payload. Unlike failed it is ScopeProvider (ADR-0002): the upstream
// returned something unusable, which is a provider fault and may trip the
// breaker / trigger failover. The distinction matters because a client error and
// a provider error must not share a cooldown decision.
func providerShapeError(reason string, cause error) error {
	return domain.New(domain.CodeTranslateFailed,
		domain.WithHTTPStatus(statusBadGateway),
		domain.WithScope(domain.ScopeProvider),
		domain.WithCause(cause),
		domain.WithParams(map[string]string{"reason": reason}),
	)
}

// unsupported builds a translate.unsupported DomainError for a (from,to) pair
// with no registered translator. It is a wiring error, so it is internal-scoped
// rather than request-scoped.
func unsupported(from, to string) error {
	return domain.New(domain.CodeTranslateUnsupported,
		domain.WithHTTPStatus(statusInternal),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"from": from, "to": to}),
	)
}

// isJSONNull reports whether raw is absent or the JSON literal null. Both mean
// "the field was not supplied" for the canonical decoder.
func isJSONNull(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	trimmed := trimSpace(raw)
	return len(trimmed) == 4 && string(trimmed) == "null"
}

// trimSpace trims ASCII whitespace from a raw JSON message without importing
// bytes (which would be fine, but this keeps the helper dependency-free).
func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// compactRaw re-encodes a raw JSON value into its compact form. It is used
// whenever a cross-format translator converts a nested provider JSON value into
// a STRING field (Anthropic/Gemini return tool arguments as a nested object;
// the canonical OpenAI shape carries them as a JSON-encoded string). Passing the
// provider's raw bytes through verbatim would leak its pretty-printing
// whitespace into the string, so two providers returning the same arguments
// would produce different strings. An empty/null raw yields fallback; an
// unparseable raw is surfaced verbatim rather than dropped.
func compactRaw(raw json.RawMessage, fallback string) string {
	if isJSONNull(raw) {
		return fallback
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}
