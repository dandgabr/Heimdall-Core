package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// errorEnvelope is the wire shape of every error. It carries the i18n code and
// named params, never a localised sentence and never a stack trace, so the
// client localises and the server stays language-agnostic (ADR-002).
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params,omitempty"`
}

// WriteError renders a DomainError as JSON and applies the central redactor to
// every param, so a stray token in a param value cannot leak into the body.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	de := asDomainError(err)

	params := make(map[string]string, len(de.Params))
	for k, v := range de.Params {
		params[k] = i18n.RedactString(v)
	}

	status := de.HTTPStatus
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: errorBody{
		Code:   de.Code,
		Params: params,
	}})
}

// asDomainError normalises an arbitrary error to a DomainError without leaking
// the cause. A non-domain error becomes an opaque internal error.
func asDomainError(err error) *domain.DomainError {
	if err == nil {
		return domain.New(domain.CodeInternal, domain.WithHTTPStatus(http.StatusInternalServerError))
	}
	var de *domain.DomainError
	if errors.As(err, &de) && de != nil {
		return de
	}
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(http.StatusInternalServerError),
		domain.WithParams(map[string]string{"reason": "internal"}),
	)
}

// ErrorEnvelope converts the mux's own plain-text responses (404 from an
// unknown route, 405 from a known route with the wrong method, 501) into the
// same JSON {error:{code}} envelope every handler uses, so a client never has to
// parse two error formats.
//
// It works by wrapping the ResponseWriter: the mux writes its canned body with a
// non-JSON content type and no body yet, so the wrapper intercepts that first
// WriteHeader, maps the status to an i18n code and emits the envelope instead of
// forwarding the plain text. A handler that already set a JSON content type is
// left untouched.
func ErrorEnvelope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ew := &envelopeWriter{ResponseWriter: w, request: r}
		next.ServeHTTP(ew, r)
	})
}

// envelopeWriter intercepts the mux's default error responses.
type envelopeWriter struct {
	http.ResponseWriter
	request  *http.Request
	informed bool
	replaced bool
}

// WriteHeader maps the mux's canned statuses to the i18n envelope. It only acts
// when the response is not already a JSON envelope (a handler that set its own
// JSON content type is forwarded untouched).
func (w *envelopeWriter) WriteHeader(status int) {
	if w.informed {
		return
	}
	w.informed = true

	code, ok := envelopeCodeFor(status)
	if !ok || strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		w.ResponseWriter.WriteHeader(status)
		return
	}

	// The mux is about to write a plain-text body. Drop the plain-text headers
	// and emit the JSON envelope instead; Write() then swallows the body.
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Type")
	w.Header().Del("X-Content-Type-Options")
	WriteError(w.ResponseWriter, w.request, domain.New(code,
		domain.WithHTTPStatus(status)))
	w.replaced = true
}

// Write swallows the plain-text body the mux writes after WriteHeader once the
// envelope has replaced it.
func (w *envelopeWriter) Write(b []byte) (int, error) {
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// envelopeCodeFor maps a status the net/http mux produces itself to an i18n
// code. Only statuses with a dedicated catalog entry are converted.
func envelopeCodeFor(status int) (string, bool) {
	switch status {
	case http.StatusNotFound:
		return domain.CodeNotFound, true
	case http.StatusMethodNotAllowed:
		return domain.CodeMethodNotAllowed, true
	default:
		return "", false
	}
}

// ManagementAuth guards the /api/mgmt/* surface. It extracts the token from the
// Authorization header ("Bearer <token>") or the X-Management-Token header and
// compares it in constant time.
//
// A management token is NEVER accepted as a client key, and a client key is
// never accepted here: this guard only verifies the operator credential
// (ADR-SEC-06 §2.1). When Throttle is set, FAILED attempts are throttled per
// client IP (ADR-SEC-06 §4.2) and a success clears the IP's history.
type ManagementAuth struct {
	// Verify returns true when the presented token matches the stored one.
	Verify func(presented string) bool
	// Throttle, when non-nil, rate-limits failed attempts per client IP.
	Throttle *LoginThrottle
}

// Middleware returns the guard.
func (a ManagementAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if a.Throttle != nil && !a.Throttle.Allow(ip) {
			writeRateLimited(w, r, a.Throttle.RetryAfter(ip))
			return
		}
		token := extractToken(r)
		if token == "" || a.Verify == nil || !a.Verify(token) {
			if a.Throttle != nil {
				a.Throttle.Fail(ip)
			}
			// A client key is NEVER accepted here: this guard only verifies the
			// operator credential. The code names the management token
			// specifically (ADR-SEC-06 §7.3), so a rejected client key is
			// distinguishable from a missing operator credential.
			WriteError(w, r, domain.New(domain.CodeManagementAuthFailed,
				domain.WithHTTPStatus(http.StatusUnauthorized)))
			return
		}
		if a.Throttle != nil {
			a.Throttle.Success(ip)
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP extracts the peer IP from RemoteAddr ("host:port"), falling back to
// the raw value. It is used as the throttle key; the port is dropped so two
// connections from one host share a bucket.
func ClientIP(r *http.Request) string {
	return hostOf(r.RemoteAddr)
}

// writeRateLimited emits the 429 quota.rate_limited envelope with a Retry-After
// header (ADR-SEC-06 §4.2).
func writeRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	secs := int(retryAfter.Seconds() + 0.999)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	WriteError(w, r, domain.New(domain.CodeQuotaRateLimited,
		domain.WithHTTPStatus(http.StatusTooManyRequests),
		domain.WithParams(map[string]string{"retry_after": strconv.Itoa(secs)})))
}

func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		return strings.TrimSpace(h)
	}
	return strings.TrimSpace(r.Header.Get("X-Management-Token"))
}

// ConstantTimeEqual is exported for the token comparison in the store and for
// tests.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
