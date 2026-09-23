package pipeline

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// Observer adapts the Chain to the HTTP request path.
//
// It runs the chain's PreRequest stage using METADATA ONLY (request id, method,
// path, header names) and the PostResponse stage once the handler returns. It
// deliberately never reads the request or response BODY: the chain's contract
// says a gate receives the minimum it needs, and the HTTP boundary is where a
// body could most easily be captured by accident.
//
// # Scope (F5-2)
//
// The GateChain is the INFERENCE pipeline (ADR-SEC-04 §1: "Entrada HTTP → …
// → Roteamento e Upstream"). Its admission gates (rate-limit, PII, injection,
// token, memory, credential-masker) reason about inference requests keyed by a
// client key, so they must NOT run against the Management API, health or the
// GUI: doing so let inference traffic exhaust the shared rate-limit bucket and
// throttle the operator's own control surface, and turned a gate Block into a
// plain-text 403 outside the i18n envelope (the F5-2 defect). The observer
// therefore drives the chain ONLY for the inference surface (/v1/*); every
// other route is passed straight through. Management has its own guards
// (LocalOnly + ManagementAuth + Host/Origin).
//
// # Catch-all discipline
//
// The observer still wraps the WHOLE mux, so a NEW /v1/* route is observed
// without an edit here; the scope decision lives in this one place.
type Observer struct {
	chain *Chain
	// Skip, when set, excludes a request from THIS observer's chain pass. It
	// exists for routes whose own handler drives the chain itself (the
	// inference gateway runs PreRequest, the chunk stage and PostResponse):
	// without it a stateful gate would observe those requests TWICE — the F4
	// rate limiter made the double-count observable. It is applied IN ADDITION
	// to the /v1/* scope below.
	Skip func(*http.Request) bool
}

// NewObserver builds the observer over a chain. A nil chain is a programming
// error and is rejected. The chain itself carries the gates (and therefore
// their logging); the observer only drives it from the HTTP path.
func NewObserver(chain *Chain) (*Observer, error) {
	if chain == nil {
		return nil, domain.New(domain.CodeInternal,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "nil gate chain"}),
		)
	}
	return &Observer{chain: chain}, nil
}

// InferencePath reports whether a path is on the inference surface the observer
// drives the chain for. It is the single scope boundary: the OpenAI-compatible
// /v1/* routes. Read-only discovery (GET /v1/models) is part of the surface but
// carries no client key; its keyless request falls into the rate limiter's
// DOCUMENTED shared bucket (a decision already accepted in F4), never into the
// management/health/GUI surface.
func InferencePath(path string) bool {
	return strings.HasPrefix(path, "/v1/")
}

// Handler returns the middleware.
func (o *Observer) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !InferencePath(r.URL.Path) || (o.Skip != nil && o.Skip(r)) {
			// Not the inference surface (or the route owns its own chain):
			// pass through untouched. The chain never sees management/health/GUI.
			next.ServeHTTP(w, r)
			return
		}
		requestID := domain.RequestID(w.Header().Get("X-Request-ID"))
		if requestID == "" {
			requestID = domain.NewRequestID()
		}

		// Build the gate input from metadata only. Provider/credential/model are
		// not resolved at this layer yet, so they stay empty.
		//
		// Headers carries NAMES ONLY: each key maps to an empty value string.
		// r.Header.Clone() would hand a gate the literal Authorization, Cookie
		// and X-Management-Token values, contradicting SEC-13 ("the minimum a
		// gate needs") before any redaction runs.
		in := contracts.GateInput{
			RequestID: requestID,
			Headers:   headerNamesOnly(r.Header),
			Meta: map[string]string{
				"http.method": r.Method,
				"http.path":   r.URL.Path,
			},
		}

		decision, err := o.chain.PreRequest(r.Context(), in)
		if err != nil {
			// The chain already applied the gate failure policy; an error here
			// means a FailClosed gate. Emit the SAME i18n envelope every handler
			// uses, never a plain-text 403 (F5-2).
			writeEnvelopeError(w, r, err)
			return
		}
		// Reuse the request-scoped Derived the chain computed once (ADR-0014
		// §6) in PostResponse, so metadata is never rebuilt.
		if decision.Derived != nil {
			in.Derived = decision.Derived
		}
		switch decision.Kind {
		case contracts.DecisionBlock:
			// A Block carries a SyntheticResponse (cache hit or policy denial):
			// Chain.PreRequest rejects a Block without one, so it is non-nil
			// here. Materialise it with its OWN status and headers (e.g. 429 +
			// Retry-After) instead of discarding it for a 403 (F5-2).
			writeSynthetic(w, decision.Synthetic)
			return
		case contracts.DecisionReroute:
			// Reroute is not enabled at this metadata-only boundary; refuse with
			// a typed envelope rather than silently ignoring the gate's intent.
			writeEnvelopeError(w, r, domain.New(domain.CodeProviderRerouteUnsupported,
				domain.WithHTTPStatus(http.StatusNotImplemented),
				domain.WithScope(domain.ScopeRequest),
				domain.WithParams(map[string]string{
					"reason": "gateway reroute is not enabled in this build",
				})))
			return
		case contracts.DecisionModify:
			// A Modify at this metadata-only boundary has no body to rewrite
			// (the observer never reads one); the change is dropped and the
			// request proceeds unchanged. The gateway owns body rewrites.
		}

		next.ServeHTTP(w, r)

		// PostResponse is best-effort: the response has already been written, so
		// an error must not change it.
		_ = o.chain.PostResponse(r.Context(), in)
	})
}

// writeSynthetic writes a gate's pre-commit synthetic response, preserving its
// status and headers (a rate-limit synthetic carries 429 + Retry-After).
func writeSynthetic(w http.ResponseWriter, s *contracts.SyntheticResponse) {
	status := s.Status
	if status == 0 {
		status = http.StatusOK
	}
	for k, vs := range s.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	_, _ = w.Write(s.Body)
}

// writeEnvelopeError renders a DomainError as the shared JSON {error:{code,
// params}} envelope (ADR-0002), redacting every param through the central
// redactor. It mirrors internal/api/middleware.WriteError so the observer never
// produces a second error format.
func writeEnvelopeError(w http.ResponseWriter, r *http.Request, err error) {
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
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code":   string(de.Code),
		"params": params,
	}})
}

// asDomainError normalises an arbitrary error to a DomainError without leaking
// the cause; a non-domain error becomes an opaque internal error.
func asDomainError(err error) *domain.DomainError {
	if de, ok := err.(*domain.DomainError); ok && de != nil {
		return de
	}
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(500),
		domain.WithParams(map[string]string{"reason": "internal"}))
}

// headerNamesOnly returns a header map whose keys are the request's header
// NAMES and whose every value is an empty string. It is the metadata-only view
// a gate receives at this phase: enough to see that Authorization or Cookie was
// present, never enough to read its value.
func headerNamesOnly(src http.Header) http.Header {
	names := make(http.Header, len(src))
	for name := range src {
		names[name] = nil
	}
	return names
}
