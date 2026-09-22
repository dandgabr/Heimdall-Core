package pipeline

import (
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Observer adapts the Chain to the HTTP request path.
//
// It runs the chain's PreRequest stage for every request using METADATA ONLY
// (request id, method, path, header names) and the PostResponse stage once the
// handler returns. It deliberately never reads the request or response BODY:
// the chain's contract says a gate receives the minimum it needs, and the HTTP
// boundary is where a body could most easily be captured by accident. A gate
// that needs a body is a future, explicit concern, not something this adapter
// hands over by default.
//
// The observer is a middleware so it wraps the whole mux and therefore sees a
// route registered later without changes — the same catch-all discipline the
// security middleware uses.
type Observer struct {
	chain *Chain
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

// Handler returns the middleware.
func (o *Observer) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := domain.RequestID(w.Header().Get("X-Request-ID"))
		if requestID == "" {
			requestID = domain.NewRequestID()
		}

		// Build the gate input from metadata only. Provider/credential/model are
		// not resolved at this layer yet (the router is F3), so they stay empty.
		//
		// Headers carries NAMES ONLY: each key maps to an empty value string.
		// r.Header.Clone() would hand a gate the literal Authorization, Cookie
		// and X-Management-Token values, contradicting SEC-13 ("the minimum a
		// gate needs") before any redaction runs. A gate that needs a specific
		// value must declare it explicitly (capability) in a later phase; that
		// value will then be served redacted, never by reading this map.
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
			// means a FailClosed gate. The observer is metadata-only and its
			// gate is FailOpen, so this path exists for completeness.
			http.Error(w, "gate chain rejected the request", http.StatusForbidden)
			return
		}
		if decision.Kind == contracts.DecisionBlock || decision.Kind == contracts.DecisionReroute {
			// Neither is meaningful at this metadata-only boundary yet; refuse
			// rather than silently ignoring a gate's intent.
			http.Error(w, "gate chain produced a pre-commit decision", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)

		// PostResponse is best-effort: the response has already been written, so
		// an error must not change it.
		_ = o.chain.PostResponse(r.Context(), in)
	})
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
