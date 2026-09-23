package gateway

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// invalidBody is a client-scoped, non-retryable error (error.invalid_request):
// the request itself is malformed, so it never cooldowns a credential.
func invalidBody(reason string) error {
	return domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(http.StatusBadRequest),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": reason}),
	)
}

// errInternal is a core bug (error.internal), never a credential's fault.
func errInternal(reason string) *domain.DomainError {
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(http.StatusInternalServerError),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": reason}),
	)
}

// rerouteUnsupported refuses a pre-commit DecisionReroute: the RerouteTarget
// vocabulary is frozen, but this gateway does not yet validate a target against
// the provider allowlist, so it refuses explicitly rather than silently ignoring
// the gate's intent (SEC-10). The Dispatcher wave owns the allowlist reroute.
func rerouteUnsupported() error {
	return domain.New(domain.CodeProviderRerouteUnsupported,
		domain.WithHTTPStatus(http.StatusNotImplemented),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": "gateway reroute is not enabled in this build"}),
	)
}

// asDomain normalises an error to a DomainError, redacting nothing here (the
// shared middleware redacts params on write).
func asDomain(err error) *domain.DomainError {
	var de *domain.DomainError
	if errors.As(err, &de) && de != nil {
		return de
	}
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(http.StatusInternalServerError),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": "internal"}),
	)
}

// writeError renders a DomainError as the shared JSON envelope, applying the
// same shape every other handler uses.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	de := asDomain(err)
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
		"code":   de.Code,
		"params": params,
	}})
}
