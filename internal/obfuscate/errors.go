package obfuscate

import (
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// obfuscationError builds a domain error for a malformed input to the layer.
// It is ScopeRequest (ADR-0002): the descriptor or the body supplied by the
// caller is the problem, so it never cools down a credential or triggers
// failover. The code is error.invalid_request, an existing catalog entry, so no
// new i18n key is introduced for an internal transformation failure.
func obfuscationError(reason string, cause error) error {
	return domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithCause(cause),
		domain.WithParams(map[string]string{"reason": "obfuscate: " + reason}),
	)
}
