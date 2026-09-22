package domain

import (
	"fmt"
	"time"
)

// ErrScope tells a caller how far a failure should propagate. Without it a
// circuit breaker cannot distinguish a client error (scope request) from an
// exhausted credential or a provider outage, and would cool down accounts for
// bad requests.
type ErrScope uint8

const (
	// ScopeRequest: the failure is caused by the request itself. Never cool
	// down a credential for it, never retry it.
	ScopeRequest ErrScope = iota
	// ScopeCredential: the failure belongs to one credential (quota, token).
	ScopeCredential
	// ScopeProvider: the failure belongs to the whole provider (outage).
	ScopeProvider
)

func (s ErrScope) String() string {
	switch s {
	case ScopeRequest:
		return "request"
	case ScopeCredential:
		return "credential"
	case ScopeProvider:
		return "provider"
	default:
		return "unknown"
	}
}

// DomainError is the single error shape the core returns. Code and Params are
// i18n keys; HTTPStatus/Retryable/Scope/RetryAfter drive routing decisions.
type DomainError struct {
	Code       string
	Params     map[string]string
	HTTPStatus int
	Retryable  bool
	Scope      ErrScope
	RetryAfter time.Duration
	Cause      error
}

func (e *DomainError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.Cause)
	}
	return e.Code
}

// Unwrap exposes the wrapped cause to errors.Is/errors.As. It tolerates a nil
// receiver, matching Error(), so a nil *DomainError travelling through
// errors.As does not panic.
func (e *DomainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Option customises a DomainError at construction time.
type Option func(*DomainError)

// WithParams attaches i18n placeholders.
func WithParams(params map[string]string) Option {
	return func(e *DomainError) {
		if e.Params == nil {
			e.Params = make(map[string]string, len(params))
		}
		for k, v := range params {
			e.Params[k] = v
		}
	}
}

// WithHTTPStatus sets the status the API layer should emit.
func WithHTTPStatus(status int) Option {
	return func(e *DomainError) { e.HTTPStatus = status }
}

// Retry hints that the operation may be retried.
func Retry() Option {
	return func(e *DomainError) { e.Retryable = true }
}

// WithScope sets the propagation scope.
func WithScope(scope ErrScope) Option {
	return func(e *DomainError) { e.Scope = scope }
}

// WithRetryAfter attaches an upstream retry hint.
func WithRetryAfter(d time.Duration) Option {
	return func(e *DomainError) { e.RetryAfter = d }
}

// WithCause wraps an underlying error.
func WithCause(err error) Option {
	return func(e *DomainError) { e.Cause = err }
}

// New builds a DomainError. Defaults are conservative: HTTP 500, scope request,
// not retryable.
func New(code string, opts ...Option) *DomainError {
	e := &DomainError{
		Code:       code,
		HTTPStatus: 500,
		Scope:      ScopeRequest,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}
