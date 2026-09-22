package domain

import (
	"errors"
	"testing"
	"time"
)

// TestNewDefaults pins the conservative defaults every error site relies on:
// a caller that forgets an option must not accidentally get a retryable 200.
func TestNewDefaults(t *testing.T) {
	e := New("some.code")

	if e.Code != "some.code" {
		t.Errorf("Code = %q", e.Code)
	}
	if e.HTTPStatus != 500 {
		t.Errorf("HTTPStatus = %d, want 500", e.HTTPStatus)
	}
	if e.Scope != ScopeRequest {
		t.Errorf("Scope = %v, want ScopeRequest", e.Scope)
	}
	if e.Retryable {
		t.Error("Retryable must default to false")
	}
	if e.Params != nil {
		t.Errorf("Params must default to nil, got %v", e.Params)
	}
	if e.RetryAfter != 0 {
		t.Errorf("RetryAfter = %v, want 0", e.RetryAfter)
	}
}

func TestOptionsApply(t *testing.T) {
	cause := errors.New("upstream exploded")

	e := New("cfg.load",
		WithParams(map[string]string{"reason": "bad toml"}),
		WithHTTPStatus(400),
		Retry(),
		WithScope(ScopeProvider),
		WithRetryAfter(30*time.Second),
		WithCause(cause),
	)

	if e.HTTPStatus != 400 {
		t.Errorf("HTTPStatus = %d", e.HTTPStatus)
	}
	if !e.Retryable {
		t.Error("Retryable = false, want true")
	}
	if e.Scope != ScopeProvider {
		t.Errorf("Scope = %v, want ScopeProvider", e.Scope)
	}
	if e.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v", e.RetryAfter)
	}
	if e.Params["reason"] != "bad toml" {
		t.Errorf("Params = %v", e.Params)
	}
	if !errors.Is(e, cause) {
		t.Error("Unwrap chain does not reach the cause")
	}
}

// TestWithParamsMerges checks that repeated WithParams calls accumulate instead
// of replacing, so several layers can each contribute a placeholder.
func TestWithParamsMerges(t *testing.T) {
	e := New("some.code",
		WithParams(map[string]string{"a": "1"}),
		WithParams(map[string]string{"b": "2"}),
	)
	if e.Params["a"] != "1" || e.Params["b"] != "2" {
		t.Errorf("Params = %v, want both a and b", e.Params)
	}
}

func TestErrorMessage(t *testing.T) {
	if got := New("only.code").Error(); got != "only.code" {
		t.Errorf("Error() = %q, want the code", got)
	}

	cause := errors.New("boom")
	got := New("some.code", WithCause(cause)).Error()
	if got != "some.code: boom" {
		t.Errorf("Error() = %q", got)
	}
}

func TestErrorNilReceiver(t *testing.T) {
	var e *DomainError
	if got := e.Error(); got != "<nil>" {
		t.Errorf("nil Error() = %q, want <nil>", got)
	}
	if e.Unwrap() != nil {
		t.Error("nil Unwrap() must be nil")
	}
}

func TestErrScopeString(t *testing.T) {
	tests := map[ErrScope]string{
		ScopeRequest:    "request",
		ScopeCredential: "credential",
		ScopeProvider:   "provider",
		ErrScope(99):    "unknown",
	}
	for scope, want := range tests {
		if got := scope.String(); got != want {
			t.Errorf("ErrScope(%d).String() = %q, want %q", scope, got, want)
		}
	}
}
