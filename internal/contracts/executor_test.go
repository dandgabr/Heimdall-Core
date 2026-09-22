package contracts

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file pins the F2 contract additions (executor.go, translator.go,
// transport.go). The interfaces themselves are covered by the compile-time
// assertions below; the tests here cover the small amount of executable logic
// (Validate, IsIdentity) and lock the invariants the F2 implementations rely on.

// --- compile-time interface assertions ---

var (
	_ Executor     = (*fakeExecutor)(nil)
	_ Stream       = (*fakeStream)(nil)
	_ Duplex       = (*fakeDuplex)(nil)
	_ Translator   = (*fakeTranslator)(nil)
	_ SecretOpener = (*fakeSecretOpener)(nil)
	_ EgressPolicy = (*fakeEgressPolicy)(nil)
	_ HTTPDoer     = (*fakeDoer)(nil)
)

// --- ExecutorDeps.Validate ---

func TestExecutorDepsValidate(t *testing.T) {
	full := ExecutorDeps{
		Clock:    fakeClock{},
		IDs:      fakeIDs{},
		Redactor: fakeRedactor{},
		Egress:   fakeEgressPolicy{},
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("full deps rejected: %v", err)
	}

	// Every required field, removed in turn, must produce provider.invalid with
	// the field name in the params so a wiring mistake is diagnosable.
	tests := []struct {
		name   string
		mutate func(*ExecutorDeps)
		want   string
	}{
		{"missing clock", func(d *ExecutorDeps) { d.Clock = nil }, "clock"},
		{"missing ids", func(d *ExecutorDeps) { d.IDs = nil }, "ids"},
		{"missing redactor", func(d *ExecutorDeps) { d.Redactor = nil }, "redactor"},
		{"missing egress", func(d *ExecutorDeps) { d.Egress = nil }, "egress"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := full
			tt.mutate(&d)
			err := d.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tt.name)
			}
			de, ok := err.(*domain.DomainError)
			if !ok {
				t.Fatalf("err = %T, want *domain.DomainError", err)
			}
			if de.Code != domain.CodeProviderInvalid {
				t.Errorf("code = %q, want %q", de.Code, domain.CodeProviderInvalid)
			}
			if de.HTTPStatus != http.StatusInternalServerError {
				t.Errorf("status = %d", de.HTTPStatus)
			}
			if de.Params["reason"] != "executor deps: missing "+tt.want {
				t.Errorf("reason = %q, missing %q", de.Params["reason"], tt.want)
			}
		})
	}
}

// TestExecutorDepsSecretsNotRequired pins the documented asymmetry: Secrets is
// only needed for a credential that has one, so Validate must not demand it.
func TestExecutorDepsSecretsNotRequired(t *testing.T) {
	d := ExecutorDeps{Clock: fakeClock{}, IDs: fakeIDs{}, Redactor: fakeRedactor{}, Egress: fakeEgressPolicy{}}
	if err := d.Validate(); err != nil {
		t.Fatalf("Secrets=nil rejected: %v", err)
	}
}

// --- Translator.IsIdentity ---

func TestIsIdentity(t *testing.T) {
	if IsIdentity(nil) {
		t.Error("IsIdentity(nil) = true")
	}
	if !IsIdentity(fakeTranslator{from: WireOpenAI, to: WireOpenAI}) {
		t.Error("identity translator reported non-identity")
	}
	if IsIdentity(fakeTranslator{from: WireOpenAI, to: WireAnthropic}) {
		t.Error("cross-format translator reported identity")
	}
}

// TestCanonicalFormatIsOpenAI pins the pivot choice (plan v2: "pivota por
// OpenAI"). Changing the pivot is an architectural decision, not a config tweak.
func TestCanonicalFormatIsOpenAI(t *testing.T) {
	if CanonicalFormat != WireOpenAI {
		t.Fatalf("CanonicalFormat = %q, want %q", CanonicalFormat, WireOpenAI)
	}
}

// --- EgressSpec.Validate ---

func TestEgressSpecValidate(t *testing.T) {
	valid := EgressSpec{BaseURL: "https://api.example.com/v1", ResponseHeaderTimeout: 30 * time.Second}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	// Redirects on with a positive cap is valid.
	withRedirects := EgressSpec{BaseURL: "https://x/v1", FollowRedirects: true, MaxRedirects: 3}
	if err := withRedirects.Validate(); err != nil {
		t.Fatalf("redirect spec rejected: %v", err)
	}

	bad := []struct {
		name string
		spec EgressSpec
	}{
		{"empty url", EgressSpec{}},
		{"negative ttft", EgressSpec{BaseURL: "https://x", ResponseHeaderTimeout: -1}},
		{"negative idle", EgressSpec{BaseURL: "https://x", IdleTimeout: -1}},
		{"negative max bytes", EgressSpec{BaseURL: "https://x", MaxResponseBytes: -1}},
		{"redirects on without cap", EgressSpec{BaseURL: "https://x", FollowRedirects: true}},
		{"cap without redirects", EgressSpec{BaseURL: "https://x", MaxRedirects: 3}},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tt.name)
			}
			de, ok := err.(*domain.DomainError)
			if !ok || de.Code != domain.CodeProviderInvalid {
				t.Fatalf("err = %v, want code %s", err, domain.CodeProviderInvalid)
			}
		})
	}
}

// --- fakes ---

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Time{} }

type fakeIDs struct{}

func (fakeIDs) NewRequestID() domain.RequestID { return "" }

type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

type fakeSecretOpener struct{}

func (fakeSecretOpener) Open(string) ([]byte, error) { return nil, nil }

type fakeEgressPolicy struct{}

func (fakeEgressPolicy) Client(EgressSpec) (HTTPDoer, error) { return fakeDoer{}, nil }

type fakeDoer struct{}

func (fakeDoer) Do(*http.Request) (*http.Response, error) { return nil, nil }

type fakeExecutor struct{}

func (fakeExecutor) Family() domain.ProviderID { return "" }
func (fakeExecutor) Do(context.Context, WireRequest, Credential) (WireResponse, error) {
	return WireResponse{}, nil
}
func (fakeExecutor) DoStream(context.Context, WireRequest, Credential) (Stream, error) {
	return nil, nil
}
func (fakeExecutor) CountTokens(context.Context, WireRequest, domain.ModelID) (int, error) {
	return 0, nil
}

type fakeStream struct{}

func (fakeStream) Headers() http.Header { return nil }
func (fakeStream) Recv() (Chunk, error) { return Chunk{}, nil }
func (fakeStream) Close() error         { return nil }

type fakeDuplex struct{ fakeStream }

func (fakeDuplex) Send(context.Context, WireEvent) error { return nil }

type fakeTranslator struct {
	from WireFormat
	to   WireFormat
}

func (t fakeTranslator) From() WireFormat { return t.from }
func (t fakeTranslator) To() WireFormat   { return t.to }
func (fakeTranslator) Request(canonical []byte, _ string, _ bool) ([]byte, error) {
	return canonical, nil
}
func (fakeTranslator) ResponseFull(payload []byte, _ string) ([]byte, error) { return payload, nil }
func (fakeTranslator) ResponseChunk(payload []byte, _ string) ([]byte, error) {
	return payload, nil
}
