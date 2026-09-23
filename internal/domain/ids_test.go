package domain

import (
	"strings"
	"testing"
)

// TestNewIDsAreUUIDv7 covers the id constructors and their String() methods.
func TestNewIDsAreUUIDv7(t *testing.T) {
	req := NewRequestID()
	if got := req.String(); got != string(req) {
		t.Errorf("RequestID.String() = %q, want %q", got, string(req))
	}
	// A UUIDv7 string is 36 chars with dashes and version nibble '7'.
	if len(req.String()) != 36 {
		t.Errorf("RequestID length = %d, want 36", len(req.String()))
	}
	if !strings.Contains(req.String(), "-") {
		t.Errorf("RequestID %q is not a UUID", req.String())
	}
	if req.String()[14] != '7' {
		t.Errorf("RequestID %q is not version 7", req.String())
	}

	cred := NewCredentialID()
	if cred.String() != string(cred) || len(cred.String()) != 36 {
		t.Errorf("CredentialID = %q", cred.String())
	}

	// Two calls must differ (time-sortable but unique). Assign first so the
	// comparison is not two syntactically identical call expressions.
	first := NewRequestID()
	second := NewRequestID()
	if first == second {
		t.Error("NewRequestID returned the same value twice")
	}
}

func TestProviderIDString(t *testing.T) {
	p := ProviderID("z.ai")
	if p.String() != "z.ai" {
		t.Errorf("ProviderID.String() = %q", p)
	}
}

// TestClientIDString covers the F5.1 client identity type.
func TestClientIDString(t *testing.T) {
	c := ClientID("client-1")
	if c.String() != "client-1" {
		t.Errorf("ClientID.String() = %q", c)
	}
}
