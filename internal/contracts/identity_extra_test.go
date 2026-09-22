package contracts

import (
	"fmt"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// sprintf is a thin alias so the verb loop reads uniformly.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// TestAuthModeStringAndParse covers every enum value, the out-of-range fallback
// and the round-trip through ParseAuthMode.
func TestAuthModeStringAndParse(t *testing.T) {
	tests := []struct {
		mode AuthMode
		want string
	}{
		{AuthNone, "none"},
		{AuthAPIKey, "api_key"},
		{AuthOAuth, "oauth"},
		{AuthMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("AuthMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}

	// ParseAuthMode round-trips the three real values and rejects the rest.
	for _, mode := range []AuthMode{AuthNone, AuthAPIKey, AuthOAuth} {
		got, ok := ParseAuthMode(mode.String())
		if !ok || got != mode {
			t.Errorf("ParseAuthMode(%q) = %v, %v; want %v, true", mode.String(), got, ok, mode)
		}
	}
	for _, bad := range []string{"", "unknown", "oauth2", "APIKey"} {
		if got, ok := ParseAuthMode(bad); ok || got != AuthNone {
			t.Errorf("ParseAuthMode(%q) = %v, %v; want AuthNone, false", bad, got, ok)
		}
	}
}

func TestModalityString(t *testing.T) {
	tests := []struct {
		m    Modality
		want string
	}{
		{ModalityText, "text"},
		{ModalityImage, "image"},
		{ModalityAudio, "audio"},
		{ModalityVideo, "video"},
		{ModalityEmbedding, "embedding"},
		{Modality(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("Modality(%d).String() = %q, want %q", tt.m, got, tt.want)
		}
	}
}

func TestModalitySetString(t *testing.T) {
	if got := ModalitySet(0).String(); got != "none" {
		t.Errorf("empty ModalitySet = %q, want none", got)
	}
	set := ModalitySet(0).Add(ModalityText, ModalityImage, ModalityEmbedding)
	if got := set.String(); got != "text,image,embedding" {
		t.Errorf("ModalitySet.String() = %q", got)
	}
	if set.Has(ModalityAudio) {
		t.Error("unadded modality reported present")
	}
}

func TestCapabilitiesString(t *testing.T) {
	if got := Capabilities(0).String(); got != "none" {
		t.Errorf("empty Capabilities = %q, want none", got)
	}
	caps := Capabilities(0).Add(CapStream, CapTools, CapPromptCache)
	got := caps.String()
	for _, want := range []string{"stream", "tools", "prompt_cache"} {
		if !contains(got, want) {
			t.Errorf("Capabilities.String() = %q, missing %q", got, want)
		}
	}
	// Has is "all bits present".
	if caps.Has(CapStream | CapVision) {
		t.Error("Has matched a partially-satisfied query")
	}
	if !caps.Has(CapStream | CapTools) {
		t.Error("Has failed on a satisfied query")
	}
}

// TestSecretFormatEveryVerb covers String, GoString and Format for the verbs fmt
// routes through the Formatter. %p is excluded: fmt handles it before consulting
// the interface (documented residual on Secret).
func TestSecretFormatEveryVerb(t *testing.T) {
	const token = "sk-live-format-test-1234567890"
	s := Secret(token)

	if got := s.String(); got != redactedPlaceholder {
		t.Errorf("String() = %q", got)
	}
	if got := s.GoString(); got != "contracts.Secret("+redactedPlaceholder+")" {
		t.Errorf("GoString() = %q", got)
	}
	for _, verb := range []string{"%s", "%v", "%q", "%d", "%x", "%t", "%c"} {
		rendered := sprintf(verb, s)
		if contains(rendered, token) {
			t.Errorf("verb %q leaked the secret: %s", verb, rendered)
		}
	}
	if (Secret("")).IsEmpty() != true {
		t.Error("empty Secret.IsEmpty() = false")
	}
	if s.Reveal() != token {
		t.Error("Reveal() mismatch")
	}
}

func TestCredentialStringHidesSealed(t *testing.T) {
	c := Credential{
		ID:       domain.CredentialID("cred-1"),
		Provider: domain.ProviderID("z.ai"),
		AuthMode: AuthAPIKey,
		Label:    "work",
		Sealed:   []byte("enc:v1:SUPERSECRET"),
	}
	got := c.String()
	if contains(got, "SUPERSECRET") {
		t.Fatalf("Credential.String() leaked the sealed blob: %s", got)
	}
	for _, want := range []string{"cred-1", "z.ai", "api_key", "work"} {
		if !contains(got, want) {
			t.Errorf("Credential.String() = %q, missing %q", got, want)
		}
	}
}

// TestProviderDescriptorIsObfuscated covers the predicate that decides whether
// the obfuscation layer runs (ADR-0003 §1): the zero descriptor is not
// obfuscated, and each technique independently makes it so.
func TestProviderDescriptorIsObfuscated(t *testing.T) {
	tests := []struct {
		name string
		desc ProviderDescriptor
		want bool
	}{
		{"zero", ProviderDescriptor{}, false},
		{"user agent", ProviderDescriptor{Obfuscation: Obfuscation{UserAgent: "ua"}}, true},
		{"requires ua", ProviderDescriptor{Obfuscation: Obfuscation{RequiresUserAgent: true}}, true},
		{"rewrites", ProviderDescriptor{Obfuscation: Obfuscation{PromptRewrites: []PromptRewrite{{From: "a"}}}}, true},
		{"cloaking", ProviderDescriptor{Obfuscation: Obfuscation{ToolCloaking: &ToolCloaking{}}}, true},
		{"project", ProviderDescriptor{Obfuscation: Obfuscation{SyntheticProject: true}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.IsObfuscated(); got != tt.want {
				t.Errorf("IsObfuscated() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWireCloudCode pins the CloudCode dialect value (ADR-0003 §2).
func TestWireCloudCode(t *testing.T) {
	if WireCloudCode != "cloudcode" {
		t.Fatalf("WireCloudCode = %q", WireCloudCode)
	}
	// It must be usable as a Protocol value.
	d := ProviderDescriptor{ID: "antigravity", Protocol: WireCloudCode}
	if d.Protocol != WireCloudCode {
		t.Fatalf("descriptor protocol = %q", d.Protocol)
	}
}
