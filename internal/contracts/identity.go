package contracts

import (
	"fmt"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the identity contracts of F1 (ADR-0001): ProviderFamily is
// the protocol implementation, Credential is the account. The distinction is
// what makes multi-account, per-credential quota, round-robin and isolated
// circuit breaking possible at all.
//
// Anti-cycle rule: this package imports only internal/domain and the standard
// library. Nothing here may reference an implementation package.

// AuthMode is the credential mechanism of a Credential. It selects which
// AuthFlow a ProviderFamily builds and how refresh works. AuthNone covers
// local, unauthenticated families (e.g. a local Ollama server), where Sealed is
// empty.
type AuthMode uint8

const (
	// AuthNone: the family needs no credential.
	AuthNone AuthMode = iota
	// AuthAPIKey: a static, contracted key (long-lived, no refresh).
	AuthAPIKey
	// AuthOAuth: an interactive grant (PKCE or device_code) plus refresh.
	AuthOAuth
)

func (m AuthMode) String() string {
	switch m {
	case AuthNone:
		return "none"
	case AuthAPIKey:
		return "api_key"
	case AuthOAuth:
		return "oauth"
	default:
		return "unknown"
	}
}

// ParseAuthMode is the inverse of String, added in F1.4 so the persistence
// layer (internal/store, internal/importers) can round-trip a persisted mode
// without re-implementing the vocabulary. The boolean is false for an unknown
// string so a caller fails closed instead of silently defaulting to AuthNone.
//
// This is the minimal contract addition flagged in the F1.3 report as a missing
// seam: without it, each consumer would carry its own private parser and the
// two could drift.
func ParseAuthMode(s string) (AuthMode, bool) {
	switch s {
	case "none":
		return AuthNone, true
	case "api_key":
		return AuthAPIKey, true
	case "oauth":
		return AuthOAuth, true
	default:
		return AuthNone, false
	}
}

// WireFormat is the on-the-wire dialect a family speaks. It is a string enum so
// a persisted descriptor stays readable and a new family can be added without
// renumbering. It is NOT the family identity: two families may share a wire
// format while differing in endpoints or capabilities.
type WireFormat string

const (
	WireOpenAI    WireFormat = "openai"
	WireAnthropic WireFormat = "anthropic"
	WireGemini    WireFormat = "gemini"
	// WireCloudCode is the Google Cloud Code Assist dialect spoken by the
	// Antigravity connector: an envelope of {project, model, requestId, request}
	// over v1internal:* methods. It is a PROTOCOL, distinct from the obfuscation
	// layer (ADR-0003 §2): the envelope is independent of the fingerprint.
	WireCloudCode WireFormat = "cloudcode"
)

// Modality is one kind of input or output content a model accepts or produces.
type Modality uint8

const (
	ModalityText Modality = iota
	ModalityImage
	ModalityAudio
	ModalityVideo
	ModalityEmbedding
)

func (m Modality) String() string {
	switch m {
	case ModalityText:
		return "text"
	case ModalityImage:
		return "image"
	case ModalityAudio:
		return "audio"
	case ModalityVideo:
		return "video"
	case ModalityEmbedding:
		return "embedding"
	default:
		return "unknown"
	}
}

// ModalitySet is a bitmask of modalities. The zero value is the empty set,
// which is never a valid declaration for a routable model: a family that does
// not know its modalities must return Capabilities(model) ok=false instead.
type ModalitySet uint16

// Add returns the set with the given modalities included.
func (s ModalitySet) Add(ms ...Modality) ModalitySet {
	for _, m := range ms {
		s |= 1 << m
	}
	return s
}

// Has reports whether the set contains the modality.
func (s ModalitySet) Has(m Modality) bool { return s&(1<<m) != 0 }

// String renders the set deterministically (used in tests and diagnostics).
func (s ModalitySet) String() string {
	if s == 0 {
		return "none"
	}
	names := make([]string, 0, 5)
	for m := ModalityText; m <= ModalityEmbedding; m++ {
		if s.Has(m) {
			names = append(names, m.String())
		}
	}
	return strings.Join(names, ",")
}

// Capabilities is a bitmask of protocol features. It is a different axis from
// ModalitySet: capabilities describe what the protocol can do (streaming, tools,
// prompt cache), modalities describe what content flows. A capability gate
// compares RequiredCaps() against the candidate's capability set by bits, never
// by string.
type Capabilities uint64

const (
	CapStream Capabilities = 1 << iota
	CapTools
	CapToolChoice
	CapVision
	CapAudio
	CapEmbedding
	CapCountTokens
	CapSystemPrompt
	CapPromptCache
	CapJSONMode
)

// Add returns the set with the given capabilities included.
func (c Capabilities) Add(cs ...Capabilities) Capabilities {
	for _, x := range cs {
		c |= x
	}
	return c
}

// Has reports whether every bit in want is present in c.
func (c Capabilities) Has(want Capabilities) bool { return c&want == want }

func (c Capabilities) String() string {
	if c == 0 {
		return "none"
	}
	all := []struct {
		bit  Capabilities
		name string
	}{
		{CapStream, "stream"},
		{CapTools, "tools"},
		{CapToolChoice, "tool_choice"},
		{CapVision, "vision"},
		{CapAudio, "audio"},
		{CapEmbedding, "embedding"},
		{CapCountTokens, "count_tokens"},
		{CapSystemPrompt, "system_prompt"},
		{CapPromptCache, "prompt_cache"},
		{CapJSONMode, "json_mode"},
	}
	names := make([]string, 0, len(all))
	for _, e := range all {
		if c&e.bit != 0 {
			names = append(names, e.name)
		}
	}
	return strings.Join(names, ",")
}

// Secret is a string that refuses to render itself. It implements
// fmt.Formatter, not just fmt.Stringer, because fmt only consults Stringer for
// a handful of verbs: %d, %x, %t and %c on a named string type bypass String()
// and would print the raw value with a "%!d(contracts.Secret=...)" marker.
// Format closes that hole for every verb fmt routes through it, so a careless
// log statement cannot leak a token by picking the wrong verb.
//
// Known residual (measured, not assumed): fmt handles %p and %T in printArg
// BEFORE consulting Formatter, so no non-pointer type can intercept them. %T is
// harmless (it prints the type name, not the value). %p on a Secret value would
// reflect its contents; using %p on a secret is a review-blocking mistake, and
// the mitigation is that Reveal is the only sanctioned read. If that residual
// ever needs closing, Secret must become an opaque pointer type — deliberately
// not done here, because value semantics keep the contracts simple and %p on a
// credential is not a plausible call site.
//
// Call Reveal only at the single point that actually needs the bytes (the
// Executor, or Seal before persistence).
type Secret string

const redactedPlaceholder = "[REDACTED]"

// String implements fmt.Stringer and always redacts.
func (Secret) String() string { return redactedPlaceholder }

// GoString implements fmt.GoStringer and always redacts (%#v).
func (Secret) GoString() string { return "contracts.Secret(" + redactedPlaceholder + ")" }

// Format implements fmt.Formatter so every verb fmt routes here — including %d,
// %x, %t and %c, which skip Stringer — renders the placeholder without the
// value.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedPlaceholder))
}

// Reveal returns the underlying value. Every call site is a deliberate
// exposure and must be justified at review.
func (s Secret) Reveal() string { return string(s) }

// IsEmpty reports whether no secret is set.
func (s Secret) IsEmpty() bool { return s == "" }

// AccountMeta is the non-secret identity of an upstream account. It is safe to
// log (it still flows through the central Redactor as defence in depth) and is
// what the GUI shows to distinguish two accounts of the same family.
type AccountMeta struct {
	// Subject is the upstream stable user id, when the provider exposes one.
	Subject string
	// Email is the account e-mail, when known.
	Email string
	// DisplayName is a human label from the provider.
	DisplayName string
	// Plan is the subscription tier a session belongs to, when known.
	Plan string
	// Project is the provider-side project/tenant id a session is bound to,
	// when the provider requires one per request (e.g. the CloudCode
	// `cloudaicompanionProject` discovered by the Antigravity OAuth
	// post-exchange). Empty when the provider has no such concept. It is a
	// non-secret routing value, not a credential.
	Project string
	// Scopes are the granted OAuth scopes.
	Scopes []string
}

// Credential is the account aggregate (ADR-0001). It never carries plaintext
// secret material: Sealed is the `enc:v1:` ciphertext produced by the
// SecretStore, and the plaintext exists only inside the Executor after Open.
//
// Credential is passed BY VALUE across boundaries (Router, Dispatcher, Gate).
// A shared pointer would couple lifecycles and make refresh/rotation racy.
type Credential struct {
	ID       domain.CredentialID
	Provider domain.ProviderID
	AuthMode AuthMode
	// Label is the operator-facing name ("work account"); never a secret.
	Label string
	Meta  AccountMeta
	// Sealed is the ciphertext of the credential secret (ADR-SEC-01), or empty
	// for AuthNone. It is opaque at this layer: only SecretStore.Open yields
	// plaintext, and only the Executor calls it.
	Sealed []byte
	// CreatedAt is when the account was first stored.
	CreatedAt time.Time
	// ExpiresAt is when the access token expires; zero means "unknown / no
	// expiry". AuthNone credentials leave it zero.
	ExpiresAt time.Time
}

// String renders a Credential without exposing Sealed.
func (c Credential) String() string {
	return fmt.Sprintf("Credential{id:%s provider:%s mode:%s label:%q}",
		c.ID, c.Provider, c.AuthMode, c.Label)
}

// ProviderDescriptor is the static description of a family that an AuthFlow
// needs to run a grant. It is deliberately independent of ProviderFamily so a
// flow can be built and tested without a live family implementation.
//
// ClientID is a PUBLIC identifier in the OAuth sense (PKCE and device_code are
// public-client flows). RequiresClientSecret is documented at its field below.
type ProviderDescriptor struct {
	ID       domain.ProviderID
	Protocol WireFormat
	// DisplayName is the human label; the GUI localises it separately via the
	// i18n code convention, so this is only a fallback.
	DisplayName string
	// AuthEndpoint is the authorization endpoint (PKCE).
	AuthEndpoint string
	// TokenEndpoint is the token endpoint (PKCE exchange and refresh).
	TokenEndpoint string
	// DeviceAuthEndpoint is the device authorization endpoint (device_code).
	DeviceAuthEndpoint string
	// DefaultScopes are requested when the caller does not specify scopes.
	DefaultScopes []string
	// RedirectAllowlist is the exact set of redirect URIs the flow may use. An
	// entry is matched exactly (no prefix or wildcard): the loopback callback
	// uses an ephemeral port, so the registered value is the stable loopback
	// URI and the port is validated separately by the OAuth package.
	RedirectAllowlist []string
	// ClientID is the public OAuth client identifier.
	ClientID string
	// ClientSecret is the PUBLIC client secret embedded in the provider's own
	// CLI (e.g. the Antigravity/CloudCode CLI client). It is NOT the user's
	// secret: it ships in the vendor's binary and is public by construction.
	// ADR-0003 registers the decision that it lives HERE, in the descriptor,
	// alongside ClientID, rather than in the SecretStore — putting public
	// material in the vault would give it the protection of a user secret and
	// obscure that it is not one.
	ClientSecret string
	// RequiresClientSecret selects the authorization_code flow WITH a client
	// secret (the CLI client is not PKCE-only) rather than pure PKCE. It is
	// true only for descriptors whose public client requires it (Antigravity);
	// the flows the v1 shipped originally are false. See ADR-0003.
	RequiresClientSecret bool
	// Obfuscation is the per-provider harness-fingerprint layer (ADR-0003 §1).
	// It is EMPTY for every provider that does not restrict its harness; a
	// non-empty value is an explicit, versioned opt-in. It is applied by the
	// family's executor, never globally.
	Obfuscation Obfuscation
	// RiskNotice is the i18n code of the ToS warning shown on the CLI and GUI
	// when this provider is enabled (ADR-0003 §4). It is REQUIRED whenever
	// Obfuscation is non-empty. It is an i18n code, not prose, like every other
	// user-facing string.
	RiskNotice string
	// Future marks a PLANNED provider whose integration is not complete yet:
	// the descriptor is fully declared (endpoints, client id, obfuscation) and
	// the provider is registered so it appears in the catalog, but it is not
	// usable in this build. It is deliberately DISTINCT from both
	// PendingEndpoints (an endpoint is unconfirmed) and a missing credential
	// (the user has not added one): a Future provider is not-ready because the
	// FEATURE is not shipped, and is reported with provider.future rather than a
	// "blocked" state that would suggest a user-fixable condition.
	Future bool
	// FutureNote is a short, non-localised note explaining what the Future
	// provider still needs (e.g. "requires OAuth login and router wiring").
	// It is diagnostic only; the user-facing message is the provider.future i18n
	// code. Non-empty only when Future is true.
	FutureNote string
}

// IsObfuscated reports whether the descriptor declares any obfuscation. It is the
// single predicate the executor and the tests use, so "no obfuscation" is one
// check rather than five field comparisons. Obfuscation contains a slice and is
// therefore not comparable with ==, so the check is field-by-field.
func (d ProviderDescriptor) IsObfuscated() bool {
	o := d.Obfuscation
	return o.UserAgent != "" ||
		o.RequiresUserAgent ||
		len(o.PromptRewrites) > 0 ||
		o.ToolCloaking != nil ||
		o.SyntheticProject
}

// Obfuscation is the per-provider harness-fingerprint layer (ADR-0003 §1). Every
// field is OPTIONAL and independent; a zero Obfuscation is "no obfuscation", and
// the obfuscate package applies each technique only when its field is set.
type Obfuscation struct {
	// UserAgent is the UA string to present. When empty, the executor sends its
	// own.
	UserAgent string
	// RequiresUserAgent forces UserAgent to be sent even if some default UA
	// exists, so an empty UserAgent is never silently substituted.
	RequiresUserAgent bool
	// PromptRewrites are applied to the system prompt, in order.
	PromptRewrites []PromptRewrite
	// ToolCloaking renames client tools and injects decoys; nil means no tool
	// cloaking.
	ToolCloaking *ToolCloaking
	// SyntheticProject makes the executor generate a project id when the
	// provider's discovery call returns none.
	SyntheticProject bool
}

// PromptRewrite is one system-prompt substitution. IsRegex selects the matching
// mode: false is a literal substring replace, true is a regular expression.
// Keeping the mode explicit (rather than "looks like a regex") makes a golden
// file unambiguous and avoids a pattern like "a.b" being silently treated as a
// regex when the author meant the literal.
type PromptRewrite struct {
	From    string
	To      string
	IsRegex bool
}

// ToolCloaking renames the client's tools and injects decoy tools. NameSuffix is
// appended to every client tool name; DecoyTools are appended verbatim. The
// reverse map (suffixed -> original name) is returned by the obfuscate package
// so responses can be uncloaked.
type ToolCloaking struct {
	NameSuffix string
	DecoyTools []ToolDecoy
}

// ToolDecoy is one injected decoy tool: a name and a neutral description. The
// decoys impersonate the provider's native tools; the description is deliberately
// generic, matching the reference connector's "currently unavailable" text.
type ToolDecoy struct {
	Name        string
	Description string
}

// ProviderFamily is the protocol implementation (ADR-0001): one per wire
// dialect, stateless with respect to accounts, and the extension point for new
// providers. It builds a per-credential Executor but owns no credential state.
//
// Capabilities reports the feature set for a specific model; ok=false means the
// family does not know the model and the Router must skip it. A family MUST NOT
// return an empty capability set with ok=true.
type ProviderFamily interface {
	// ID is the immutable family identifier.
	ID() domain.ProviderID
	// AuthModes lists the mechanisms this family supports, in preference order
	// when more than one applies.
	AuthModes() []AuthMode
	// Protocol is the wire dialect spoken.
	Protocol() WireFormat
	// Capabilities returns the feature set for model, or ok=false if unknown.
	Capabilities(model domain.ModelID) (Capabilities, bool)
	// BuildExecutor constructs the transport+auth for one credential. The
	// credential's Sealed secret is opened by the returned Executor, never by
	// the family, so plaintext does not outlive the executor. The full Executor
	// contract is frozen in executor.go (F2).
	BuildExecutor(cred Credential, deps ExecutorDeps) (Executor, error)
}
