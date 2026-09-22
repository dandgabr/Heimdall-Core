package contracts

// This file freezes the Translator contract of F2 (plan v2, F2; review note
// "Translator vira contrato próprio").
//
// A Translator converts between the CANONICAL pivot format and one provider's
// wire format. It is PURE by contract: no context, no I/O, no clock, no logger,
// no randomness. Purity is what makes it verifiable with golden files — the same
// input bytes must produce the same output bytes on every run and machine — and
// it is why the Executor (transport+auth) and the Translator are separate
// components rather than one.
//
// CANONICAL FORMAT — the pivot is OpenAI-shaped JSON (plan v2: "pivota por
// OpenAI"). Rationale: the OpenAI chat-completions schema is the lingua franca
// every compatible provider already speaks, the gateway's client surface is
// OpenAI-compatible (internal/api/openai), and making it the pivot means the
// OpenAI family's Translator is the identity function — the common path costs
// nothing and has nothing to get wrong. A provider-specific pivot (Anthropic,
// for instance) would force every other family through an unnecessary hop and
// make the identity case the rare one.
//
// DIRECTION — From() is the pivot format and To() is the provider format:
//   - Request converts pivot -> provider (From -> To);
//   - ResponseFull / ResponseChunk convert provider -> pivot (To -> From).
// A Translator whose From() == To() (the OpenAI family) is the IDENTITY: it
// returns its input unchanged. The IsIdentity helper exposes that so the
// pipeline can skip the call entirely on the common path.

// CanonicalFormat is the pivot wire format every Translator converts through.
// It is a named constant, not a bare string, so the pivot is stated once.
const CanonicalFormat = WireOpenAI

// Translator converts between the canonical pivot and one provider format. See
// the file comment for the direction convention and the purity invariant.
type Translator interface {
	// From is the source format; by convention this is the canonical pivot for
	// a concrete provider translator.
	From() WireFormat
	// To is the target format; by convention this is the provider format.
	To() WireFormat

	// Request converts a canonical pivot request into the provider wire format.
	// canonical is the pivot JSON; the returned bytes are the provider payload.
	// model and stream are passed explicitly because some providers restructure
	// where those live, so reading them out of canonical is not enough.
	Request(canonical []byte, model string, stream bool) ([]byte, error)

	// ResponseFull converts a complete non-streaming provider response into the
	// canonical pivot format. payload is the provider payload and the return is
	// pivot JSON. model is supplied because some providers omit it from the
	// response and the pivot requires it.
	ResponseFull(payload []byte, model string) ([]byte, error)

	// ResponseChunk converts ONE provider stream event into the canonical pivot
	// format. A provider frame may decode to zero, one or several pivot events;
	// the convention is that the returned bytes are the pivot representation of
	// this single upstream frame, and an empty return means "nothing to emit"
	// (e.g. a keep-alive or a role-only frame).
	ResponseChunk(payload []byte, model string) ([]byte, error)
}

// IsIdentity reports whether a Translator is a no-op (From == To), which is the
// case for the canonical OpenAI family. The pipeline uses it to skip the call on
// the common path; a Translator is free to implement From() == To() while still
// normalising, but the canonical family does not, and the helper documents the
// intended shortcut.
func IsIdentity(t Translator) bool {
	return t != nil && t.From() == t.To()
}
