package contracts

import (
	"context"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the transport+auth contract of F2 (plan v2, F2; review note
// "contratos/streaming"). It replaces the provisional one-method Executor seam
// that lived in identity.go during F1.
//
// Scope split (review note, structural change #3):
//   - Executor is TRANSPORT + AUTH only: it opens the credential, builds the
//     upstream request and moves bytes. It does not implement schema translation
//     — it delegates to the family's Translator (pure, golden-tested, see
//     translator.go).
//   - Translator is PURE: no context, no I/O. It is where the wire dialect is
//     handled, so it can be verified with golden files without a network.
//
// CANONICAL PAYLOAD DECISION — why []byte + minimal metadata, not typed structs:
// the internal pivot format is OpenAI-shaped JSON (plan v2: "pivota por OpenAI").
// WireRequest.Body and WireResponse.Body carry that JSON VERBATIM, and only the
// fields routing needs (model, stream) are denormalised into typed fields. A
// fully typed request struct was rejected because it would force this core to
// model every provider-specific extension (reasoning/thinking/cache_control/
// safety settings…); any field not modelled would be silently dropped on the
// way through. Byte-preservation is what the F0 passthrough already relies on
// ("the body is forwarded verbatim so unknown fields survive"), and it is the
// property that keeps a new provider from requiring a core change.
//
// STREAMING INVARIANTS (normative for every Executor; from the review note and
// ADR-SEC-05 §6). These are the properties F2.2 must satisfy and F2.2's tests
// must assert:
//
//  1. THE `committed` FLAG IS SET ON THE FIRST DOWNSTREAM BYTE. Until that byte
//     is flushed, the pipeline may still change its mind: a non-2xx upstream, a
//     transport error or an empty stream are all pre-commit and may be retried
//     or failed over. After it, the response is committed.
//  2. POST-COMMIT FORBIDS REROUTE AND MODEL SWAP. Once committed, a different
//     provider or model MUST NOT be tried for the same request: the client
//     already holds a partial response from the original route. The only legal
//     terminal moves are a clean end or an in-band error.
//  3. AN ERROR AFTER HTTP 200 IS A TERMINAL SSE EVENT, NEVER AN HTTP ERROR. The
//     status line was already sent, so a mid-stream failure is emitted as a
//     final `event: error` chunk (see passthrough/stream.go:writeSSEError). A
//     truncated 200 with no terminal event is a bug, not an acceptable failure
//     mode.
//  4. BACKPRESSURE IS A BOUNDED CHANNEL. A Recv-pull Stream or a bounded channel
//     is required; an unbounded buffer would let a slow client grow process
//     memory without limit. The reader blocks on a full buffer instead.
//  5. CANCELLATION FLOWS THROUGH ctx. The Stream is bound to the context passed
//     to DoStream: cancelling it cancels the upstream request and makes Recv
//     return a terminal error. Every wait selects on ctx.Done(); Close is
//     idempotent and safe from any goroutine.
//  6. EXACTLY ONE TERMINAL OUTCOME. A valid stream ends with io.EOF, or with a
//     typed *domain.DomainError. A mid-stream error is never io.EOF, and EOF is
//     never followed by more data.

// WireRequest is the canonical request an Executor sends. Body is the verbatim
// canonical JSON; messages and tools live inside it, deliberately unmodelled so
// provider extensions survive. Model and Stream are denormalised because the
// transport and the token counter need them without re-parsing the body.
//
// INVARIANT: Model MUST equal the "model" field inside Body. It is a routing
// denormalisation, not a second source of truth; a caller that changes one must
// change both (the Translator/Executor preserves the original bytes).
type WireRequest struct {
	// Body is the canonical (OpenAI-shaped) request JSON, kept verbatim.
	Body []byte
	// Model is the upstream model, mirrored from Body for routing and counting.
	Model domain.ModelID
	// Stream requests a streaming (SSE) response. It mirrors Body's "stream".
	Stream bool
	// Headers are extra provider-specific request headers, already free of
	// credentials: the Executor injects auth itself, so a header here can never
	// carry an upstream token.
	Headers http.Header
}

// WireResponse is the canonical non-streaming response an Executor returns.
// Body is the canonical JSON produced by the family's Translator from the
// provider payload.
type WireResponse struct {
	// Status is the upstream HTTP status actually received.
	Status int
	// Headers are the upstream response headers worth forwarding.
	Headers http.Header
	// Body is the canonical response JSON (Translator output).
	Body []byte
}

// Chunk is ONE decoded stream event, already de-framed from the transport
// (SSE/NDJSON/WebSocket frames). It is deliberately not a raw TCP buffer: a
// transport read boundary and an application event boundary are not the same
// thing, and gates must see events, not partial frames.
type Chunk struct {
	// Data is the event payload.
	Data []byte
	// Event is the SSE event name when the transport has one ("", "message",
	// "done", "error"). Empty for transports without named events.
	Event string
	// ID is the optional SSE id field, preserved for resumability.
	ID string
}

// Stream is the pull-based read side of a streamed response. Pull (rather than a
// channel handed to the caller) is what makes backpressure natural: Recv blocks
// until data, a terminal error, or EOF.
//
// The Stream is BOUND to the context passed to Executor.DoStream. Recv takes no
// context for that reason: cancelling the DoStream context cancels the upstream
// call and makes Recv return a terminal error.
type Stream interface {
	// Headers returns the upstream response headers. Valid once the stream is
	// live (a non-2xx is returned by DoStream as an error, not as a Stream).
	Headers() http.Header
	// Recv returns the next event. It returns io.EOF exactly once at a clean
	// end, and a *domain.DomainError on a mid-stream failure (never io.EOF in
	// that case). Calls after a terminal outcome return the same terminal
	// outcome.
	Recv() (Chunk, error)
	// Close releases the upstream body. It is idempotent and safe to call from
	// any goroutine, and it is the caller's obligation (the Executor does not
	// close a returned Stream).
	Close() error
}

// WireEvent is one frame on a bidirectional (WebSocket) transport.
type WireEvent struct {
	Data  []byte
	Event string
}

// Duplex is the bidirectional session port. It is declared now even though F2
// ships no WebSocket family, so the executor contract does not have to change
// when one arrives. A Duplex is also a Stream (it can be read with Recv).
type Duplex interface {
	Stream
	// Send writes one frame upstream. It honours ctx for cancellation.
	Send(ctx context.Context, ev WireEvent) error
}

// Executor is the frozen transport+auth contract (F2). One instance serves ONE
// credential of one family: the credential is passed per call so the executor
// holds no account state, and it opens the sealed secret internally (via
// ExecutorDeps.Secrets) so plaintext never crosses this boundary.
//
// The Executor does not translate schemas: it uses the family's pure Translator
// to move between the canonical Body and the provider wire format.
type Executor interface {
	// Family reports which family built this executor.
	Family() domain.ProviderID
	// Do performs a non-streaming call and returns the canonical response.
	Do(ctx context.Context, req WireRequest, cred Credential) (WireResponse, error)
	// DoStream performs a streaming call. A non-2xx upstream is returned as an
	// error here (pre-commit); on success the returned Stream is live and the
	// caller owns Close.
	DoStream(ctx context.Context, req WireRequest, cred Credential) (Stream, error)
	// CountTokens returns the input token count for req. A family without the
	// CapCountTokens capability returns provider.executor_unavailable rather
	// than a fabricated number.
	CountTokens(ctx context.Context, req WireRequest, model domain.ModelID) (int, error)
}

// SecretOpener is the consumer-defined view of the SecretStore: the Executor
// needs to OPEN a credential's sealed blob, never to seal one (sealing happens
// at the auth/persistence boundary). Declaring the narrow port here follows the
// Go idiom and keeps the Executor coupled to nothing but the one method it
// calls. *secret.Store satisfies it.
type SecretOpener interface {
	// Open decrypts an enc:v1 envelope. On any failure it returns an error and
	// never partial plaintext (ADR-SEC-01 fail-closed).
	Open(encoded string) ([]byte, error)
}

// ExecutorDeps is the support-service bundle a ProviderFamily receives in
// BuildExecutor. It is the seams-only bundle: every field is a port declared in
// this package, so no implementation package is referenced (anti-cycle) and the
// Executor is testable with fakes.
type ExecutorDeps struct {
	// Clock is the injectable time source (timeouts, TTL, retry-after).
	Clock Clock
	// IDs supplies correlation identifiers.
	IDs IDGen
	// Redactor is the central secret scrubber for any diagnostic string.
	Redactor Redactor
	// Secrets opens a credential's sealed blob. It is required only for
	// AuthAPIKey/AuthOAuth credentials; a caller wiring only AuthNone families
	// may leave it nil.
	Secrets SecretOpener
	// Egress is the mandatory outbound-transport policy (ADR-SEC-05). Every
	// client an Executor uses MUST come from it; building an http.Client
	// directly is forbidden.
	Egress EgressPolicy
	// Refresher is the OPTIONAL renewal port of BD02-1: an executor holding an
	// OAuth credential whose access token is at/past expiry calls it to obtain
	// the refreshed, already-persisted credential before presenting the bearer.
	// It is wired only by the composition root (the renewal needs the flow
	// factory and the vault); a nil Refresher means "no renewal", and the
	// credential is used as stored.
	Refresher CredentialRefresher
}

// CredentialRefresher renews an OAuth credential at the point of use. The
// implementation (composition root) performs the single-flight token exchange
// against the provider and PERSISTS the refreshed credential before returning
// it, so concurrent callers observe the same renewed row. On failure it
// returns the error and the caller fails open with the stored credential.
type CredentialRefresher interface {
	RefreshCredential(ctx context.Context, cred Credential) (Credential, error)
}

// Validate reports whether the structurally required dependencies are present.
// Secrets is intentionally NOT required here: it is only needed for a
// credential that has a secret, which the deps bundle cannot know. The
// composition root calls Validate once at wiring time; BuildExecutor calls it
// for families whose auth mode needs Secrets.
//
// It returns a provider.invalid DomainError (never a bare error) so a wiring
// mistake surfaces through the same i18n envelope as every other failure.
func (d ExecutorDeps) Validate() error {
	switch {
	case d.Clock == nil:
		return missingDep("clock")
	case d.IDs == nil:
		return missingDep("ids")
	case d.Redactor == nil:
		return missingDep("redactor")
	case d.Egress == nil:
		return missingDep("egress")
	default:
		return nil
	}
}

func missingDep(name string) error {
	return domain.New(domain.CodeProviderInvalid,
		domain.WithHTTPStatus(http.StatusInternalServerError),
		domain.WithParams(map[string]string{"reason": "executor deps: missing " + name}),
	)
}
