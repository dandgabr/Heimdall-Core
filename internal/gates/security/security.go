// Package security holds the F4 security gates (ADR-SEC-03 / ADR-SEC-04): the
// credential masker, the PII masker, the prompt-injection guard, the SSRF guard
// and the per-client-key rate limiter. Every gate implements the frozen
// contracts.Gate, declares its Stages/RequiredCaps/FailurePolicy, and
// participates in the dependency graph of ADR-0014 through GateDeclarer.
//
// # Order (ADR-SEC-04 §1, derived — never hardcoded)
//
// The chain order is derived by the gate registry from each gate's reads/writes:
//
//	credential-masker  writes prompt_text (containment, phase 1)
//	rate-limit         reads/writes nothing (containment, phase 1)
//	ssrf-guard         reads/writes nothing (containment, phase 1)
//	token (wave 2)     writes prompt_text (phase 4)
//	injection-guard    reads prompt_text, writes injection_flag (phase 5)
//	pii-masker         reads prompt_text, writes pii (phase 5)
//
// The containment gates have no data edges, so Kahn's tie-break orders them
// lexicographically by ID (c < r < s) and they run before every gate that reads
// prompt_text. The verification gates read prompt_text, so the graph places
// them after the credential masker AND after the token engine — exactly the
// ADR-SEC-04 phases: containment → (cache → memory → token, other waves) → PII +
// injection. Every declaration is independent: a gate switched off by its
// feature flag is not constructed, and the derived order of the rest stays
// valid (ADR-0014 §4). No gate uses After, so no combination of disabled gates
// can fail the boot with a dangling dependency.
//
// # Injection immunity (ADR-SEC-03 §3)
//
// A gate's decision is a PURE function of (static policy, deterministic
// pattern match). No gate parses natural-language instructions out of the body
// to decide what to do, and no gate carries text-derived state, so an
// adversarial payload can never rewrite a Block into a Continue or vice versa.
//
// # Minimum content (ADR-SEC-03 §2)
//
// A gate that needs the body implements contracts.BodyConsumer; the rate
// limiter does not and never sees a payload. Header VALUES are never read
// (GateInput.Headers carries names only). No gate logs or persists body
// content: observability is limited to Meta counts, policy rule NAMES and the
// denylist HOST of a refused URL — never the matched text, and any param placed
// on a Decision or a synthetic envelope is a non-content label (a type name, a
// host, a retry hint).
//
// # Failure policies (ADR-SEC-04 §3)
//
// FailClosed: credential-masker, ssrf-guard, pii-masker and the blocking
// injection guard — an internal failure aborts the request instead of letting
// unaudited content through. The registry itself refuses a FailOpen gate that
// writes pii or injection_flag (ADR-0014 §3.4). FailOpen: rate-limit
// (throttling is availability machinery, same posture as quota) and the
// flag-only injection guard (detection is recorded, availability wins).
package security

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// The stable gate identifiers. They are also the per-gate feature-flag names
// (features.gates.<id> in the config; ADR-0014 §4) and the Meta namespace of
// each gate ("<id>.<key>").
const (
	// IDCredentialMasker strips upstream credentials from the body.
	IDCredentialMasker = "credential-masker"
	// IDPIIMasker masks or blocks personal data in the body.
	IDPIIMasker = "pii-masker"
	// IDInjectionGuard detects prompt-injection signatures in the body.
	IDInjectionGuard = "injection-guard"
	// IDSSRFGuard denies client-supplied URLs to protected network targets.
	IDSSRFGuard = "ssrf-guard"
	// IDRateLimit throttles requests per client key.
	IDRateLimit = "rate-limit"
)

// MetaKeyClient is the reserved GateInput.Meta key the HTTP boundary may set to
// identify the downstream client (a resolved, NON-SECRET key reference — never
// a raw API key). The rate limiter prefers it over its fallbacks. Keys land in
// no log and no error: they only index an in-memory bucket.
const MetaKeyClient = "client.key"

// envelope mirrors the API error wire shape (internal/api/middleware): the i18n
// code plus named params, never a localised sentence and never content.
type envelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params,omitempty"`
}

// mapJSONStrings applies fn to every JSON string token of body — object keys
// included, so a secret pasted into a key position is covered too — and returns
// the rewritten body, how many tokens fn CHANGED, and an error when body is not
// valid JSON.
//
// Determinism and byte-fidelity: the scanner is a pure byte walk (no maps, no
// re-serialisation of untouched regions), so a body with zero changes is
// returned byte-identical — a masker that finds nothing must not perturb the
// request, which also keeps the token gate's frozen prefix intact. Escapes
// (\", \\, \uXXXX) are handled by decoding the token before fn runs and
// re-encoding only a changed value.
//
// The upfront json.Valid is the load-bearing check: in valid JSON a `"` byte
// can only delimit a string, so the walk below always sees well-formed tokens,
// and both decodes are therefore infallible — json.Unmarshal of a valid string
// token and json.Marshal of a plain string cannot fail. The invariant is
// pinned by TestMapJSONStringsInfallibleDecode, not by unreachable guards.
func mapJSONStrings(body []byte, fn func(string) string) (out []byte, hits int, err error) {
	if len(body) == 0 {
		return body, 0, nil
	}
	if !json.Valid(body) {
		return nil, 0, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithParams(map[string]string{"reason": "body is not valid JSON"}),
		)
	}
	out = make([]byte, 0, len(body))
	for i := 0; i < len(body); {
		c := body[i]
		if c != '"' {
			out = append(out, c)
			i++
			continue
		}
		// body is valid JSON, so the token starting at i always closes before
		// the end; the walk skips escaped bytes so \" never ends it early.
		j := i + 1
		for j < len(body) {
			if body[j] == '\\' {
				j += 2
				continue
			}
			if body[j] == '"' {
				j++
				break
			}
			j++
		}
		var decoded string
		_ = json.Unmarshal(body[i:j], &decoded) // infallible: token is valid JSON
		if mapped := fn(decoded); mapped == decoded {
			out = append(out, body[i:j]...)
		} else {
			enc, _ := json.Marshal(mapped) // infallible for a plain string
			out = append(out, enc...)
			hits++
		}
		i = j
	}
	if hits == 0 {
		return body, 0, nil
	}
	return out, hits, nil
}

// blockWith builds a security Block carrying the standard error envelope as a
// synthetic response. A security denial is a RESPONSE with its intent status
// (ADR-SEC-04 §2), not an HTTP error path: the pipeline delivers Synthetic to
// the client and never calls upstream.
func blockWith(code string, params map[string]string, status int) contracts.Decision {
	d := contracts.Decision{Kind: contracts.DecisionBlock, Code: code, Params: params}
	d.Synthetic = &contracts.SyntheticResponse{
		Status:  status,
		Headers: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:    envelopeJSON(code, params),
	}
	return d
}

// envelopeJSON renders the {error:{code,params}} envelope byte-identically
// for the same input (json.Marshal sorts map keys). Marshal of this struct
// cannot fail (strings and a string map only), so there is no error path.
func envelopeJSON(code string, params map[string]string) []byte {
	b, _ := json.Marshal(envelope{Error: errorBody{Code: code, Params: params}})
	return b
}

// setMeta records a namespaced, non-content value in the request scratch map.
// Meta may be nil when a caller drives the gate directly; the gate then simply
// has nowhere to record and must not fail.
func setMeta(meta map[string]string, key, value string) {
	if meta != nil {
		meta[key] = value
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
