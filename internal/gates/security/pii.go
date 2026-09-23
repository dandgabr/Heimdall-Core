package security

import (
	"context"
	"net/http"
	"regexp"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// PIIMasker detects and contains personal data in the request body: e-mail,
// phone (BR-oriented), CPF (canonical formatted form) and credit-card numbers
// (validated by the Luhn checksum, so ordinary digit runs are not masked).
//
// The policy is the operator's and only the operator's — Mask rewrites each
// match into a typed placeholder ([PII:email] and peers), Block refuses the
// request listing only the detected TYPES, Off means the gate is not
// constructed at all (NewPIIMasker returns nil). The policy never derives from
// the payload: no text can turn Mask into Continue or Block into Mask.
//
// Bias: over-masking. The patterns prefer a false positive (a long digit run
// read as a phone) over a missed PII, mirroring the central redactor's stance
// that a security control should over-redact rather than miss. Only the
// canonical formatted forms of CPF are contained — a bare 11-digit run is
// ambiguous (CPF vs mobile) and would mask half the digits in any log-like
// text.
//
// FailurePolicy is FailClosed — and must be: the registry refuses a FailOpen
// gate that writes the pii field (ADR-0014 §3.4), so the combination cannot
// even boot.
type PIIMasker struct {
	policy PiiPolicy
}

// Compile-time assertions.
var (
	_ contracts.Gate         = (*PIIMasker)(nil)
	_ contracts.GateDeclarer = (*PIIMasker)(nil)
	_ contracts.BodyConsumer = (*PIIMasker)(nil)
)

// PiiPolicy is the configured behaviour on detection. PiiMask is the zero
// value so an operator who forgets to configure the gate still gets the safe
// default (mask, not off).
type PiiPolicy uint8

const (
	// PiiMask replaces each match with a typed placeholder.
	PiiMask PiiPolicy = iota
	// PiiBlock refuses the request when any pattern matches.
	PiiBlock
	// PiiOff disables the gate: it is not constructed.
	PiiOff
)

// PiiConfig configures the gate.
type PiiConfig struct {
	Policy PiiPolicy
}

// NewPIIMasker builds the gate, or nil when the policy is Off — a disabled
// security gate is never constructed (ADR-0014 §4).
func NewPIIMasker(cfg PiiConfig) *PIIMasker {
	if cfg.Policy == PiiOff {
		return nil
	}
	return &PIIMasker{policy: cfg.Policy}
}

// ID implements contracts.Gate.
func (g *PIIMasker) ID() string { return IDPIIMasker }

// Stages implements contracts.Gate: final verification runs pre-request only.
func (g *PIIMasker) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// RequiredCaps implements contracts.Gate.
func (g *PIIMasker) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate.
func (g *PIIMasker) FailurePolicy() contracts.FailurePolicy { return contracts.FailClosed }

// NeedsBody implements contracts.BodyConsumer.
func (g *PIIMasker) NeedsBody() bool { return true }

// Declare implements contracts.GateDeclarer. It READS prompt_text — so the
// graph places it after the credential masker and after the token engine, the
// ADR-SEC-04 phase-5 position — and WRITES pii.
func (g *PIIMasker) Declare() contracts.Declared {
	return contracts.Declared{
		Stages: g.Stages(),
		Reads:  []contracts.DataField{contracts.FieldPromptText},
		Writes: []contracts.DataField{contracts.FieldPII},
	}
}

// piiRule is one detection/masking rule. The rules run in slice order on every
// string; the order is deterministic and places the most specific (and
// checksum-verified) pattern first.
type piiRule struct {
	kind string
	re   *regexp.Regexp
	// luhn, when true, accepts a match only when its digits pass the Luhn
	// checksum (credit cards). Other rules accept every match.
	luhn bool
}

// placeholders are typed, fixed strings: they leak neither the value nor its
// length, and they are stable so downstream prompts stay diffable.
const (
	phEmail = "[PII:email]"
	phCard  = "[PII:card]"
	phCPF   = "[PII:cpf]"
	phPhone = "[PII:phone]"
)

// piiRules are compiled once.
var piiRules = []piiRule{
	{kind: "email", re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+`)},
	{kind: "card", re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), luhn: true},
	{kind: "cpf", re: regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)},
	{kind: "phone", re: regexp.MustCompile(`(\+55[\s-]?)?\(?\d{2}\)?[\s-]?\d{4,5}-?\d{4}\b`)},
}

// PreRequest implements contracts.Gate. One pass over the body's strings: the
// pass rewrites accepted matches (no-op for a clean body, which comes back
// byte-identical). In Block policy the rewritten output is DISCARDED — only
// the detected kinds drive the refusal, so the payload never propagates.
func (g *PIIMasker) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if len(in.Body) == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	var kinds []string
	seen := map[string]bool{}
	record := func(kind string) {
		if !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
	}
	fn := func(s string) string {
		for _, r := range piiRules {
			s = r.re.ReplaceAllStringFunc(s, func(match string) string {
				if r.luhn && !luhnValid(digitsOf(match)) {
					return match
				}
				record(r.kind)
				return placeholderFor(r.kind)
			})
		}
		return s
	}

	out, _, err := mapJSONStrings(in.Body, fn)
	if err != nil {
		return contracts.Decision{}, err
	}
	if len(kinds) == 0 {
		// No accepted match: out is byte-identical to in.Body (mapJSONStrings
		// only rewrites tokens fn changed) and there is nothing to report.
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	types := joinKinds(kinds)
	setMeta(in.Meta, IDPIIMasker+".types", types)
	if g.policy == PiiBlock {
		return blockWith(domain.CodeSecurityPIIBlocked,
			map[string]string{"types": types},
			http.StatusBadRequest), nil
	}
	// Mask policy: kinds is only filled by accepted rewrites, so hits > 0 and
	// out carries the placeholders.
	return contracts.Decision{Kind: contracts.DecisionModify, Body: out}, nil
}

// OnResponseChunk implements contracts.Gate: no post-commit action.
func (g *PIIMasker) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate: nothing to observe.
func (g *PIIMasker) PostResponse(context.Context, contracts.GateInput) error { return nil }

// Close implements contracts.Gate.
func (g *PIIMasker) Close() error { return nil }

// placeholderFor maps a rule kind to its fixed placeholder.
func placeholderFor(kind string) string {
	switch kind {
	case "email":
		return phEmail
	case "card":
		return phCard
	case "cpf":
		return phCPF
	default:
		return phPhone
	}
}

// joinKinds renders the detected kinds deterministically (rule order, deduped
// on insert).
func joinKinds(kinds []string) string {
	out := ""
	for i, k := range kinds {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return out
}

// digitsOf keeps only the ASCII digits of s (the Luhn input of a formatted
// card match).
func digitsOf(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return string(out)
}

// luhnValid reports whether the digit string passes the Luhn checksum.
func luhnValid(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
