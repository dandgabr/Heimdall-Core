package security

import (
	"context"
	"net/http"
	"regexp"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// InjectionGuard detects known prompt-injection signatures in the FINAL body —
// after the memory retriever has assembled context and the token engine has
// rewritten the prompt (it reads prompt_text, so the dependency graph places
// it there, ADR-SEC-04 §1.4/§1.5). Retrieved memory and user text pass through
// the same deterministic rule list: neither can smuggle a payload past it.
//
// # The decision is a function of (policy, match) — never of the text
//
// Two policies, chosen by configuration and changeable by nothing else:
//
//   - InjectBlock (FailClosed): a match refuses the request with a 400
//     synthetic. The verdict WRITES the injection_flag field, which is what
//     keeps it FailClosed — the registry refuses the opposite combination
//     (ADR-0014 §3.4).
//   - InjectFlag (FailOpen): a match is recorded in Meta (rule NAMES only)
//     and the request continues — availability first. The declaration writes
//     no field, so FailOpen is registry-coherent.
//
// The rule list is static and case-insensitive. The gate never parses
// instructions out of the content, never carries state across calls, and the
// synthetic refusal carries a rule NAME — a code constant — never the matched
// text, so nothing from the payload is echoed back.
type InjectionGuard struct {
	policy InjectPolicy
}

// Compile-time assertions.
var (
	_ contracts.Gate         = (*InjectionGuard)(nil)
	_ contracts.GateDeclarer = (*InjectionGuard)(nil)
	_ contracts.BodyConsumer = (*InjectionGuard)(nil)
)

// InjectPolicy is the configured behaviour on a pattern match. InjectBlock is
// the zero value: the safe default is refusal.
type InjectPolicy uint8

const (
	// InjectBlock refuses the request on a match (FailClosed).
	InjectBlock InjectPolicy = iota
	// InjectFlag records the match and continues (FailOpen).
	InjectFlag
)

// InjectConfig configures the gate.
type InjectConfig struct {
	Disabled bool
	Policy   InjectPolicy
}

// NewInjectionGuard builds the gate, or nil when disabled.
func NewInjectionGuard(cfg InjectConfig) *InjectionGuard {
	if cfg.Disabled {
		return nil
	}
	return &InjectionGuard{policy: cfg.Policy}
}

// ID implements contracts.Gate.
func (g *InjectionGuard) ID() string { return IDInjectionGuard }

// Stages implements contracts.Gate.
func (g *InjectionGuard) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// RequiredCaps implements contracts.Gate.
func (g *InjectionGuard) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate: block mode fails closed; flag mode
// fails open (and writes no security field, so the registry accepts it).
func (g *InjectionGuard) FailurePolicy() contracts.FailurePolicy {
	if g.policy == InjectFlag {
		return contracts.FailOpen
	}
	return contracts.FailClosed
}

// NeedsBody implements contracts.BodyConsumer.
func (g *InjectionGuard) NeedsBody() bool { return true }

// Declare implements contracts.GateDeclarer. It READS context AND prompt_text:
// the context edge orders it after the memory retriever (it must inspect the
// assembled context), the prompt_text edge after the token engine that rewrote
// the final body. Block mode WRITES injection_flag; flag mode writes nothing.
func (g *InjectionGuard) Declare() contracts.Declared {
	d := contracts.Declared{
		Stages: g.Stages(),
		Reads:  []contracts.DataField{contracts.FieldContext, contracts.FieldPromptText},
	}
	if g.policy == InjectBlock {
		d.Writes = []contracts.DataField{contracts.FieldInjectionFlag}
	}
	return d
}

// injectRule is one deterministic signature. Names are stable code constants:
// they may appear in Meta and diagnostics, never the matched text.
type injectRule struct {
	name string
	re   *regexp.Regexp
}

// injectionRules is the static signature list (EN + pt-BR). It is deliberately
// curated: a broad net ("you must obey me") would flag legitimate prompts and
// train operators to ignore the gate.
var injectionRules = []injectRule{
	{name: "ignore-instructions", re: regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|dire[cs]?[çc][õo]es)\b`)},
	{name: "ignore-regras", re: regexp.MustCompile(`(?i)\b(?:ignore|desconsidere|desconsiderar)\s+(?:as\s+|todas?\s+as\s+)?(?:regras|instru[çc][õo]es)\b`)},
	{name: "disregard-rules", re: regexp.MustCompile(`(?i)\bdisregard\s+(?:all\s+|your\s+|the\s+)?(?:previous|prior|above|earlier)?\s*(?:instructions?|rules?|guidelines)\b`)},
	{name: "reveal-system", re: regexp.MustCompile(`(?i)\b(?:reveal|print|repeat|show|output)\s+(?:me\s+)?(?:your\s+)?(?:full\s+|exact\s+|original\s+)?(?:system\s+)?(?:prompt|instructions?|rules)\b`)},
	{name: "role-hijack", re: regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:a|an|in|my)\b`)},
	{name: "dev-mode", re: regexp.MustCompile(`(?i)\b(?:enter|activate|enable)\s+(?:the\s+)?(?:developer|god|dan|unrestricted)\s+mode\b`)},
}

// PreRequest implements contracts.Gate. The scan never modifies the body; a
// match flips the outcome only through the configured policy.
func (g *InjectionGuard) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if len(in.Body) == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	var rules []string
	seen := map[string]bool{}
	_, _, err := mapJSONStrings(in.Body, func(s string) string {
		for _, r := range injectionRules {
			if r.re.MatchString(s) && !seen[r.name] {
				seen[r.name] = true
				rules = append(rules, r.name)
			}
		}
		return s
	})
	if err != nil {
		if g.policy == InjectFlag {
			// FailOpen: the error is surfaced for the pipeline to log while
			// the request continues with the input unmodified.
			return contracts.Decision{Kind: contracts.DecisionContinue}, err
		}
		return contracts.Decision{}, err
	}
	if len(rules) == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	if g.policy == InjectFlag {
		setMeta(in.Meta, IDInjectionGuard+".flagged", joinKinds(rules))
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	setMeta(in.Meta, IDInjectionGuard+".rule", rules[0])
	return blockWith(domain.CodeSecurityInjectionDetected, nil, http.StatusBadRequest), nil
}

// OnResponseChunk implements contracts.Gate: no post-commit action.
func (g *InjectionGuard) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate: nothing to observe.
func (g *InjectionGuard) PostResponse(context.Context, contracts.GateInput) error { return nil }

// Close implements contracts.Gate.
func (g *InjectionGuard) Close() error { return nil }
