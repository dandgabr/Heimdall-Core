package router

import (
	"context"
	"strconv"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// expanded is one Candidate plus the provenance the strategies need but the
// frozen Candidate does not carry (step index/tier, weight, allowed
// connections, capability fit). The Router orders []expanded and emits only the
// frozen Candidate (with a built Reason).
type expanded struct {
	candidate contracts.Candidate
	// step is the top-level step index this candidate came from. It is the
	// priority signal and the round-robin tier.
	step int
	// weight feeds weighted; >= 1.
	weight int
	// allowedConnections restricts the candidate to those credentials (empty =
	// any healthy credential).
	allowedConnections []domain.CredentialID
	// fallbackOnlyOnQuota is carried for the Dispatcher (ADR-0013 §2); the
	// Router does not act on it.
	fallbackOnlyOnQuota bool
	// compatible is the capability fit against the request (demote, never drop).
	compatible bool
}

// expand turns a combo's steps into candidates. It is pure over the catalog and
// the combo map. `depth` counts combo-ref hops; `chain` detects cycles at
// runtime (the save-time validator should already have refused one, but the
// Router never trusts persisted data blindly — ADR-0009 §3).
func (r *Resolver) expand(ctx context.Context, combo combos.Combo, req *contracts.Request, byID map[domain.ComboID]combos.Combo, depth int, chain map[domain.ComboID]bool) ([]expanded, error) {
	if depth > maxDepth {
		return nil, depthExceeded(combo.Name)
	}
	if chain[combo.ID] {
		return nil, cyclicCombo(combo.Name)
	}
	chain[combo.ID] = true
	defer delete(chain, combo.ID)

	var out []expanded
	for i, step := range combo.Steps {
		switch step.Kind {
		case combos.StepModel:
			for _, provider := range r.catalog.Providers() {
				caps, ok := r.catalog.Capabilities(provider, domain.ModelID(step.Ref))
				if !ok {
					continue // this provider does not declare the model
				}
				mods, _ := r.catalog.Modalities(provider, domain.ModelID(step.Ref))
				out = append(out, r.mkExpanded(req, i, step, provider, domain.ModelID(step.Ref), caps, mods))
			}
			// A model step that no provider declares yields no candidate for
			// this step; the plan may still have others.

		case combos.StepProviderWildcard:
			provider := domain.ProviderID(step.Ref)
			if !hasProvider(r.catalog.Providers(), provider) {
				return nil, unknownProvider(combo.Name, step.Ref)
			}
			for _, model := range r.catalog.Models(provider) {
				caps, _ := r.catalog.Capabilities(provider, model)
				mods, _ := r.catalog.Modalities(provider, model)
				out = append(out, r.mkExpanded(req, i, step, provider, model, caps, mods))
			}

		case combos.StepComboRef:
			ref, ok := byID[domain.ComboID(step.Ref)]
			if !ok {
				return nil, invalidCombo(combo.Name, "reference to unknown combo "+step.Ref)
			}
			nested, err := r.expand(ctx, ref, req, byID, depth+1, chain)
			if err != nil {
				return nil, err
			}
			// Nested candidates inherit the top-level step index (the tier) but
			// keep their own weight, so a combo-ref step is one tier.
			for j := range nested {
				nested[j].step = i
				nested[j].weight = step.WeightOrOne()
				out = append(out, nested[j])
			}

		default:
			return nil, invalidCombo(combo.Name, "unknown step kind "+string(step.Kind))
		}
	}
	return out, nil
}

// mkExpanded builds one expanded candidate with its capability fit against req.
func (r *Resolver) mkExpanded(req *contracts.Request, stepIndex int, step combos.Step, provider domain.ProviderID, model domain.ModelID, caps contracts.Capabilities, mods contracts.ModalitySet) expanded {
	fit := combos.ComputeFit(combos.CandidateSpec{
		Candidate:    contracts.Candidate{Provider: provider, Model: model},
		Capabilities: caps,
		Modalities:   mods,
	}, req)
	return expanded{
		candidate:           contracts.Candidate{Provider: provider, Model: model},
		step:                stepIndex,
		weight:              step.WeightOrOne(),
		allowedConnections:  append([]domain.CredentialID(nil), step.AllowedConnections...),
		fallbackOnlyOnQuota: step.FallbackOnlyOnQuota,
		compatible:          fit.Compatible,
	}
}

// hasProvider reports whether provider is in the deterministic provider list.
func hasProvider(providers []domain.ProviderID, provider domain.ProviderID) bool {
	for _, p := range providers {
		if p == provider {
			return true
		}
	}
	return false
}

// stableKey is the deterministic tie-break (Provider, Model, Credential) the
// ADR-0009 §4 requires.
func stableKey(c contracts.Candidate) string {
	return string(c.Provider) + "\x00" + string(c.Model) + "\x00" + string(c.Credential)
}

// lessStable orders two candidates by the stable key.
func lessStable(a, b contracts.Candidate) bool { return stableKey(a) < stableKey(b) }

// buildReason renders the observability string for a candidate: why it is here
// and, when demoted, what it lacks. It is data, never an instruction.
func buildReason(strategy contracts.StrategyKind, e expanded, extra string) string {
	reason := "strategy=" + string(strategy) + " step=" + strconv.Itoa(e.step)
	if e.weight != 1 {
		reason += " weight=" + strconv.Itoa(e.weight)
	}
	if !e.compatible {
		reason += " capability_mismatch"
	}
	if extra != "" {
		reason += " " + extra
	}
	return reason
}
