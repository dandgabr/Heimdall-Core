package combos

import (
	"sort"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file holds the capability-aware ordering (ADR-0013 §3.7). It is PURE: a
// function over candidates and a request's required modality/capabilities. It
// REORDERS, it never DROPS: an incompatible candidate is demoted to the end (and
// flagged), not removed, because a fallback may still serve a partial request and
// the Router must be able to try it.

// CandidateSpec is a candidate plus the capabilities/modalities its model
// declares, as the provider registry reports them. It is the input to Fit.
type CandidateSpec struct {
	Candidate    contracts.Candidate
	Capabilities contracts.Capabilities
	Modalities   contracts.ModalitySet
}

// Fit is the result of capability-aware ordering for one candidate.
type Fit struct {
	// Compatible is true when the candidate satisfies every required modality
	// and capability of the request.
	Compatible bool
	// MissingCaps and MissingModalities name exactly what is absent, so the
	// demotion is explainable (Reason).
	MissingCaps       contracts.Capabilities
	MissingModalities contracts.ModalitySet
}

// ComputeFit reports how a candidate's declared capability/modality set matches
// a request's requirements.
func ComputeFit(spec CandidateSpec, req *contracts.Request) Fit {
	if req == nil {
		return Fit{Compatible: true}
	}
	fit := Fit{}
	if !spec.Capabilities.Has(req.Capabilities) {
		fit.MissingCaps = req.Capabilities &^ spec.Capabilities
	}
	for m := contracts.Modality(0); int(m) <= int(contracts.ModalityEmbedding); m++ {
		if req.Modalities.Has(m) && !spec.Modalities.Has(m) {
			fit.MissingModalities |= 1 << m
		}
	}
	fit.Compatible = fit.MissingCaps == 0 && fit.MissingModalities == 0
	return fit
}

// OrderByCapability reorders specs so that fully-compatible candidates come
// first, in their original relative order (a stable sort), and incompatible ones
// follow, also in original order. No candidate is dropped.
//
// Ties are broken by the candidate's stable key (Provider, Model, Credential)
// lexicographic, so the result is deterministic regardless of the input order
// when two candidates are otherwise equal.
func OrderByCapability(specs []CandidateSpec, req *contracts.Request) []CandidateSpec {
	out := make([]CandidateSpec, len(specs))
	copy(out, specs)

	type scored struct {
		spec CandidateSpec
		fit  Fit
	}
	scoredList := make([]scored, len(out))
	for i, s := range out {
		scoredList[i] = scored{spec: s, fit: ComputeFit(s, req)}
	}

	sort.SliceStable(scoredList, func(i, j int) bool {
		fi, fj := scoredList[i].fit, scoredList[j].fit
		if fi.Compatible != fj.Compatible {
			return fi.Compatible
		}
		return lessCandidate(scoredList[i].spec.Candidate, scoredList[j].spec.Candidate)
	})

	for i, s := range scoredList {
		out[i] = s.spec
	}
	return out
}

// lessCandidate is the stable tie-break: Provider, then Model, then Credential,
// all lexicographic. It is the same deterministic order ADR-0009 §4 requires.
func lessCandidate(a, b contracts.Candidate) bool {
	if a.Provider != b.Provider {
		return a.Provider < b.Provider
	}
	if a.Model != b.Model {
		return a.Model < b.Model
	}
	return a.Credential < b.Credential
}
