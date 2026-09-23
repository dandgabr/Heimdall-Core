package combos

import (
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestComputeFit covers each mismatch axis independently and the all-match case.
func TestComputeFit(t *testing.T) {
	spec := CandidateSpec{
		Candidate:    contracts.Candidate{Provider: "p", Model: "m"},
		Capabilities: contracts.Capabilities(0).Add(contracts.CapStream, contracts.CapTools),
		Modalities:   contracts.ModalitySet(0).Add(contracts.ModalityText, contracts.ModalityImage),
	}

	// All required present.
	req := &contracts.Request{
		Capabilities: contracts.CapStream,
		Modalities:   contracts.ModalitySet(0).Add(contracts.ModalityText),
	}
	fit := ComputeFit(spec, req)
	if !fit.Compatible || fit.MissingCaps != 0 || fit.MissingModalities != 0 {
		t.Fatalf("all-match fit = %+v", fit)
	}

	// Missing a capability.
	req.Capabilities = contracts.CapStream | contracts.CapVision
	fit = ComputeFit(spec, req)
	if fit.Compatible {
		t.Fatal("missing capability reported compatible")
	}
	if !fit.MissingCaps.Has(contracts.CapVision) {
		t.Fatalf("MissingCaps = %s", fit.MissingCaps)
	}

	// Missing a modality.
	req = &contracts.Request{Modalities: contracts.ModalitySet(0).Add(contracts.ModalityAudio)}
	fit = ComputeFit(spec, req)
	if fit.Compatible || !fit.MissingModalities.Has(contracts.ModalityAudio) {
		t.Fatalf("missing modality fit = %+v", fit)
	}

	// Nil request is compatible by definition (nothing required).
	if got := ComputeFit(spec, nil); !got.Compatible {
		t.Fatal("nil request reported incompatible")
	}
}

// TestOrderByCapabilityDemotesNotDrops is the ADR-0013 §3.7 guarantee: an
// incompatible candidate moves to the end but is NOT removed.
func TestOrderByCapabilityDemotesNotDrops(t *testing.T) {
	req := &contracts.Request{
		Capabilities: contracts.CapStream,
		Modalities:   contracts.ModalitySet(0).Add(contracts.ModalityImage),
	}
	// a: no image -> incompatible. b: image + stream -> compatible. c: no image
	// -> incompatible. Input order is a, b, c.
	specs := []CandidateSpec{
		{Candidate: contracts.Candidate{Provider: "p", Model: "a"}, Modalities: contracts.ModalitySet(0).Add(contracts.ModalityText)},
		{
			Candidate:    contracts.Candidate{Provider: "p", Model: "b"},
			Capabilities: contracts.Capabilities(0).Add(contracts.CapStream),
			Modalities:   contracts.ModalitySet(0).Add(contracts.ModalityImage),
		},
		{Candidate: contracts.Candidate{Provider: "p", Model: "c"}, Modalities: contracts.ModalitySet(0).Add(contracts.ModalityText)},
	}
	got := OrderByCapability(specs, req)
	if len(got) != 3 {
		t.Fatalf("OrderByCapability dropped a candidate: %d", len(got))
	}
	if got[0].Candidate.Model != "b" {
		t.Fatalf("compatible candidate not first: %v", modelsOf(got))
	}
	// The two incompatible ones keep their relative order (stable sort).
	if got[1].Candidate.Model != "a" || got[2].Candidate.Model != "c" {
		t.Fatalf("demoted order not stable: %v", modelsOf(got))
	}
}

// TestOrderByCapabilityDeterministicTieBreak pins that equal candidates are
// ordered by the stable key, not by input order.
func TestOrderByCapabilityDeterministicTieBreak(t *testing.T) {
	req := &contracts.Request{}
	specs := []CandidateSpec{
		{Candidate: contracts.Candidate{Provider: "z", Model: "m"}},
		{Candidate: contracts.Candidate{Provider: "a", Model: "m"}},
		{Candidate: contracts.Candidate{Provider: "a", Model: "a"}},
	}
	for i := 0; i < 20; i++ {
		got := OrderByCapability(specs, req)
		want := []domain.ModelID{"a", "m", "m"}
		for j := range want {
			if got[j].Candidate.Model != want[j] {
				t.Fatalf("iteration %d: order = %v", i, modelsOf(got))
			}
		}
	}
}

// TestOrderByCapabilityNilRequest keeps every candidate and preserves the
// deterministic tie-break when nothing is required.
func TestOrderByCapabilityNilRequest(t *testing.T) {
	specs := []CandidateSpec{
		{Candidate: contracts.Candidate{Provider: "b", Model: "m"}},
		{Candidate: contracts.Candidate{Provider: "a", Model: "m"}},
	}
	got := OrderByCapability(specs, nil)
	if len(got) != 2 || got[0].Candidate.Provider != "a" {
		t.Fatalf("nil-request order = %v", got)
	}
}

// TestOrderByCapabilityBreaksCredentialTie covers the third tie-break key.
func TestOrderByCapabilityBreaksCredentialTie(t *testing.T) {
	specs := []CandidateSpec{
		{Candidate: contracts.Candidate{Provider: "p", Model: "m", Credential: "c2"}},
		{Candidate: contracts.Candidate{Provider: "p", Model: "m", Credential: "c1"}},
	}
	got := OrderByCapability(specs, nil)
	if got[0].Candidate.Credential != "c1" || got[1].Candidate.Credential != "c2" {
		t.Fatalf("credential tie-break failed: %v", got)
	}
}

func modelsOf(specs []CandidateSpec) []domain.ModelID {
	out := make([]domain.ModelID, len(specs))
	for i, s := range specs {
		out[i] = s.Candidate.Model
	}
	return out
}
