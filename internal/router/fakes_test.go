package router

import (
	"context"
	"math/rand/v2"
	"sort"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeComboLoader is an in-memory ComboLoader.
type fakeComboLoader struct {
	combos map[domain.ComboID]combos.Combo
	err    error
}

func (f *fakeComboLoader) Get(_ context.Context, id domain.ComboID) (combos.Combo, error) {
	if f.err != nil {
		return combos.Combo{}, f.err
	}
	c, ok := f.combos[id]
	if !ok {
		return combos.Combo{}, combos.ErrNotFound
	}
	return c, nil
}

func (f *fakeComboLoader) List(_ context.Context) ([]combos.Combo, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]combos.Combo, 0, len(f.combos))
	for _, c := range f.combos {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// fakeCatalog is a deterministic ModelCatalog.
type fakeCatalog struct {
	providers []domain.ProviderID
	models    map[domain.ProviderID][]domain.ModelID
	caps      map[string]contracts.Capabilities
	mods      map[string]contracts.ModalitySet
}

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{
		models: map[domain.ProviderID][]domain.ModelID{},
		caps:   map[string]contracts.Capabilities{},
		mods:   map[string]contracts.ModalitySet{},
	}
}

func (f *fakeCatalog) add(provider domain.ProviderID, model domain.ModelID, caps contracts.Capabilities, mods contracts.ModalitySet) *fakeCatalog {
	if _, ok := f.models[provider]; !ok {
		f.providers = append(f.providers, provider)
	}
	f.models[provider] = append(f.models[provider], model)
	f.caps[string(provider)+"/"+string(model)] = caps
	f.mods[string(provider)+"/"+string(model)] = mods
	return f
}

func (f *fakeCatalog) Providers() []domain.ProviderID {
	out := append([]domain.ProviderID(nil), f.providers...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (f *fakeCatalog) Models(p domain.ProviderID) []domain.ModelID {
	out := append([]domain.ModelID(nil), f.models[p]...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (f *fakeCatalog) Capabilities(p domain.ProviderID, m domain.ModelID) (contracts.Capabilities, bool) {
	c, ok := f.caps[string(p)+"/"+string(m)]
	return c, ok
}

func (f *fakeCatalog) Modalities(p domain.ProviderID, m domain.ModelID) (contracts.ModalitySet, bool) {
	mods, ok := f.mods[string(p)+"/"+string(m)]
	return mods, ok
}

// fixedRNG always returns the same Intn value (a deterministic source).
type fixedRNG struct{ v int }

func (r fixedRNG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return r.v % n
}
func (r fixedRNG) Float64() float64 { return 0.5 }

// fakeSignals is a deterministic Signals source keyed by "provider/model".
type fakeSignals struct {
	quota    map[string]float64
	health   map[string]float64
	latency  map[string]float64
	inflight map[string]int
}

func newFakeSignals() *fakeSignals {
	return &fakeSignals{
		quota: map[string]float64{}, health: map[string]float64{},
		latency: map[string]float64{}, inflight: map[string]int{},
	}
}

func key(c contracts.Candidate) string { return string(c.Provider) + "/" + string(c.Model) }

func (s *fakeSignals) QuotaRemaining(_ context.Context, c contracts.Candidate) float64 {
	if v, ok := s.quota[key(c)]; ok {
		return v
	}
	return 1.0
}
func (s *fakeSignals) BreakerHealth(_ context.Context, c contracts.Candidate) float64 {
	if v, ok := s.health[key(c)]; ok {
		return v
	}
	return 1.0
}
func (s *fakeSignals) Latency(_ context.Context, c contracts.Candidate) float64 {
	return s.latency[key(c)]
}
func (s *fakeSignals) InFlight(_ context.Context, c contracts.Candidate) int {
	return s.inflight[key(c)]
}

// fakeCost is a deterministic CostCatalog keyed by "provider/model".
type fakeCost struct{ m map[string]int64 }

func (c fakeCost) CostMicros(p domain.ProviderID, m domain.ModelID) (int64, bool) {
	v, ok := c.m[string(p)+"/"+string(m)]
	return v, ok
}

// fakeCreds is a deterministic CredentialSource.
type fakeCreds struct {
	m map[domain.ProviderID][]domain.CredentialID
}

func (c fakeCreds) Credentials(p domain.ProviderID) []domain.CredentialID {
	return c.m[p]
}

// fakeJudge returns a configurable judge plan.
type fakeJudge struct {
	plan contracts.RoutePlan
	err  error
}

func (j fakeJudge) JudgePlan(_ context.Context, _ *contracts.Request, _ []string) (contracts.RoutePlan, error) {
	return j.plan, j.err
}

// fakePreflight filters candidates whose Reason-ish key is in the deny set.
type fakePreflight struct{ deny map[string]bool }

func (p fakePreflight) AllowCandidate(_ context.Context, c contracts.Candidate) (bool, string) {
	if p.deny[key(c)] {
		return false, "denied"
	}
	return true, ""
}

// combo builds a combo with steps.
func combo(name string, strategy contracts.StrategyKind, steps ...combos.Step) combos.Combo {
	return combos.NewCombo(name, strategy, steps)
}

func modelStep(model string, weight int) combos.Step {
	return combos.Step{Kind: combos.StepModel, Ref: model, Weight: weight}
}

func wildcardStep(provider string) combos.Step {
	return combos.Step{Kind: combos.StepProviderWildcard, Ref: provider}
}

func refStep(ref string) combos.Step {
	return combos.Step{Kind: combos.StepComboRef, Ref: ref}
}

// newPCGRand builds a deterministic *rand.Rand for the adapter test.
func newPCGRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, seed))
}
