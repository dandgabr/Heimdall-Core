package router

import (
	"context"
	"math"
	"sort"
	"strconv"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file holds the STRATEGIES that produce a single linear order (no
// fan-out): priority, fallback, round-robin, weighted, fill-first, cost, p2c and
// auto. fusion and pipeline (the two structural strategies) live in
// strategies_structural.go.
//
// Every strategy REORDERS, never DROPS: an incompatible candidate is demoted to
// the end (ADR-0013 §3.7). Every tie is broken by the stable (Provider, Model,
// Credential) key (ADR-0009 §4).

// priorityStrategy: ADR-0009 §2 defines `priority` as "priority declared on the
// step, higher first; tie by name". The combo step model has no explicit
// priority field, so the DECLARED ORDER is the priority: earlier step = higher
// priority. Ties (same step/tier) break on the stable key. `fallback` is the
// same order but never reorders by health — the two share this ordering and
// differ only in their declared intent (and MaxRounds), so the implementation is
// deliberately shared.
type priorityStrategy struct{}

// Kind implements Strategy.
func (priorityStrategy) Kind() contracts.StrategyKind { return contracts.StrategyPriority }

// Order implements Strategy.
func (priorityStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, _ Env) []contracts.Candidate {
	// Stable sort by (step asc, stable key). Earlier step = higher priority.
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].step != in[j].step {
			return in[i].step < in[j].step
		}
		return lessStable(in[i].candidate, in[j].candidate)
	})
	out := make([]contracts.Candidate, 0, len(in))
	for i := range in {
		c := in[i].candidate
		c.Score = float64(in[i].step)
		c.Reason = buildReason(contracts.StrategyPriority, in[i], "")
		out = append(out, c)
	}
	return out
}

// fallbackStrategy: the declared order of steps, never reordered by health.
// MaxRounds = number of steps (handled by the resolver).
type fallbackStrategy struct{}

// Kind implements Strategy.
func (fallbackStrategy) Kind() contracts.StrategyKind { return contracts.StrategyFallback }

// Order implements Strategy.
func (fallbackStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, _ Env) []contracts.Candidate {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].step != in[j].step {
			return in[i].step < in[j].step
		}
		return lessStable(in[i].candidate, in[j].candidate)
	})
	out := make([]contracts.Candidate, 0, len(in))
	for i := range in {
		c := in[i].candidate
		c.Reason = buildReason(contracts.StrategyFallback, in[i], "")
		out = append(out, c)
	}
	return out
}

// roundRobinStrategy: rotates between candidates of the SAME tier (step). The
// cursor is in-memory and per (combo, tier); a new process starts at index 0.
// Ties within the rotation are resolved by the stable key (ADR-0009 §2).
type roundRobinStrategy struct{}

// Kind implements Strategy.
func (roundRobinStrategy) Kind() contracts.StrategyKind { return contracts.StrategyRoundRobin }

// Order implements Strategy.
func (roundRobinStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, ec Env) []contracts.Candidate {
	// Group by tier (step), preserving the stable key inside each tier.
	tiers := map[int][]expanded{}
	var tierOrder []int
	for _, e := range in {
		if _, seen := tiers[e.step]; !seen {
			tierOrder = append(tierOrder, e.step)
		}
		tiers[e.step] = append(tiers[e.step], e)
	}
	sort.Ints(tierOrder)

	out := make([]contracts.Candidate, 0, len(in))
	for _, tier := range tierOrder {
		group := tiers[tier]
		sort.SliceStable(group, func(i, j int) bool { return lessStable(group[i].candidate, group[j].candidate) })
		// Rotate: pick the cursor position, then the rest in order.
		start := 0
		if ec.Cursor != nil {
			start = ec.Cursor.nextRR(rrKey(ec.Combo, tier), len(group))
		}
		for k := 0; k < len(group); k++ {
			e := group[(start+k)%len(group)]
			c := e.candidate
			c.Score = float64((start + k) % len(group))
			c.Reason = buildReason(contracts.StrategyRoundRobin, e, "cursor="+itoa(start))
			out = append(out, c)
		}
	}
	return out
}

// weightedStrategy: independent per-request weighted DRAW. It does not rotate:
// each request draws, proportional to weight. Requires an RNG; nil makes it
// non-deterministic by definition (documented).
type weightedStrategy struct{}

// Kind implements Strategy.
func (weightedStrategy) Kind() contracts.StrategyKind { return contracts.StrategyWeighted }

// Order implements Strategy. Weighted is a per-request draw over the WHOLE
// candidate set (ADR-0009 §2: "sorteio proporcional ao weight do passo, POR
// REQUEST"): every candidate is drawn without replacement, proportional to its
// step's weight, so a heavier step tends to be tried first. It is NOT a rotation
// (that is round-robin).
func (weightedStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, ec Env) []contracts.Candidate {
	group := append([]expanded(nil), in...)
	// Stable base order so a nil RNG (or a run of ties) is deterministic.
	sort.SliceStable(group, func(i, j int) bool { return lessStable(group[i].candidate, group[j].candidate) })
	order := weightedDraw(group, ec.RNG)
	out := make([]contracts.Candidate, 0, len(group))
	for rank, idx := range order {
		e := group[idx]
		c := e.candidate
		c.Score = float64(e.weight)
		c.Reason = buildReason(contracts.StrategyWeighted, e, "weight="+itoa(e.weight)+" draw="+itoa(rank))
		out = append(out, c)
	}
	return out
}

// weightedDraw returns the group indices in draw order. With an RNG it draws
// without replacement proportional to weight; with a nil RNG it falls back to
// the deterministic weight-descending order (all equally weighted draws are
// non-deterministic by definition).
func weightedDraw(group []expanded, rng RNG) []int {
	idx := make([]int, len(group))
	for i := range idx {
		idx[i] = i
	}
	if rng == nil {
		sort.SliceStable(idx, func(i, j int) bool {
			if group[idx[i]].weight != group[idx[j]].weight {
				return group[idx[i]].weight > group[idx[j]].weight
			}
			return false
		})
		return idx
	}
	// Weighted draw without replacement: pick each position by a cumulative
	// weight over the not-yet-picked candidates.
	remaining := append([]int(nil), idx...)
	var out []int
	for len(remaining) > 0 {
		total := 0
		for _, i := range remaining {
			total += group[i].weight
		}
		r := rng.Intn(total)
		acc := 0
		pick := 0
		for pos, i := range remaining {
			acc += group[i].weight
			if r < acc {
				pick = pos
				break
			}
		}
		out = append(out, remaining[pick])
		remaining = append(remaining[:pick], remaining[pick+1:]...)
	}
	return out
}

// fillFirstStrategy: exhausts the current CREDENTIAL of a provider/step before
// moving to the next. It consults the CredentialSource for the account list and
// the QuotaFilter-via-Signals to know when "exhausted". State is in-memory.
type fillFirstStrategy struct{}

// Kind implements Strategy.
func (fillFirstStrategy) Kind() contracts.StrategyKind { return contracts.StrategyFillFirst }

// Order implements Strategy.
func (fillFirstStrategy) Order(ctx context.Context, req *contracts.Request, in []expanded, ec Env) []contracts.Candidate {
	// Group by (step, provider), fill the current credential for each provider,
	// then emit candidates ordered by (step, provider, credential).
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].step != in[j].step {
			return in[i].step < in[j].step
		}
		if in[i].candidate.Provider != in[j].candidate.Provider {
			return in[i].candidate.Provider < in[j].candidate.Provider
		}
		return lessStable(in[i].candidate, in[j].candidate)
	})
	out := make([]contracts.Candidate, 0, len(in))
	for i := range in {
		e := in[i]
		c := e.candidate
		// Pick the current credential for the (step, provider) group.
		creds := e.allowedConnections
		if ec.Cred != nil && len(creds) == 0 {
			creds = ec.Cred.Credentials(e.candidate.Provider)
		}
		if len(creds) > 0 {
			start := 0
			if ec.Cursor != nil {
				start = ec.Cursor.nextFill(string(e.candidate.Provider)+"#"+itoa(e.step), len(creds))
			}
			c.Credential = creds[start]
		}
		c.Reason = buildReason(contracts.StrategyFillFirst, e, "credential="+string(c.Credential))
		out = append(out, c)
	}
	return out
}

// costStrategy: ascending estimated cost; a model with no known price goes to
// the end. Ties break on the stable key.
type costStrategy struct{}

// Kind implements Strategy.
func (costStrategy) Kind() contracts.StrategyKind { return contracts.StrategyCost }

// Order implements Strategy.
func (costStrategy) Order(_ context.Context, _ *contracts.Request, in []expanded, ec Env) []contracts.Candidate {
	type row struct {
		e     expanded
		cost  int64
		known bool
	}
	rows := make([]row, len(in))
	for i, e := range in {
		var cost int64
		known := false
		if ec.Cost != nil {
			cost, known = ec.Cost.CostMicros(e.candidate.Provider, e.candidate.Model)
		}
		rows[i] = row{e: e, cost: cost, known: known}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].known != rows[j].known {
			return rows[i].known // known price first; unknown last
		}
		if rows[i].known && rows[i].cost != rows[j].cost {
			return rows[i].cost < rows[j].cost
		}
		return lessStable(rows[i].e.candidate, rows[j].e.candidate)
	})
	out := make([]contracts.Candidate, 0, len(rows))
	for _, rw := range rows {
		c := rw.e.candidate
		if rw.known {
			c.Score = float64(rw.cost)
		} else {
			c.Score = math.Inf(1)
		}
		note := "cost_unknown"
		if rw.known {
			note = "cost_micros=" + itoa64(rw.cost)
		}
		c.Reason = buildReason(contracts.StrategyCost, rw.e, note)
		out = append(out, c)
	}
	return out
}

// p2cStrategy: power of two choices — draw two candidates and pick the lower
// pressure (quota ↑, latency ↓, in-flight ↓). Requires an RNG; nil falls back to
// the deterministic stable order.
type p2cStrategy struct{}

// Kind implements Strategy.
func (p2cStrategy) Kind() contracts.StrategyKind { return contracts.StrategyP2C }

// Order implements Strategy.
func (p2cStrategy) Order(ctx context.Context, _ *contracts.Request, in []expanded, ec Env) []contracts.Candidate {
	group := append([]expanded(nil), in...)
	sort.SliceStable(group, func(i, j int) bool { return lessStable(group[i].candidate, group[j].candidate) })

	remaining := make([]int, len(group))
	for i := range remaining {
		remaining[i] = i
	}
	out := make([]contracts.Candidate, 0, len(group))
	if ec.RNG == nil {
		// Deterministic fallback: stable order.
		for _, idx := range remaining {
			out = append(out, p2cCandidate(group[idx], ec, 0))
		}
		return out
	}
	rank := 0
	for len(remaining) > 0 {
		var pick int
		if len(remaining) == 1 {
			pick = 0
		} else {
			a := ec.RNG.Intn(len(remaining))
			b := ec.RNG.Intn(len(remaining) - 1)
			if b >= a {
				b++
			}
			pick = betterPressure(ctx, ec, group[remaining[a]], group[remaining[b]])
		}
		idx := remaining[pick]
		out = append(out, p2cCandidate(group[idx], ec, rank))
		rank++
		remaining = append(remaining[:pick], remaining[pick+1:]...)
	}
	return out
}

// betterPressure returns the position (0 or 1) of the lower-pressure candidate.
func betterPressure(ctx context.Context, ec Env, a, b expanded) int {
	if ec.Signals == nil {
		return 0
	}
	pa := pressure(ctx, ec.Signals, a.candidate)
	pb := pressure(ctx, ec.Signals, b.candidate)
	if pb < pa {
		return 1
	}
	return 0
}

// pressure is a scalar where LOWER is better: high quota and health reduce it;
// latency and in-flight raise it. It is the p2c criterion.
func pressure(ctx context.Context, s Signals, c contracts.Candidate) float64 {
	q := s.QuotaRemaining(ctx, c)
	h := s.BreakerHealth(ctx, c)
	lat := s.Latency(ctx, c)
	inflight := float64(s.InFlight(ctx, c))
	// Higher quota/health => lower pressure; higher latency/in-flight => higher.
	return (1.0-q)*2.0 + (1.0-h)*2.0 + lat + inflight
}

// p2cCandidate renders one chosen candidate with its score/reason.
func p2cCandidate(e expanded, ec Env, rank int) contracts.Candidate {
	c := e.candidate
	if ec.Signals != nil {
		c.Score = pressure(context.Background(), ec.Signals, e.candidate)
	}
	c.Reason = buildReason(contracts.StrategyP2C, e, "pick="+itoa(rank))
	return c
}

// autoStrategy: a weighted sum of normalized factors, weights summing to 1.0,
// deterministic and NOT learning (ADR-0009 §5).
type autoStrategy struct{}

// Kind implements Strategy.
func (autoStrategy) Kind() contracts.StrategyKind { return contracts.StrategyAuto }

// Order implements Strategy.
func (autoStrategy) Order(ctx context.Context, _ *contracts.Request, in []expanded, ec Env) []contracts.Candidate {
	group := append([]expanded(nil), in...)
	type scored struct {
		e     expanded
		score float64
		notes string
	}
	rows := make([]scored, len(group))
	for i, e := range group {
		s, notes := autoScore(ctx, ec, e.candidate)
		rows[i] = scored{e: e, score: s, notes: notes}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score // higher score first
		}
		return lessStable(rows[i].e.candidate, rows[j].e.candidate)
	})
	out := make([]contracts.Candidate, 0, len(rows))
	for _, rw := range rows {
		c := rw.e.candidate
		c.Score = rw.score
		c.Reason = buildReason(contracts.StrategyAuto, rw.e, rw.notes)
		out = append(out, c)
	}
	return out
}

// autoWeights are the default factor weights; they sum to 1.0 (ADR-0009 §5).
var autoWeights = struct {
	Quota, Health, Cost, Latency, Tier, CapFit float64
}{0.30, 0.25, 0.15, 0.15, 0.05, 0.10}

// autoScore computes the weighted score in [0,1] plus the factor notes. Neutral
// defaults apply when there is no Signals, so the score is still deterministic.
func autoScore(ctx context.Context, ec Env, c contracts.Candidate) (float64, string) {
	quota, health, latency := 1.0, 1.0, 0.0
	if ec.Signals != nil {
		quota = ec.Signals.QuotaRemaining(ctx, c)
		health = ec.Signals.BreakerHealth(ctx, c)
		latency = ec.Signals.Latency(ctx, c)
	}
	cost := 0.0
	if ec.Cost != nil {
		if micros, ok := ec.Cost.CostMicros(c.Provider, c.Model); ok && micros > 0 {
			// Normalize by a soft ceiling so a "cheap" model approaches 1.0.
			cost = 1.0 - clamp01(float64(micros)/autoCostCeilingMicros)
		}
	}
	capfit := 1.0
	score := autoWeights.Quota*quota +
		autoWeights.Health*health +
		autoWeights.Cost*cost +
		autoWeights.Latency*(1.0-latency) +
		autoWeights.Tier*1.0 +
		autoWeights.CapFit*capfit
	notes := "quota=" + ftoa(quota) + " health=" + ftoa(health) + " cost=" + ftoa(cost) +
		" latency=" + ftoa(latency) + " capfit=" + ftoa(capfit)
	return score, notes
}

// autoCostCeilingMicros normalizes cost into [0,1]; it is a soft ceiling, not a
// limit.
const autoCostCeilingMicros = 50.0

// clamp01 clamps v into [0,1].
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// itoa64 formats an int64 (a tiny local helper).
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ftoa formats a float with 3 decimals (stable in Reason strings).
func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }
