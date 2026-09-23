package router

import (
	"math/rand/v2"
	"strconv"
)

// maxDepth is the runtime ceiling on nested combo-refs. It mirrors
// combos.MaxDepth so a persisted combo that predates the validator, or a
// malformed store, cannot make the Router recurse without bound (ADR-0009 §3).
const maxDepth = 8

// itoa is a tiny local integer formatter.
func itoa(n int) string { return strconv.Itoa(n) }

// randSource adapts a math/rand/v2 *Rand to the RNG port. It is the production
// adapter; a test injects a deterministic source instead.
type randSource struct{ r *rand.Rand }

// Intn implements RNG.
func (s randSource) Intn(n int) int { return s.r.IntN(n) }

// Float64 implements RNG.
func (s randSource) Float64() float64 { return s.r.Float64() }

// NewRandSource builds the default RNG over a caller-supplied *rand.Rand, so the
// caller controls the seed (deterministic TDD) or uses rand.New(rand.NewPCG(…))
// for production. Passing a nil *rand.Rand is a programming error and panics
// like any nil dereference would; callers go through WithRNG or the default.
func NewRandSource(r *rand.Rand) RNG { return randSource{r: r} }

// rrKey builds the round-robin cursor key for (combo, tier).
func rrKey(combo string, tier int) string {
	return combo + "#" + itoa(tier)
}

// nextRR returns the next round-robin index for a key and advances the cursor.
// It is mutex-free by contract: the Router holds a single lock when it mutates
// the cursor (see resolve). It returns 0 when n <= 0.
func (c *Cursor) nextRR(key string, n int) int {
	if n <= 0 {
		return 0
	}
	idx := 0
	if c.roundRobin != nil {
		idx = c.roundRobin[key]
	}
	if idx < 0 || idx >= n {
		idx = 0
	}
	if c.roundRobin == nil {
		c.roundRobin = make(map[string]int)
	}
	c.roundRobin[key] = (idx + 1) % n
	return idx
}

// nextFill returns the current fill-first credential index for a provider key
// and advances it. It returns 0 when n <= 0.
func (c *Cursor) nextFill(key string, n int) int {
	if n <= 0 {
		return 0
	}
	idx := 0
	if c.fillFirst != nil {
		idx = c.fillFirst[key]
	}
	if idx < 0 || idx >= n {
		idx = 0
	}
	if c.fillFirst == nil {
		c.fillFirst = make(map[string]int)
	}
	c.fillFirst[key] = (idx + 1) % n
	return idx
}
