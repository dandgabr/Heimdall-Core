package token

import (
	"bytes"
	"sort"
)

// This file holds the built-in compression engines. Each is PURE (no I/O, no
// clock) and declares its cache impact and lossiness (ADR-0015 §1). The gate
// additionally VERIFIES two invariants on every engine's output — the frozen
// prefix is unchanged unless the engine is ImpactHigh with opt-in, and the body
// stays valid JSON — so a buggy engine can never corrupt the request or
// silently invalidate the cache.

// collapseWhitespace is a real, conservative engine: it collapses runs of ASCII
// whitespace (space, tab, CR, LF) to a single space OUTSIDE JSON string literals,
// leaving string content untouched. It is offset-LOW impact: it acts on the
// suffix, and never on the frozen prefix.
type collapseWhitespace struct{}

// NewCollapseWhitespace returns the whitespace-collapse engine.
func NewCollapseWhitespace() CompressionEngine { return collapseWhitespace{} }

// ID implements CompressionEngine.
func (collapseWhitespace) ID() string { return "collapse-whitespace" }

// CacheImpact implements CompressionEngine.
func (collapseWhitespace) CacheImpact() CacheImpact { return ImpactLow }

// Lossy implements CompressionEngine: collapsing whitespace discards characters.
func (collapseWhitespace) Lossy() bool { return true }

// Apply implements CompressionEngine: it collapses whitespace only in the region
// it is allowed to touch.
func (e collapseWhitespace) Apply(canonical []byte, opts Options) ([]byte, Stats, error) {
	stats := Stats{ID: e.ID(), BytesIn: len(canonical)}
	region := canonical
	offset := 0
	if !opts.AllowPrefixRewrite && opts.PrefixEnd > 0 && opts.PrefixEnd <= len(canonical) {
		region = canonical[opts.PrefixEnd:]
		offset = opts.PrefixEnd
	}
	collapsed := collapseRuns(region)
	out := make([]byte, 0, offset+len(collapsed))
	out = append(out, canonical[:offset]...)
	out = append(out, collapsed...)
	stats.BytesOut = len(out)
	stats.TokensSaved = estimateTokens(stats.BytesIn - stats.BytesOut)
	stats.PrefixInvalidated = !bytes.Equal(prefixOf(canonical, opts), prefixOf(out, opts))
	return out, stats, nil
}

// collapseRuns collapses whitespace runs to one space outside string literals.
func collapseRuns(src []byte) []byte {
	out := make([]byte, 0, len(src))
	inString := false
	escaped := false
	pendingSpace := false
	for _, b := range src {
		if inString {
			out = append(out, b)
			if escaped {
				escaped = false
				continue
			}
			switch b {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			if pendingSpace {
				out = append(out, ' ')
				pendingSpace = false
			}
			inString = true
			out = append(out, b)
		case ' ', '\t', '\r', '\n':
			pendingSpace = true
		default:
			if pendingSpace {
				out = append(out, ' ')
				pendingSpace = false
			}
			out = append(out, b)
		}
	}
	// A trailing run is dropped: whitespace after the last token is optional in
	// JSON, and dropping it saves bytes without changing meaning.
	return out
}

// dedupLines is a real, conservative engine: it removes EXACT duplicate lines
// within the region it may touch, keeping the FIRST occurrence and preserving
// order. It is offset-LOW impact (suffix only).
type dedupLines struct{}

// NewDedupLines returns the duplicate-line engine.
func NewDedupLines() CompressionEngine { return dedupLines{} }

// ID implements CompressionEngine.
func (dedupLines) ID() string { return "dedup-lines" }

// CacheImpact implements CompressionEngine.
func (dedupLines) CacheImpact() CacheImpact { return ImpactLow }

// Lossy implements CompressionEngine: it discards duplicate lines.
func (dedupLines) Lossy() bool { return true }

// Apply implements CompressionEngine.
func (e dedupLines) Apply(canonical []byte, opts Options) ([]byte, Stats, error) {
	stats := Stats{ID: e.ID(), BytesIn: len(canonical)}
	region := canonical
	offset := 0
	if !opts.AllowPrefixRewrite && opts.PrefixEnd > 0 && opts.PrefixEnd <= len(canonical) {
		region = canonical[opts.PrefixEnd:]
		offset = opts.PrefixEnd
	}
	deduped := dedupExactLines(region)
	out := make([]byte, 0, offset+len(deduped))
	out = append(out, canonical[:offset]...)
	out = append(out, deduped...)
	stats.BytesOut = len(out)
	stats.TokensSaved = estimateTokens(stats.BytesIn - stats.BytesOut)
	stats.PrefixInvalidated = !bytes.Equal(prefixOf(canonical, opts), prefixOf(out, opts))
	return out, stats, nil
}

// dedupExactLines removes exact duplicate '\n'-delimited lines, keeping the first
// and preserving order. An empty line is never deduped, so whitespace layout is
// preserved.
func dedupExactLines(src []byte) []byte {
	if len(src) == 0 {
		return src
	}
	lines := bytes.Split(src, []byte("\n"))
	seen := make(map[string]bool, len(lines))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			out = append(out, line)
			continue
		}
		key := string(line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\n"))
}

// prefixRewrite is an ImpactHigh engine: it collapses whitespace across the
// WHOLE body, including the cacheable prefix. It therefore requires the
// operator's explicit opt-in (ADR-0015 §3); without it the engine behaves like
// the suffix-only engine and leaves the prefix untouched.
type prefixRewrite struct{}

// NewPrefixRewrite returns the opt-in prefix-rewrite engine.
func NewPrefixRewrite() CompressionEngine { return prefixRewrite{} }

// ID implements CompressionEngine.
func (prefixRewrite) ID() string { return "prefix-rewrite" }

// CacheImpact implements CompressionEngine: it can touch the prefix.
func (prefixRewrite) CacheImpact() CacheImpact { return ImpactHigh }

// Lossy implements CompressionEngine.
func (prefixRewrite) Lossy() bool { return true }

// Apply implements CompressionEngine. With AllowPrefixRewrite false it processes
// only the suffix (safe default); with true it processes the whole body and
// reports PrefixInvalidated.
func (e prefixRewrite) Apply(canonical []byte, opts Options) ([]byte, Stats, error) {
	stats := Stats{ID: e.ID(), BytesIn: len(canonical)}
	if opts.AllowPrefixRewrite {
		out := collapseRuns(canonical)
		stats.BytesOut = len(out)
		stats.TokensSaved = estimateTokens(stats.BytesIn - stats.BytesOut)
		stats.PrefixInvalidated = !bytes.Equal(prefixOf(canonical, opts), prefixOf(out, opts))
		return out, stats, nil
	}
	// No opt-in: fall back to suffix-only (the freeze is never violated).
	return collapseWhitespace{}.Apply(canonical, opts)
}

// countOnly is the ImpactNone reference engine: it changes nothing and only
// reports the input size. It proves the ImpactNone + lossy=false declaration is
// valid and gives the gate a pure no-op node.
type countOnly struct{}

// NewCountOnly returns the counting-only engine.
func NewCountOnly() CompressionEngine { return countOnly{} }

// ID implements CompressionEngine.
func (countOnly) ID() string { return "count-only" }

// CacheImpact implements CompressionEngine.
func (countOnly) CacheImpact() CacheImpact { return ImpactNone }

// Lossy implements CompressionEngine.
func (countOnly) Lossy() bool { return false }

// Apply implements CompressionEngine: it returns the input unchanged.
func (e countOnly) Apply(canonical []byte, _ Options) ([]byte, Stats, error) {
	return canonical, Stats{ID: e.ID(), BytesIn: len(canonical), BytesOut: len(canonical)}, nil
}

// prefixOf returns the frozen prefix of body, or empty when there is none.
func prefixOf(body []byte, opts Options) []byte {
	end := opts.PrefixEnd
	if end <= 0 || end > len(body) {
		return nil
	}
	return body[:end]
}

// estimateTokens estimates tokens from a byte delta using the ~4-bytes-per-token
// heuristic. It is observability only, never a decision input.
func estimateTokens(bytesSaved int) int {
	if bytesSaved <= 0 {
		return 0
	}
	return bytesSaved / 4
}

// DefaultEngines returns the built-in engine set in a deterministic order, for
// the composition root to register. The opt-in engine is included; whether it
// is REGISTERED with opt-in is the operator's per-engine config.
func DefaultEngines() []CompressionEngine {
	engines := []CompressionEngine{
		NewCollapseWhitespace(),
		NewDedupLines(),
		NewPrefixRewrite(),
	}
	sort.Slice(engines, func(i, j int) bool { return engines[i].ID() < engines[j].ID() })
	return engines
}
