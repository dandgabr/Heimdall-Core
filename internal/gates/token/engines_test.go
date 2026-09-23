package token

import (
	"encoding/json"
	"strings"
	"testing"
)

// pretty builds a canonical body with whitespace so the structural engine has
// something to collapse. It keeps the last user message as the compressible
// suffix.
func pretty(system, user string) []byte {
	return []byte("{\n  \"model\": \"m\",\n  \"messages\": [\n" +
		"    {\"role\": \"system\", \"content\": \"" + system + "\"},\n" +
		"    {\"role\": \"user\", \"content\": \"" + user + "\"}\n" +
		"  ]\n}")
}

// TestPrefixBoundarySplitsAtLastUserMessage pins the freeze boundary: everything
// BEFORE the last user message is frozen; the last user turn is the suffix.
func TestPrefixBoundarySplitsAtLastUserMessage(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"system","content":"SYS"},{"role":"user","content":"first"},{"role":"assistant","content":"a"},{"role":"user","content":"second"}]}`)
	end := prefixBoundary(body)
	if end <= 0 || end >= len(body) {
		t.Fatalf("boundary = %d, want inside (0,%d)", end, len(body))
	}
	if !strings.HasPrefix(string(body[end:]), `,{"role":"user","content":"second"}`) {
		t.Fatalf("suffix = %q, want the last user turn", body[end:])
	}
	if !strings.HasSuffix(string(body[:end]), `"content":"a"}`) {
		t.Fatalf("prefix = %q, want to end at the previous message", body[:end])
	}
}

// TestPrefixBoundaryEdgeCases covers the "no stable prefix" cases: empty, scalar,
// no messages, no user message.
func TestPrefixBoundaryEdgeCases(t *testing.T) {
	cases := map[string]int{
		"":                                 0,
		"null":                             0,
		"[]":                               0,
		`{"model":"m"}`:                    0,
		`{"messages":[]}`:                  0,
		`{"messages":[{"role":"system"}]}`: 0,
		`{"messages":"not-an-array"}`:      0,
		`{"messages":[{"role":"user"}]}`:   13, // the sole user message starts at offset 13
	}
	for body, want := range cases {
		if got := prefixBoundary([]byte(body)); got != want {
			t.Errorf("prefixBoundary(%q) = %d, want %d", body, got, want)
		}
	}
}

// TestCountOnlyIsImpactNone proves the reference engine changes nothing and
// declares the valid ImpactNone/lossy=false pair.
func TestCountOnlyIsImpactNone(t *testing.T) {
	e := NewCountOnly()
	if e.ID() != "count-only" || e.CacheImpact() != ImpactNone || e.Lossy() {
		t.Fatalf("count-only metadata = %s/%v/%v", e.ID(), e.CacheImpact(), e.Lossy())
	}
	in := []byte(`{"a":1}`)
	out, stats, err := e.Apply(in, Options{})
	if err != nil || string(out) != string(in) || stats.Applied() {
		t.Fatalf("count-only = %q, %+v, %v", out, stats, err)
	}
}

// TestCollapseWhitespaceOnlyOutsideStrings proves the engine collapses
// structural whitespace but never inside a string literal.
func TestCollapseWhitespaceOnlyOutsideStrings(t *testing.T) {
	e := NewCollapseWhitespace()
	in := []byte("{\n  \"content\": \"a   b\\t c\",\n  \"x\": 1\n}")
	out, stats, err := e.Apply(in, Options{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("output is not valid JSON: %q", out)
	}
	// The string value must be byte-identical (whitespace inside preserved).
	if !strings.Contains(string(out), `"a   b\t c"`) {
		t.Fatalf("string content was altered: %q", out)
	}
	if stats.BytesOut >= stats.BytesIn {
		t.Fatalf("no compression: %+v", stats)
	}
	if !stats.Applied() || stats.TokensSaved == 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestCollapseWhitespaceEscapedQuote proves the string scanner handles an
// escaped quote inside a string (does not exit the string early).
func TestCollapseWhitespaceEscapedQuote(t *testing.T) {
	e := NewCollapseWhitespace()
	// "a\"b   c" : the escaped quote must not end the string, so the internal
	// spaces survive while the outer structural spaces collapse.
	in := []byte("{\n  \"content\": \"a\\\"b   c\"\n}")
	out, _, err := e.Apply(in, Options{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(string(out), `"a\"b   c"`) {
		t.Fatalf("escaped-quote string altered: %q", out)
	}
	if !json.Valid(out) {
		t.Fatalf("invalid JSON: %q", out)
	}
}

// TestCollapseWhitespaceTrailingRun proves a trailing whitespace run is dropped.
func TestCollapseWhitespaceTrailingRun(t *testing.T) {
	out := collapseRuns([]byte("a b \n"))
	if string(out) != "a b" {
		t.Fatalf("collapseRuns = %q, want %q", out, "a b")
	}
}

// TestCollapseWhitespaceRespectsPrefix proves the engine leaves the frozen
// prefix byte-identical and only compresses the suffix.
func TestCollapseWhitespaceRespectsPrefix(t *testing.T) {
	e := NewCollapseWhitespace()
	in := pretty("SYS   A", "user   B")
	end := prefixBoundary(in)
	out, _, err := e.Apply(in, Options{PrefixEnd: end})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(in[:end]) != string(out[:end]) {
		t.Fatalf("prefix changed: %q -> %q", in[:end], out[:end])
	}
}

// TestDedupLinesRemovesExactDuplicates proves duplicate lines are removed,
// keeping the first and preserving order; empty lines are preserved.
func TestDedupLinesRemovesExactDuplicates(t *testing.T) {
	e := NewDedupLines()
	in := []byte("{\n \"a\": 1,\n \"a\": 1,\n\n \"b\": 2\n}")
	out, stats, err := e.Apply(in, Options{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if strings.Count(string(out), `"a": 1`) != 1 {
		t.Fatalf("duplicate line survived: %q", out)
	}
	if !stats.Applied() {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestDedupLinesEmpty covers the empty-input fast path.
func TestDedupLinesEmpty(t *testing.T) {
	if got := dedupExactLines(nil); got != nil {
		t.Fatalf("dedupExactLines(nil) = %q", got)
	}
}

// TestDedupLinesRespectsPrefix proves the frozen prefix is untouched.
func TestDedupLinesRespectsPrefix(t *testing.T) {
	e := NewDedupLines()
	in := []byte("{\"system\":\"S\",\"messages\":[\n \"x\",\n \"x\"\n]}")
	end := prefixBoundary(in)
	out, _, err := e.Apply(in, Options{PrefixEnd: end})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(in[:end]) != string(out[:end]) {
		t.Fatalf("prefix changed")
	}
}

// TestPrefixRewriteRequiresOptIn proves the ImpactHigh engine touches the prefix
// ONLY with opt-in; without it, it falls back to suffix-only.
func TestPrefixRewriteRequiresOptIn(t *testing.T) {
	e := NewPrefixRewrite()
	if e.CacheImpact() != ImpactHigh {
		t.Fatalf("impact = %v, want high", e.CacheImpact())
	}
	in := pretty("SYS   A", "user   B")
	end := prefixBoundary(in)

	// Without opt-in: prefix untouched.
	safe, _, err := e.Apply(in, Options{PrefixEnd: end})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(in[:end]) != string(safe[:end]) {
		t.Fatalf("no-opt-in touched the prefix")
	}

	// With opt-in: the prefix may change.
	risky, stats, err := e.Apply(in, Options{PrefixEnd: end, AllowPrefixRewrite: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if stats.BytesOut >= stats.BytesIn {
		t.Fatalf("opt-in produced no compression: %+v", stats)
	}
	if len(risky) >= len(in) {
		t.Fatalf("opt-in did not compress: %d vs %d", len(risky), len(in))
	}
}

// TestDefaultEnginesDeterministicOrder proves the built-in set is ID-sorted.
func TestDefaultEnginesDeterministicOrder(t *testing.T) {
	got := DefaultEngines()
	if len(got) != 3 {
		t.Fatalf("engines = %d, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].ID() >= got[i].ID() {
			t.Fatalf("not sorted: %s before %s", got[i-1].ID(), got[i].ID())
		}
	}
}

// TestEstimateTokens covers the heuristic branches.
func TestEstimateTokens(t *testing.T) {
	if estimateTokens(0) != 0 || estimateTokens(-5) != 0 {
		t.Fatal("non-positive estimate should be 0")
	}
	if estimateTokens(8) != 2 {
		t.Fatalf("estimateTokens(8) = %d, want 2", estimateTokens(8))
	}
}

// TestEngineMetadataAccessors exercises the concrete metadata methods directly
// (they are otherwise reached only through the CompressionEngine interface, so
// the compiler does not attribute coverage to them).
func TestEngineMetadataAccessors(t *testing.T) {
	// collapseWhitespace
	if got := (collapseWhitespace{}).CacheImpact(); got != ImpactLow {
		t.Fatalf("collapse impact = %v", got)
	}
	if !(collapseWhitespace{}).Lossy() {
		t.Fatal("collapse must be lossy")
	}
	// dedupLines
	if got := (dedupLines{}).CacheImpact(); got != ImpactLow {
		t.Fatalf("dedup impact = %v", got)
	}
	if !(dedupLines{}).Lossy() {
		t.Fatal("dedup must be lossy")
	}
	// prefixRewrite
	if got := (prefixRewrite{}).CacheImpact(); got != ImpactHigh {
		t.Fatalf("prefix rewrite impact = %v", got)
	}
	if !(prefixRewrite{}).Lossy() {
		t.Fatal("prefix rewrite must be lossy")
	}
}

// TestPrefixRewriteWithoutOptInDelegates proves the ImpactHigh engine's
// no-opt-in branch delegates to suffix-only collapse (never touching the
// prefix), including the prefix-invalidation flag staying false.
func TestPrefixRewriteWithoutOptInDelegates(t *testing.T) {
	e := prefixRewrite{}
	withUser := pretty("SYS   A", "user    B")
	end := prefixBoundary(withUser)
	out, stats, err := e.Apply(withUser, Options{PrefixEnd: end})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(withUser[:end]) != string(out[:end]) {
		t.Fatal("no-opt-in prefix rewrite touched the prefix")
	}
	if stats.PrefixInvalidated {
		t.Fatal("no-opt-in reported prefix invalidation")
	}
}

// TestPrefixBoundaryMalformedJSON covers every defensive decode-error branch:
// a non-object first token, a non-string key, an unparseable value, and a
// malformed message inside the array.
func TestPrefixBoundaryMalformedJSON(t *testing.T) {
	cases := []string{
		`"just a string"`,     // first token not '{'
		`{123: 1}`,            // non-string key
		`{"model": }`,         // value decode error
		`{"messages": [1 2]}`, // message decode error
		`{"messages": [`,      // unterminated array
	}
	for _, body := range cases {
		if got := prefixBoundary([]byte(body)); got != 0 {
			t.Errorf("prefixBoundary(%q) = %d, want 0", body, got)
		}
	}
}

// TestPrefixBoundaryValueDecodeError covers the non-messages skip decode error.
func TestPrefixBoundarySkipDecodeError(t *testing.T) {
	// A valid opening, a key, then a truncated value forces the skip Decode to
	// fail.
	if got := prefixBoundary([]byte(`{"model":`)); got != 0 {
		t.Fatalf("truncated value = %d, want 0", got)
	}
	// A valid prefix key/value, then a truncated messages opening.
	if got := prefixBoundary([]byte(`{"model":"m","messages":`)); got != 0 {
		t.Fatalf("truncated messages = %d, want 0", got)
	}
}

// TestDedupLinesWithRealPrefix exercises the dedup engine's prefix-slicing
// branch (PrefixEnd in range) directly.
func TestDedupLinesWithRealPrefix(t *testing.T) {
	in := pretty("SYS   A", "user    B")
	end := prefixBoundary(in)
	e := dedupLines{}
	out, stats, err := e.Apply(in, Options{PrefixEnd: end})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if string(in[:end]) != string(out[:end]) {
		t.Fatal("dedup touched the frozen prefix")
	}
	if stats.BytesIn != len(in) {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestCacheablePrefixEndExported covers the exported wrapper used by callers
// outside the package.
func TestCacheablePrefixEndExported(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"system","content":"S"},{"role":"user","content":"u"}]}`)
	if got := CacheablePrefixEnd(body); got != prefixBoundary(body) {
		t.Fatalf("CacheablePrefixEnd = %d, want %d", got, prefixBoundary(body))
	}
	if got := CacheablePrefixEnd(nil); got != 0 {
		t.Fatalf("CacheablePrefixEnd(nil) = %d", got)
	}
}

// TestPrefixBoundaryEmptyBody covers the nil/empty-input guard.
func TestPrefixBoundaryEmptyBody(t *testing.T) {
	if prefixBoundary(nil) != 0 {
		t.Fatal("nil body has no prefix")
	}
}

// TestPrefixBoundaryFirstTokenError covers the first Token() error branch with a
// body that begins with an invalid JSON byte.
func TestPrefixBoundaryFirstTokenError(t *testing.T) {
	if got := prefixBoundary([]byte("\xff\xfe")); got != 0 {
		t.Fatalf("invalid first token = %d, want 0", got)
	}
}

// TestPrefixBoundaryNonStringKey covers a malformed member name: Token() itself
// returns an error, so the boundary is zero.
func TestPrefixBoundaryNonStringKey(t *testing.T) {
	if got := prefixBoundary([]byte(`{{}:1}`)); got != 0 {
		t.Fatalf("non-string key = %d, want 0", got)
	}
}

// TestCacheImpactString covers every impact label plus the unknown default.
func TestCacheImpactString(t *testing.T) {
	cases := map[CacheImpact]string{
		ImpactNone: "none", ImpactLow: "low", ImpactModerate: "moderate",
		ImpactHigh: "high", CacheImpact(99): "unknown",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("CacheImpact(%d).String() = %q, want %q", c, got, want)
		}
	}
}
