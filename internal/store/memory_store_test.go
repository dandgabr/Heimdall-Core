package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// newMemoryTestStore opens a throwaway vault with the memory migration.
func newMemoryTestStore(t *testing.T) (*MemoryStore, *Store) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewMemoryStore(s), s
}

// rec builds a record with deterministic fields (the ID derives from the
// content hash, mirroring the gate's time-ordered + hash scheme).
func rec(ns, content string, createdAt, expiresAt time.Time) contracts.MemoryRecord {
	sum := sha256.Sum256([]byte(ns + "\x00" + content))
	hash := hex.EncodeToString(sum[:])
	return contracts.MemoryRecord{
		ID:          "2026092300000000000-" + hash[:16],
		Namespace:   ns,
		Content:     content,
		Provenance:  contracts.SourceUser,
		TurnID:      "req-1",
		ContentHash: hash,
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}
}

func TestMemoryStoreInsertSearchRoundTrip(t *testing.T) {
	m, _ := newMemoryTestStore(t)
	ctx := context.Background()
	ns := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Unix(0, 0).UTC()

	r1 := rec(ns, "the deploy window is tuesday", now, now.Add(24*time.Hour))
	inserted, err := m.Insert(ctx, r1)
	if err != nil || !inserted {
		t.Fatalf("insert: inserted=%v err=%v", inserted, err)
	}
	if _, err := m.Insert(ctx, rec(ns, "unrelated note about pasta", now, now.Add(24*time.Hour))); err != nil {
		t.Fatalf("insert 2: %v", err)
	}

	hits, err := m.Search(ctx, ns, "deploy window", now, 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1 (%+v)", len(hits), hits)
	}
	h := hits[0]
	if h.Content != r1.Content {
		t.Fatalf("content = %q", h.Content)
	}
	if h.Provenance != contracts.SourceUser || h.Provenance.String() != "user" {
		t.Fatalf("provenance = %v", h.Provenance)
	}
	if h.TurnID != "req-1" {
		t.Fatalf("turn id = %q", h.TurnID)
	}
	if !h.CreatedAt.Equal(now) || !h.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("timestamps = %v/%v", h.CreatedAt, h.ExpiresAt)
	}
	if h.Rank != 0 {
		t.Fatalf("rank = %d", h.Rank)
	}
}

// TestMemoryStoreNamespaceIsolation is the MANDATORY isolation assertion:
// client A's memories are invisible to B even for identical content, and a
// foreign namespace query returns nothing.
func TestMemoryStoreNamespaceIsolation(t *testing.T) {
	m, _ := newMemoryTestStore(t)
	ctx := context.Background()
	nsA, nsB := "aaaa", "bbbb"
	now := time.Unix(0, 0).UTC()

	if _, err := m.Insert(ctx, rec(nsA, "shared secret of A", now, now.Add(time.Hour))); err != nil {
		t.Fatalf("insert A: %v", err)
	}
	hits, err := m.Search(ctx, nsB, "shared secret", now, 5)
	if err != nil {
		t.Fatalf("search B: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("B sees A's memory: %+v", hits)
	}
	// Identical content under B is a DIFFERENT record (dedup is per-namespace).
	inserted, err := m.Insert(ctx, rec(nsB, "shared secret of A", now, now.Add(time.Hour)))
	if err != nil || !inserted {
		t.Fatalf("insert B: inserted=%v err=%v", inserted, err)
	}
	nA, err := m.CountNamespace(ctx, nsA)
	if err != nil || nA != 1 {
		t.Fatalf("count A = %d, %v", nA, err)
	}
	nB, err := m.CountNamespace(ctx, nsB)
	if err != nil || nB != 1 {
		t.Fatalf("count B = %d, %v", nB, err)
	}
}

// TestMemoryStoreTTLPinsExpiry proves the retention limit: an expired row is
// invisible to Search even before the sweep, and PurgeExpired removes it
// exactly once.
func TestMemoryStoreTTLPinsExpiry(t *testing.T) {
	m, _ := newMemoryTestStore(t)
	ctx := context.Background()
	ns := "cccc"
	now := time.Unix(0, 0).UTC()

	if _, err := m.Insert(ctx, rec(ns, "expired fact", now, now.Add(-time.Second))); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := m.Insert(ctx, rec(ns, "fresh fact", now, now.Add(time.Hour))); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	hits, err := m.Search(ctx, ns, "fact", now, 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 || hits[0].Content != "fresh fact" {
		t.Fatalf("expired row leaked: %+v", hits)
	}

	removed, err := m.PurgeExpired(ctx, now)
	if err != nil || removed != 1 {
		t.Fatalf("purge = %d, %v", removed, err)
	}
	removed, err = m.PurgeExpired(ctx, now)
	if err != nil || removed != 0 {
		t.Fatalf("second purge = %d, %v (must be idempotent)", removed, err)
	}
	if n, _ := m.CountNamespace(ctx, ns); n != 1 {
		t.Fatalf("count after purge = %d", n)
	}
}

// TestMemoryStoreDedupIdempotentByHash is the idempotency proof: the same
// (namespace, content) inserted twice yields ONE row and inserted=false on
// the re-delivery.
func TestMemoryStoreDedupIdempotentByHash(t *testing.T) {
	m, _ := newMemoryTestStore(t)
	ctx := context.Background()
	ns := "dddd"
	now := time.Unix(0, 0).UTC()

	first, err := m.Insert(ctx, rec(ns, "same content", now, now.Add(time.Hour)))
	if err != nil || !first {
		t.Fatalf("first insert: %v %v", first, err)
	}
	second, err := m.Insert(ctx, rec(ns, "same content", now.Add(time.Minute), now.Add(2*time.Hour)))
	if err != nil {
		t.Fatalf("second insert: %v", err)
	}
	if second {
		t.Fatal("re-delivery must be a dedup no-op (inserted=false)")
	}
	if n, _ := m.CountNamespace(ctx, ns); n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

// TestMemoryStorePurgeNamespaceErasesEverything proves the erasure primitive:
// only the target namespace's rows (and FTS entries) are physically removed.
func TestMemoryStorePurgeNamespaceErasesEverything(t *testing.T) {
	m, _ := newMemoryTestStore(t)
	ctx := context.Background()
	nsA, nsB := "eeee", "ffff"
	now := time.Unix(0, 0).UTC()

	for _, ns := range []string{nsA, nsB} {
		for _, c := range []string{"alpha note", "beta note"} {
			if _, err := m.Insert(ctx, rec(ns, c, now, now.Add(time.Hour))); err != nil {
				t.Fatalf("insert %s/%s: %v", ns, c, err)
			}
		}
	}
	removed, err := m.PurgeNamespace(ctx, nsA)
	if err != nil || removed != 2 {
		t.Fatalf("purge = %d, %v", removed, err)
	}
	if n, _ := m.CountNamespace(ctx, nsA); n != 0 {
		t.Fatalf("A rows left = %d", n)
	}
	if n, _ := m.CountNamespace(ctx, nsB); n != 2 {
		t.Fatalf("B rows must survive, = %d", n)
	}
	// The FTS entries are gone too: a lexical search over B still finds its
	// rows, and A's namespace returns nothing.
	hits, err := m.Search(ctx, nsB, "note", now, 10)
	if err != nil {
		t.Fatalf("search B: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("B hits = %d, want 2", len(hits))
	}
	hitsA, err := m.Search(ctx, nsA, "alpha OR beta OR note", now, 10)
	if err != nil || len(hitsA) != 0 {
		t.Fatalf("A hits after purge = %d, %v", len(hitsA), err)
	}
}

// TestMemoryStoreSearchGuards covers the no-query and no-limit guards plus the
// namespace-mandatory refusals.
func TestMemoryStoreSearchGuards(t *testing.T) {
	m, _ := newMemoryTestStore(t)
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()

	hits, err := m.Search(ctx, "ns", "   ", now, 5)
	if err != nil || hits != nil {
		t.Fatalf("empty query: %v %v", hits, err)
	}
	if _, err := m.Search(ctx, "", "query", now, 5); !IsNamespaceRequired(err) {
		t.Fatalf("empty namespace: err = %v, want namespace-required", err)
	}
	_, insertErr := m.Insert(ctx, contracts.MemoryRecord{Namespace: "", Content: "x"})
	if !IsNamespaceRequired(insertErr) {
		t.Fatalf("insert without namespace: err = %v", insertErr)
	}
	if _, err := m.PurgeNamespace(ctx, ""); !IsNamespaceRequired(err) {
		t.Fatalf("purge without namespace: err = %v", err)
	}
}

// TestMemoryStoreErrorsTypedOnClosedStore pins the typed error wrapping of
// every statement on a closed vault.
func TestMemoryStoreErrorsTypedOnClosedStore(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "heimdall.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m := NewMemoryStore(s)
	_ = s.Close()
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()

	if _, err := m.Insert(ctx, rec("ns", "c", now, now)); err == nil {
		t.Fatal("insert on closed store: want error")
	}
	searchErr := func() error {
		_, err := m.Search(ctx, "ns", "q", now, 1)
		return err
	}()
	var de *domain.DomainError
	if !errors.As(searchErr, &de) || de.Code != domain.CodeStoreOpenFailed {
		t.Fatalf("search error not typed: %v", searchErr)
	}
	if _, err := m.PurgeExpired(ctx, now); err == nil {
		t.Fatal("purge on closed store: want error")
	}
	if _, err := m.CountNamespace(ctx, "ns"); err == nil {
		t.Fatal("count on closed store: want error")
	}
}

// TestMemoryStoreEmbeddingBlobRoundTrip pins the on-disk embedding encoding
// (little-endian float32) for the future vec0 retrieval.
func TestMemoryStoreEmbeddingBlobRoundTrip(t *testing.T) {
	m, s := newMemoryTestStore(t)
	ctx := context.Background()
	ns := "1234"
	now := time.Unix(0, 0).UTC()

	r := rec(ns, "vectorised fact", now, now.Add(time.Hour))
	r.Embedding = []float32{1.5, -2.25, 0, 3}
	if inserted, err := m.Insert(ctx, r); err != nil || !inserted {
		t.Fatalf("insert: %v %v", inserted, err)
	}
	var blob []byte
	if err := s.read.QueryRow(`SELECT embedding FROM memories WHERE namespace = ?`, ns).Scan(&blob); err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if len(blob) != 16 {
		t.Fatalf("blob len = %d", len(blob))
	}
	for i, want := range r.Embedding {
		got := math.Float32frombits(binary.LittleEndian.Uint32(blob[4*i:]))
		if got != want {
			t.Fatalf("vec[%d] = %v, want %v", i, got, want)
		}
	}
}

// TestMatchQueryShape pins the FTS5 injection guard: tokens become quoted
// phrases, embedded quotes are stripped, input is bounded, blank is empty.
func TestMatchQueryShape(t *testing.T) {
	if got := matchQuery("   "); got != "" {
		t.Fatalf("blank = %q", got)
	}
	if got := matchQuery(`he said "drop table" then`); got != `"he" "said" "drop" "table" "then"` {
		t.Fatalf("quoted = %q", got)
	}
	// A token made only of quotes is stripped and skipped (the continue).
	if got := matchQuery(`"" x`); got != `"x"` {
		t.Fatalf("quote-only token = %q, want \"x\"", got)
	}
	long := strings.Repeat("tok ", 100)
	if got := strings.Count(matchQuery(long), `" "`) + 1; got != 64 {
		t.Fatalf("token cap = %d, want 64", got)
	}
	if got := matchQuery(strings.Repeat("a", 600)); strings.Count(got, "a") != 512 {
		t.Fatalf("long single token kept %d chars, want the 512-byte truncated one", strings.Count(got, "a"))
	}
}

// TestEncodeEmbeddingNil covers the nil-vector branch.
func TestEncodeEmbeddingNil(t *testing.T) {
	if encodeEmbedding(nil) != nil {
		t.Fatal("nil embedding must encode to nil")
	}
}
