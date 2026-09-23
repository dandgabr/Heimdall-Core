package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file drives the SQL-error branches of MemoryStore through the fault
// driver (the same pattern the quota store uses): every memoryStoreError site
// is reached exactly by the injected failure that provokes it.

// memoryRecordFixture is a valid record for the fault-driver inserts.
func memoryRecordFixture() contracts.MemoryRecord {
	return contracts.MemoryRecord{
		ID: "m-1", Namespace: "ns", Content: "c",
		Provenance: contracts.SourceUser, TurnID: "req-1",
		ContentHash: "h", CreatedAt: time.Unix(0, 0).UTC(), ExpiresAt: time.Unix(0, 0).UTC().Add(time.Hour),
	}
}

// TestMemoryStoreSQLFailures reaches every Exec/Begin/Commit error branch.
func TestMemoryStoreSQLFailures(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		cfg  faultDriverConfig
		call func(m *MemoryStore) error
	}{
		{"insert begin", faultDriverConfig{failBegin: true}, func(m *MemoryStore) error {
			_, err := m.Insert(ctx, memoryRecordFixture())
			return err
		}},
		{"insert exec", faultDriverConfig{failOn: "INSERT INTO memories\n"}, func(m *MemoryStore) error {
			_, err := m.Insert(ctx, memoryRecordFixture())
			return err
		}},
		{"insert rows affected", faultDriverConfig{failRowsAffected: true}, func(m *MemoryStore) error {
			_, err := m.Insert(ctx, memoryRecordFixture())
			return err
		}},
		{"insert fts exec", faultDriverConfig{failNthExec: 2}, func(m *MemoryStore) error {
			_, err := m.Insert(ctx, memoryRecordFixture())
			return err
		}},
		{"insert commit", faultDriverConfig{failCommit: true}, func(m *MemoryStore) error {
			_, err := m.Insert(ctx, memoryRecordFixture())
			return err
		}},
		{"dedup commit", faultDriverConfig{failCommit: true, zeroRowsAffected: true}, func(m *MemoryStore) error {
			_, err := m.Insert(ctx, memoryRecordFixture())
			return err
		}},
		{"purge begin", faultDriverConfig{failBegin: true}, func(m *MemoryStore) error {
			_, err := m.PurgeExpired(ctx, time.Unix(0, 0).UTC())
			return err
		}},
		{"purge fts exec", faultDriverConfig{failOn: "DELETE FROM memories_fts"}, func(m *MemoryStore) error {
			_, err := m.PurgeExpired(ctx, time.Unix(0, 0).UTC())
			return err
		}},
		{"purge rows exec", faultDriverConfig{failNthExec: 2}, func(m *MemoryStore) error {
			_, err := m.PurgeNamespace(ctx, "ns")
			return err
		}},
		{"purge rows affected", faultDriverConfig{failRowsAffected: true}, func(m *MemoryStore) error {
			_, err := m.PurgeNamespace(ctx, "ns")
			return err
		}},
		{"purge commit", faultDriverConfig{failCommit: true}, func(m *MemoryStore) error {
			_, err := m.PurgeNamespace(ctx, "ns")
			return err
		}},
		{"search query", faultDriverConfig{failOn: "memories_fts MATCH"}, func(m *MemoryStore) error {
			_, err := m.Search(ctx, "ns", "q", time.Unix(0, 0).UTC(), 1)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMemoryStore(faultyStore(t, tc.cfg))
			err := tc.call(m)
			var de *domain.DomainError
			if !errors.As(err, &de) || de.Code != domain.CodeStoreOpenFailed {
				t.Fatalf("err = %v, want typed store.open_failed", err)
			}
		})
	}
}

// TestMemoryStoreSearchRowBranches drives the per-row scan/parse/rowsErr
// branches of the search.
func TestMemoryStoreSearchRowBranches(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		cfg  faultDriverConfig
	}{
		{"scan error", faultDriverConfig{memoryOneColRow: true}},
		{"bad created_at", faultDriverConfig{memoryBadCreated: true}},
		{"bad expires_at", faultDriverConfig{memoryBadExpires: true}},
		{"rows error", faultDriverConfig{memoryRowsErr: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMemoryStore(faultyStore(t, tc.cfg))
			if _, err := m.Search(ctx, "ns", "q", time.Unix(0, 0).UTC(), 5); err == nil {
				t.Fatalf("%s: want error", tc.name)
			}
		})
	}
}

// TestMemoryStoreSearchValidRowFromFaultDriver covers the successful scan past
// the fault driver (mirrors the quota store's complement test).
func TestMemoryStoreSearchValidRowFromFaultDriver(t *testing.T) {
	m := NewMemoryStore(faultyStore(t, faultDriverConfig{memoryRow: true}))
	hits, err := m.Search(context.Background(), "ns", "q", time.Unix(0, 0).UTC(), 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != "m-1" || hits[0].Content != "the deploy window is tuesday" {
		t.Fatalf("hits = %+v", hits)
	}
	if hits[0].Provenance != 0 || hits[0].TurnID != "req-1" {
		t.Fatalf("hit metadata = %+v", hits[0])
	}
	if hits[0].CreatedAt.IsZero() || hits[0].ExpiresAt.IsZero() {
		t.Fatal("timestamps not parsed")
	}
}

// TestMemoryStoreInsertDedupCommitPath covers the dedup commit branch
// (RowsAffected==0: the (namespace, hash) row already existed).
func TestMemoryStoreInsertDedupCommitPath(t *testing.T) {
	m := NewMemoryStore(faultyStore(t, faultDriverConfig{zeroRowsAffected: true}))
	inserted, err := m.Insert(context.Background(), memoryRecordFixture())
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if inserted {
		t.Fatal("RowsAffected==0 must report inserted=false")
	}
}

// TestMemoryStoreSearchDefaultLimit covers the limit<=0 fallback.
func TestMemoryStoreSearchDefaultLimit(t *testing.T) {
	m := NewMemoryStore(faultyStore(t, faultDriverConfig{memoryRow: true}))
	hits, err := m.Search(context.Background(), "ns", "q", time.Unix(0, 0).UTC(), 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1 (the fallback limit kept the row)", len(hits))
	}
}

// TestIsNamespaceRequiredNegative covers the negative branch of the typed
// predicate.
func TestIsNamespaceRequiredNegative(t *testing.T) {
	if IsNamespaceRequired(nil) || IsNamespaceRequired(errors.New("plain")) {
		t.Fatal("predicate must be false for nil/plain errors")
	}
}
