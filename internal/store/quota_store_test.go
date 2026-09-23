package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// newQuotaStore opens a real vault and returns a QuotaStore over it.
func newQuotaStore(t *testing.T) *QuotaStore {
	t.Helper()
	s, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	return NewQuotaStore(s)
}

func sampleWindow(kind contracts.WindowKind, used, limit float64, reset time.Time) contracts.QuotaWindow {
	return contracts.QuotaWindow{
		Kind:      kind,
		Used:      used,
		Limit:     limit,
		Remaining: 1 - used/limit,
		ResetsAt:  reset,
		Source:    contracts.SourceLocalCounter,
		UpdatedAt: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC),
	}
}

// TestQuotaStoreSnapshotMissing proves an unknown credential returns ok=false.
func TestQuotaStoreSnapshotMissing(t *testing.T) {
	q := newQuotaStore(t)
	if _, ok, err := q.Snapshot(context.Background(), "nobody"); err != nil || ok {
		t.Fatalf("Snapshot(unknown) = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// TestQuotaStoreUpsertAndSnapshotRoundTrip proves the durable write/read path,
// including a window with a known reset and one without.
func TestQuotaStoreUpsertAndSnapshotRoundTrip(t *testing.T) {
	q := newQuotaStore(t)
	ctx := context.Background()
	cred := domain.CredentialID("acct-1")
	reset := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)

	if err := q.UpsertWindow(ctx, cred, sampleWindow(contracts.WindowShort, 95, 100, reset)); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}
	// A window with an unknown limit and zero reset.
	if err := q.UpsertWindow(ctx, cred, sampleWindow(contracts.WindowLong, 10, 0, time.Time{})); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}

	st, ok, err := q.Snapshot(ctx, cred)
	if err != nil || !ok {
		t.Fatalf("Snapshot = ok=%v err=%v", ok, err)
	}
	if st.Credential != cred {
		t.Errorf("credential = %q", st.Credential)
	}
	if len(st.Windows) != 2 {
		t.Fatalf("windows = %d, want 2", len(st.Windows))
	}
	// ORDER BY kind: short (0) before long (1).
	short := st.Windows[0]
	if short.Kind != contracts.WindowShort || short.Used != 95 || short.Limit != 100 {
		t.Errorf("short window = %+v", short)
	}
	if !short.ResetsAt.Equal(reset) {
		t.Errorf("short reset = %v, want %v", short.ResetsAt, reset)
	}
	long := st.Windows[1]
	if !long.ResetsAt.IsZero() {
		t.Errorf("long reset = %v, want zero", long.ResetsAt)
	}
}

// TestQuotaStoreUpsertReplaces proves the (credential, kind) primary key makes a
// second upsert replace rather than duplicate.
func TestQuotaStoreUpsertReplaces(t *testing.T) {
	q := newQuotaStore(t)
	ctx := context.Background()
	cred := domain.CredentialID("acct-1")
	_ = q.UpsertWindow(ctx, cred, sampleWindow(contracts.WindowShort, 10, 100, time.Time{}))
	_ = q.UpsertWindow(ctx, cred, sampleWindow(contracts.WindowShort, 70, 100, time.Time{}))
	st, _, _ := q.Snapshot(ctx, cred)
	if len(st.Windows) != 1 || st.Windows[0].Used != 70 {
		t.Fatalf("upsert did not replace: %+v", st.Windows)
	}
}

// TestQuotaStoreRecordAttemptIdempotent proves the durable half of idempotency:
// recording the same AttemptKey twice leaves exactly one row, with the second
// value (replace, not sum).
func TestQuotaStoreRecordAttemptIdempotent(t *testing.T) {
	q := newQuotaStore(t)
	ctx := context.Background()

	first := contracts.Usage{
		AttemptKey: "req:1", Credential: "acct-1", Provider: "zai", Model: "glm",
		Tokens: 50, Requests: 1, CostMicros: 5,
	}
	if _, err := q.RecordAttempt(ctx, first, "ok"); err != nil {
		t.Fatalf("first RecordAttempt: %v", err)
	}
	second := first
	second.Tokens = 20
	if _, err := q.RecordAttempt(ctx, second, "aborted"); err != nil {
		t.Fatalf("second RecordAttempt: %v", err)
	}

	got, ok, err := q.GetAttempt(ctx, "req:1")
	if err != nil || !ok {
		t.Fatalf("GetAttempt = ok=%v err=%v", ok, err)
	}
	if got.Tokens != 20 {
		t.Fatalf("tokens = %d, want 20 (replace, not sum)", got.Tokens)
	}

	// Exactly one row exists: a different key proves the COUNT is 1.
	var n int
	if err := q.store.read.QueryRow(`SELECT COUNT(*) FROM usage_attempts WHERE attempt_key = ?`, "req:1").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("attempt rows = %d, want 1", n)
	}
}

// TestQuotaStoreGetAttemptMissing proves a missing key returns ok=false.
func TestQuotaStoreGetAttemptMissing(t *testing.T) {
	q := newQuotaStore(t)
	if _, ok, err := q.GetAttempt(context.Background(), "nope"); err != nil || ok {
		t.Fatalf("GetAttempt(missing) = ok=%v err=%v", ok, err)
	}
}

// TestQuotaStoreSQLFailures drives the SQL-error branches through the fault
// driver so every quotaStoreError path is reached.
func TestQuotaStoreSQLFailures(t *testing.T) {
	ctx := context.Background()
	cred := domain.CredentialID("acct")

	t.Run("snapshot query", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{failOn: "FROM quota_windows"}))
		assertInjected(t, errOf(q.Snapshot(ctx, cred)), domain.CodeStoreOpenFailed)
	})
	t.Run("upsert window", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{failOn: "INSERT INTO quota_windows"}))
		assertInjected(t, q.UpsertWindow(ctx, cred, sampleWindow(contracts.WindowShort, 1, 10, time.Time{})),
			domain.CodeStoreOpenFailed)
	})
	t.Run("record attempt", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{failOn: "INSERT INTO usage_attempts"}))
		_, err := q.RecordAttempt(ctx, contracts.Usage{AttemptKey: "k"}, "ok")
		assertInjected(t, err, domain.CodeStoreOpenFailed)
	})
	t.Run("get attempt", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{failOn: "FROM usage_attempts"}))
		_, _, err := q.GetAttempt(ctx, "k")
		assertInjected(t, err, domain.CodeStoreOpenFailed)
	})
}

// TestQuotaStoreSnapshotScanError covers the per-row scan-error branch.
func TestQuotaStoreSnapshotScanError(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{quotaOneColRow: true}))
	if _, _, err := q.Snapshot(context.Background(), "acct"); err == nil {
		t.Fatal("Snapshot tolerated a short row")
	}
}

// TestQuotaStoreSnapshotRowsErr covers the rows.Err() branch after a valid row.
func TestQuotaStoreSnapshotRowsErr(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{quotaRowsErr: true}))
	if _, _, err := q.Snapshot(context.Background(), "acct"); err == nil {
		t.Fatal("Snapshot swallowed rows.Err()")
	}
}

// TestQuotaStoreSnapshotBadTimestamps covers the resets_at/updated_at parse
// branches.
func TestQuotaStoreSnapshotBadTimestamps(t *testing.T) {
	t.Run("resets_at", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{quotaBadResets: true}))
		if _, _, err := q.Snapshot(context.Background(), "acct"); err == nil {
			t.Fatal("Snapshot tolerated a bad resets_at")
		}
	})
	t.Run("updated_at", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{quotaBadUpdated: true}))
		if _, _, err := q.Snapshot(context.Background(), "acct"); err == nil {
			t.Fatal("Snapshot tolerated a bad updated_at")
		}
	})
}

// TestQuotaStoreGetAttemptScanError covers the usage scan-error branch.
func TestQuotaStoreGetAttemptScanError(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageOneColRow: true}))
	if _, _, err := q.GetAttempt(context.Background(), "k"); err == nil {
		t.Fatal("GetAttempt tolerated a short row")
	}
}

// TestQuotaStoreSnapshotValidRowFromFaultDriver covers the successful path over
// the fault driver (a real timestamp round-trip) as a complement to the vault
// round-trip above.
func TestQuotaStoreSnapshotValidRowFromFaultDriver(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{quotaRow: true}))
	st, ok, err := q.Snapshot(context.Background(), "acct")
	if err != nil || !ok {
		t.Fatalf("Snapshot = ok=%v err=%v", ok, err)
	}
	if len(st.Windows) != 1 || st.Windows[0].Used != 10 {
		t.Fatalf("windows = %+v", st.Windows)
	}
	if st.Windows[0].ResetsAt.IsZero() {
		t.Error("resets_at not parsed")
	}
}

// TestQuotaStoreGetAttemptValidRowFromFaultDriver covers the successful scan.
func TestQuotaStoreGetAttemptValidRowFromFaultDriver(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageRow: true}))
	u, ok, err := q.GetAttempt(context.Background(), "req:1")
	if err != nil || !ok {
		t.Fatalf("GetAttempt = ok=%v err=%v", ok, err)
	}
	if u.Tokens != 120 || u.Credential != "acct-1" || u.Provider != "zai" || u.Model != "glm" {
		t.Fatalf("attempt = %+v", u)
	}
}

// TestQuotaStoreUpsertZeroUpdatedAt covers the default-timestamp branch: an
// UpdatedAt left zero is stamped on write rather than persisted as the zero
// time.
func TestQuotaStoreUpsertZeroUpdatedAt(t *testing.T) {
	q := newQuotaStore(t)
	ctx := context.Background()
	cred := domain.CredentialID("acct-1")
	w := sampleWindow(contracts.WindowShort, 5, 100, time.Time{})
	w.UpdatedAt = time.Time{} // force the default branch
	if err := q.UpsertWindow(ctx, cred, w); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}
	st, ok, _ := q.Snapshot(ctx, cred)
	if !ok || st.Windows[0].UpdatedAt.IsZero() {
		t.Fatalf("zero UpdatedAt was not stamped: %+v", st.Windows)
	}
}

// TestQuotaStoreRecordAttemptRowsAffectedError covers the tolerated
// RowsAffected-error branch: the write succeeded, so RecordAttempt reports no
// error even when the driver cannot report the affected count.
func TestQuotaStoreRecordAttemptRowsAffectedError(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{failRowsAffected: true}))
	_, err := q.RecordAttempt(context.Background(), contracts.Usage{AttemptKey: "k"}, "ok")
	if err != nil {
		t.Fatalf("RecordAttempt surfaced a RowsAffected error: %v", err)
	}
}

// TestQuotaStoreRecordAttemptZeroRowsAffected covers the n==0 return branch.
func TestQuotaStoreRecordAttemptZeroRowsAffected(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{zeroRowsAffected: true}))
	replaced, err := q.RecordAttempt(context.Background(), contracts.Usage{AttemptKey: "k"}, "ok")
	if err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if !replaced {
		t.Fatal("zero rows affected did not report replaced")
	}
}

// errOf adapts the three-value Snapshot to the single-error assert helper.
func errOf(_ contracts.QuotaState, _ bool, err error) error { return err }
