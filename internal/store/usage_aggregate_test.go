package store

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestAggregateUsageEmpty proves an empty log returns a zero total and empty
// (non-nil) group slices, never an error.
func TestAggregateUsageEmpty(t *testing.T) {
	q := newQuotaStore(t)
	total, byProvider, byCred, err := q.AggregateUsage(context.Background())
	if err != nil {
		t.Fatalf("AggregateUsage: %v", err)
	}
	if total.Key != "total" || total.Tokens != 0 || total.Attempts != 0 {
		t.Fatalf("total = %+v", total)
	}
	if byProvider == nil || byCred == nil {
		t.Fatal("group slices must be non-nil")
	}
	if len(byProvider) != 0 || len(byCred) != 0 {
		t.Fatalf("groups = %v %v", byProvider, byCred)
	}
}

// TestAggregateUsageRollsUp records a few attempts and checks the totals and
// per-key groups, including idempotency (a re-recorded key does not double
// count).
func TestAggregateUsageRollsUp(t *testing.T) {
	q := newQuotaStore(t)
	ctx := context.Background()

	attempts := []contracts.Usage{
		{AttemptKey: "r1:c1:0", Provider: "z.ai", Credential: "c1", Model: "m", Tokens: 100, Requests: 1, CostMicros: 10},
		{AttemptKey: "r2:c1:0", Provider: "z.ai", Credential: "c1", Model: "m", Tokens: 50, Requests: 1, CostMicros: 5},
		{AttemptKey: "r3:c2:0", Provider: "other", Credential: "c2", Model: "m", Tokens: 25, Requests: 2, CostMicros: 3},
	}
	for _, u := range attempts {
		if _, err := q.RecordAttempt(ctx, u, "ok"); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
	}
	// Re-record the first attempt (idempotent): totals must not move.
	if _, err := q.RecordAttempt(ctx, attempts[0], "ok"); err != nil {
		t.Fatalf("re-record: %v", err)
	}

	total, byProvider, byCred, err := q.AggregateUsage(ctx)
	if err != nil {
		t.Fatalf("AggregateUsage: %v", err)
	}
	if total.Tokens != 175 || total.Requests != 4 || total.CostMicros != 18 || total.Attempts != 3 {
		t.Fatalf("total = %+v", total)
	}
	// Providers are ordered by key: "other" < "z.ai".
	if len(byProvider) != 2 || byProvider[0].Key != "other" || byProvider[1].Key != "z.ai" {
		t.Fatalf("byProvider = %+v", byProvider)
	}
	if byProvider[1].Tokens != 150 || byProvider[1].Attempts != 2 {
		t.Fatalf("z.ai group = %+v", byProvider[1])
	}
	if len(byCred) != 2 || byCred[0].Key != "c1" || byCred[0].Tokens != 150 {
		t.Fatalf("byCred = %+v", byCred)
	}
}

// TestAggregateUsageSQLFailures covers each error branch with the fault driver.
func TestAggregateUsageSQLFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("total query", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{failOn: "COUNT(*)"}))
		_, _, _, err := q.AggregateUsage(ctx)
		assertInjected(t, err, domain.CodeStoreOpenFailed)
	})
	t.Run("group query", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{failOn: "GROUP BY"}))
		_, _, _, err := q.AggregateUsage(ctx)
		assertInjected(t, err, domain.CodeStoreOpenFailed)
	})
	t.Run("group scan", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageAggTotal: true, usageAggGroupOneCol: true}))
		_, _, _, err := q.AggregateUsage(ctx)
		if err == nil {
			t.Fatal("group scan tolerated a short row")
		}
	})
	t.Run("group rows err", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageAggTotal: true, usageAggRowsErr: true}))
		_, _, _, err := q.AggregateUsage(ctx)
		if err == nil {
			t.Fatal("group rows.Err swallowed")
		}
	})
	t.Run("second group query error", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageAggTotal: true, usageAggSecondGroupErr: true}))
		_, _, _, err := q.AggregateUsage(ctx)
		if err == nil {
			t.Fatal("by-credential group error swallowed")
		}
	})
	t.Run("total scan short", func(t *testing.T) {
		q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageAggOneColRow: true}))
		_, _, _, err := q.AggregateUsage(ctx)
		if err == nil {
			t.Fatal("total scan tolerated a short row")
		}
	})
}

// TestAggregateUsageFaultDriverSuccess covers the successful scan paths over the
// fault driver, complementing the real-vault round trip.
func TestAggregateUsageFaultDriverSuccess(t *testing.T) {
	q := NewQuotaStore(faultyStore(t, faultDriverConfig{usageAggTotal: true, usageAggGroup: true}))
	total, byProvider, byCred, err := q.AggregateUsage(context.Background())
	if err != nil {
		t.Fatalf("AggregateUsage: %v", err)
	}
	if total.Tokens != 300 || total.Attempts != 3 {
		t.Fatalf("total = %+v", total)
	}
	if len(byProvider) != 1 || byProvider[0].Key != "z.ai" || byProvider[0].Tokens != 300 {
		t.Fatalf("byProvider = %+v", byProvider)
	}
	if len(byCred) != 1 || byCred[0].Key != "z.ai" {
		t.Fatalf("byCred = %+v", byCred)
	}
}
