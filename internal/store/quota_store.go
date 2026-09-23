package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// QuotaStore is the SQLite persistence of durable quota state (ADR-0011 §4):
// the per-credential windows and the idempotent usage-attempt log.
//
// It is deliberately a thin primitive layer: it stores and returns
// contracts.QuotaWindow/QuotaState and applies the idempotent upsert of a
// usage attempt. It does NOT decide policy — the percentage/cutoff decision and
// the window arithmetic live in internal/quota, which owns the state machine.
//
// Concurrency: reads go through the read pool (Snapshot is read in the
// preflight); writes go through the single writer connection. The usage attempt
// upsert is keyed by AttemptKey, so a re-delivered attempt with the same key
// REPLACES its row rather than inserting a second one — that is the idempotency
// the ADR requires and it is enforced by the PRIMARY KEY, not by a read-modify
// write that could race.
type QuotaStore struct {
	store *Store
}

// NewQuotaStore builds the store over an open vault.
func NewQuotaStore(s *Store) *QuotaStore {
	return &QuotaStore{store: s}
}

// quotaStateQuery reads every window of one credential.
const quotaStateQuery = `
	SELECT kind, used, limit_value, resets_at, source, updated_at
	FROM quota_windows WHERE credential_id = ? ORDER BY kind ASC`

// Snapshot returns the persisted state of a credential. ok is false when the
// credential has no recorded window at all (the filter treats that as
// fail-open, ADR-0011 §2.4). A stored terminal marker (if any) is not persisted
// here: quota terminals are unrecoverable plan states and the ADR keeps only the
// windows durable; a caller that needs the terminal reads the breaker.
func (q *QuotaStore) Snapshot(ctx context.Context, cred domain.CredentialID) (contracts.QuotaState, bool, error) {
	rows, err := q.store.read.QueryContext(ctx, quotaStateQuery, string(cred))
	if err != nil {
		return contracts.QuotaState{}, false, quotaStoreError("snapshot", err)
	}
	defer rows.Close()

	state := contracts.QuotaState{Credential: cred}
	for rows.Next() {
		var (
			kind, source           int
			used, limit            float64
			resetsAt, updatedAt    sql.NullString
			window                 contracts.QuotaWindow
			resetTime, updatedTime time.Time
			parseErr               error
		)
		if err := rows.Scan(&kind, &used, &limit, &resetsAt, &source, &updatedAt); err != nil {
			return contracts.QuotaState{}, false, quotaStoreError("snapshot scan", err)
		}
		window.Kind = contracts.WindowKind(kind)
		window.Used = used
		window.Limit = limit
		window.Source = contracts.QuotaSource(source)
		if resetsAt.Valid && resetsAt.String != "" {
			if resetTime, parseErr = time.Parse(time.RFC3339Nano, resetsAt.String); parseErr != nil {
				return contracts.QuotaState{}, false, quotaStoreError("snapshot resets_at", parseErr)
			}
			window.ResetsAt = resetTime
		}
		if updatedAt.Valid && updatedAt.String != "" {
			if updatedTime, parseErr = time.Parse(time.RFC3339Nano, updatedAt.String); parseErr != nil {
				return contracts.QuotaState{}, false, quotaStoreError("snapshot updated_at", parseErr)
			}
			window.UpdatedAt = updatedTime
		}
		state.Windows = append(state.Windows, window)
	}
	if err := rows.Err(); err != nil {
		return contracts.QuotaState{}, false, quotaStoreError("snapshot rows", err)
	}
	if len(state.Windows) == 0 {
		return contracts.QuotaState{}, false, nil
	}
	return state, true, nil
}

// UpsertWindow writes ONE window idempotently. It is the durable half of what
// the in-memory recorder computes: the caller (internal/quota) has already
// applied the window arithmetic; this just persists the result under the
// (credential, kind) primary key.
func (q *QuotaStore) UpsertWindow(ctx context.Context, cred domain.CredentialID, w contracts.QuotaWindow) error {
	var resetsAt any
	if !w.ResetsAt.IsZero() {
		resetsAt = w.ResetsAt.UTC().Format(time.RFC3339Nano)
	}
	updated := w.UpdatedAt
	if updated.IsZero() {
		updated = time.Now().UTC()
	}
	_, err := q.store.write.ExecContext(ctx, `
		INSERT INTO quota_windows
			(credential_id, kind, used, limit_value, resets_at, source, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(credential_id, kind) DO UPDATE SET
			used = excluded.used,
			limit_value = excluded.limit_value,
			resets_at = excluded.resets_at,
			source = excluded.source,
			updated_at = excluded.updated_at`,
		string(cred), int(w.Kind), w.Used, w.Limit, resetsAt, int(w.Source),
		updated.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return quotaStoreError("upsert window", err)
	}
	return nil
}

// RecordAttempt inserts (or REPLACES) the usage row for one attempt, keyed by
// its deterministic AttemptKey. The ON CONFLICT DO UPDATE is what makes a
// re-delivery idempotent: the same key updates in place, so tokens are never
// double-counted. The window totals are NOT recomputed here — internal/quota
// owns that arithmetic and calls UpsertWindow with the resulting absolute
// values, so a replay of the same attempt converges to the same window.
func (q *QuotaStore) RecordAttempt(ctx context.Context, u contracts.Usage, outcome string) (replaced bool, err error) {
	now := time.Now().UTC()
	res, err := q.store.write.ExecContext(ctx, `
		INSERT INTO usage_attempts
			(attempt_key, credential_id, provider_id, model, tokens, requests, cost_micros, outcome, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(attempt_key) DO UPDATE SET
			credential_id = excluded.credential_id,
			provider_id = excluded.provider_id,
			model = excluded.model,
			tokens = excluded.tokens,
			requests = excluded.requests,
			cost_micros = excluded.cost_micros,
			outcome = excluded.outcome`,
		u.AttemptKey, string(u.Credential), string(u.Provider), string(u.Model),
		u.Tokens, u.Requests, u.CostMicros, outcome, now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return false, quotaStoreError("record attempt", err)
	}
	// RowsAffected is 1 for both a fresh insert and an update in SQLite, so it
	// cannot distinguish replace from insert. The caller already treats the API
	// as idempotent (ADR-0011 §4) and does not branch on this value; it is
	// returned for observability only and a RowsAffected error is tolerated.
	n, rowsErr := res.RowsAffected()
	if rowsErr != nil {
		return false, nil
	}
	return n == 0, nil
}

// GetAttempt reads one usage attempt by key. found is false when the key is
// absent. It exists so a test (and an operator audit) can PROVE idempotency:
// after two records of the same key exactly one row exists with the second
// value.
func (q *QuotaStore) GetAttempt(ctx context.Context, key string) (contracts.Usage, bool, error) {
	var (
		cred, provider, model, outcome string
		tokens, requests               int
		costMicros                     int64
	)
	row := q.store.read.QueryRowContext(ctx, `
		SELECT credential_id, provider_id, model, tokens, requests, cost_micros, outcome
		FROM usage_attempts WHERE attempt_key = ?`, key)
	err := row.Scan(&cred, &provider, &model, &tokens, &requests, &costMicros, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.Usage{}, false, nil
	}
	if err != nil {
		return contracts.Usage{}, false, quotaStoreError("get attempt", err)
	}
	return contracts.Usage{
		AttemptKey: key,
		Credential: domain.CredentialID(cred),
		Provider:   domain.ProviderID(provider),
		Model:      domain.ModelID(model),
		Tokens:     tokens,
		Requests:   requests,
		CostMicros: costMicros,
	}, true, nil
}

func quotaStoreError(op string, err error) error {
	return domain.New(domain.CodeStoreOpenFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": "quota " + op + ": " + err.Error()}),
	)
}

// UsageRollup is one aggregate row over the durable usage-attempt log. Key is
// the grouping value ("total", a provider id or a credential id). It carries
// only numbers — never a secret.
type UsageRollup struct {
	Key        string
	Tokens     int64
	Requests   int64
	CostMicros int64
	Attempts   int64
}

// AggregateUsage rolls the durable usage-attempt log up into the total plus
// per-provider and per-credential sums, on READ. There is deliberately no
// materialized rollup table: the attempt log is small, local and idempotent by
// AttemptKey (ADR-0011 §4), so summing on demand keeps one source of truth and
// avoids a second thing to keep consistent. The management API documents that
// this is a scan, not a live counter.
//
// Rows are ordered by key so the response is deterministic. An empty log
// returns a zero total and empty (non-nil) slices, never an error.
func (q *QuotaStore) AggregateUsage(ctx context.Context) (UsageRollup, []UsageRollup, []UsageRollup, error) {
	total, err := q.usageTotal(ctx)
	if err != nil {
		return UsageRollup{}, nil, nil, err
	}
	byProvider, err := q.usageGrouped(ctx, "provider_id")
	if err != nil {
		return UsageRollup{}, nil, nil, err
	}
	byCred, err := q.usageGrouped(ctx, "credential_id")
	if err != nil {
		return UsageRollup{}, nil, nil, err
	}
	return total, byProvider, byCred, nil
}

func (q *QuotaStore) usageTotal(ctx context.Context) (UsageRollup, error) {
	row := q.store.read.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(tokens), 0), COALESCE(SUM(requests), 0),
		       COALESCE(SUM(cost_micros), 0), COUNT(*)
		FROM usage_attempts`)
	var r UsageRollup
	r.Key = "total"
	if err := row.Scan(&r.Tokens, &r.Requests, &r.CostMicros, &r.Attempts); err != nil {
		return UsageRollup{}, quotaStoreError("usage total", err)
	}
	return r, nil
}

// usageGrouped runs the GROUP BY over one column. column is a trusted literal
// chosen by the caller (never user input), so it is safe to interpolate.
func (q *QuotaStore) usageGrouped(ctx context.Context, column string) ([]UsageRollup, error) {
	rows, err := q.store.read.QueryContext(ctx, `
		SELECT `+column+`, COALESCE(SUM(tokens), 0), COALESCE(SUM(requests), 0),
		       COALESCE(SUM(cost_micros), 0), COUNT(*)
		FROM usage_attempts GROUP BY `+column+` ORDER BY `+column+` ASC`)
	if err != nil {
		return nil, quotaStoreError("usage group", err)
	}
	defer rows.Close()

	out := []UsageRollup{}
	for rows.Next() {
		var r UsageRollup
		if err := rows.Scan(&r.Key, &r.Tokens, &r.Requests, &r.CostMicros, &r.Attempts); err != nil {
			return nil, quotaStoreError("usage group scan", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, quotaStoreError("usage group rows", err)
	}
	return out, nil
}
