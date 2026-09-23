package store

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// MemoryStore is the SQLite persistence of context memory (F4 wave 3,
// ADR-SEC-07). It is a thin primitive layer: it enforces the MANDATORY
// namespace predicate on every statement, the per-namespace dedup (idempotent
// by content hash) and the TTL visibility/purge; it decides no policy — what
// to remember, for how long, and what to inject live in internal/gates/memory.
//
// Vector retrieval is a documented ROADMAP: the modernc driver does not embed
// sqlite-vec (probe test: "no such module: vec0"), so this store persists the
// optional embedding BLOB but offers no vector search; lexical FTS5 is the
// only retrieval surface in v1.
type MemoryStore struct {
	store *Store
}

// NewMemoryStore builds the store over an open vault.
func NewMemoryStore(s *Store) *MemoryStore { return &MemoryStore{store: s} }

// Insert stores one memory row and its FTS index entry in one write
// transaction. The UNIQUE(namespace, content_hash) constraint makes a
// re-delivery idempotent: inserted is false and nothing changes when the same
// (namespace, content) already exists.
func (m *MemoryStore) Insert(ctx context.Context, rec contracts.MemoryRecord) (bool, error) {
	if strings.TrimSpace(rec.Namespace) == "" {
		return false, memoryStoreError("insert", errNamespaceRequired)
	}
	tx, err := m.store.write.BeginTx(ctx, nil)
	if err != nil {
		return false, memoryStoreError("insert begin", err)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO memories
			(id, namespace, content, embedding, provenance, turn_id, content_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, content_hash) DO NOTHING`,
		rec.ID, rec.Namespace, rec.Content, encodeEmbedding(rec.Embedding),
		int(rec.Provenance), rec.TurnID, rec.ContentHash,
		rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		rec.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		_ = tx.Rollback()
		return false, memoryStoreError("insert", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return false, memoryStoreError("insert rows", err)
	}
	if n == 0 {
		// Dedup hit: the row already exists. Nothing to index.
		if err := tx.Commit(); err != nil {
			return false, memoryStoreError("insert commit", err)
		}
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO memories_fts (content, memory_id) VALUES (?, ?)`,
		rec.Content, rec.ID,
	); err != nil {
		_ = tx.Rollback()
		return false, memoryStoreError("insert fts", err)
	}
	if err := tx.Commit(); err != nil {
		return false, memoryStoreError("insert commit", err)
	}
	return true, nil
}

// Search runs the lexical FTS5 retrieval for ONE namespace. The namespace
// predicate and the TTL filter are part of the statement itself (ADR-SEC-07
// §3/§4): an expired row is invisible even before the sweeper purges it, and a
// row of another namespace can never leak. Ordering is FTS5 relevance (bm25,
// lower is better). query is the raw text; matchQuery turns it into a safe
// MATCH expression. An empty query returns no rows.
func (m *MemoryStore) Search(ctx context.Context, namespace, query string, now time.Time, limit int) ([]contracts.MemoryHit, error) {
	if strings.TrimSpace(namespace) == "" {
		return nil, memoryStoreError("search", errNamespaceRequired)
	}
	expr := matchQuery(query)
	if expr == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 1
	}
	rows, err := m.store.read.QueryContext(ctx, `
		SELECT m.id, m.content, m.provenance, m.turn_id, m.created_at, m.expires_at
		FROM memories_fts f
		JOIN memories m ON m.id = f.memory_id
		WHERE memories_fts MATCH ? AND m.namespace = ? AND m.expires_at > ?
		ORDER BY bm25(memories_fts) ASC
		LIMIT ?`,
		expr, namespace, now.UTC().Format(time.RFC3339Nano), limit,
	)
	if err != nil {
		return nil, memoryStoreError("search", err)
	}
	defer rows.Close()

	var hits []contracts.MemoryHit
	for rows.Next() {
		var (
			h                     contracts.MemoryHit
			provenance            int
			createdAt, expiresAt  string
			createdTime, expireTm time.Time
			parseErr              error
		)
		if err := rows.Scan(&h.ID, &h.Content, &provenance, &h.TurnID, &createdAt, &expiresAt); err != nil {
			return nil, memoryStoreError("search scan", err)
		}
		h.Provenance = contracts.MemoryProvenance(provenance)
		if createdTime, parseErr = time.Parse(time.RFC3339Nano, createdAt); parseErr != nil {
			return nil, memoryStoreError("search created_at", parseErr)
		}
		h.CreatedAt = createdTime
		if expireTm, parseErr = time.Parse(time.RFC3339Nano, expiresAt); parseErr != nil {
			return nil, memoryStoreError("search expires_at", parseErr)
		}
		h.ExpiresAt = expireTm
		h.Rank = len(hits)
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return nil, memoryStoreError("search rows", err)
	}
	return hits, nil
}

// PurgeExpired hard-deletes every expired row and its FTS entries in one
// transaction (the background sweep of ADR-SEC-07 §4). It returns the number
// of memory rows removed.
func (m *MemoryStore) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	return m.purgeWhere(ctx, `expires_at < ?`, now.UTC().Format(time.RFC3339Nano))
}

// PurgeNamespace hard-deletes EVERY memory of one namespace and its FTS
// entries in one transaction: the right-to-erasure primitive
// (ADR-SEC-07 §5). It returns the number of memory rows removed.
func (m *MemoryStore) PurgeNamespace(ctx context.Context, namespace string) (int64, error) {
	if strings.TrimSpace(namespace) == "" {
		return 0, memoryStoreError("purge namespace", errNamespaceRequired)
	}
	return m.purgeWhere(ctx, `namespace = ?`, namespace)
}

// purgeWhere deletes the FTS entries first, then the rows, in one transaction.
func (m *MemoryStore) purgeWhere(ctx context.Context, where string, arg any) (int64, error) {
	tx, err := m.store.write.BeginTx(ctx, nil)
	if err != nil {
		return 0, memoryStoreError("purge begin", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM memories_fts WHERE memory_id IN (SELECT id FROM memories WHERE `+where+`)`, arg,
	); err != nil {
		_ = tx.Rollback()
		return 0, memoryStoreError("purge fts", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM memories WHERE `+where, arg)
	if err != nil {
		_ = tx.Rollback()
		return 0, memoryStoreError("purge", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return 0, memoryStoreError("purge rows", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, memoryStoreError("purge commit", err)
	}
	return n, nil
}

// CountNamespace returns how many live rows a namespace holds. It is an audit
// primitive (and the test's idempotency proof), not a retrieval path.
func (m *MemoryStore) CountNamespace(ctx context.Context, namespace string) (int, error) {
	var n int
	err := m.store.read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memories WHERE namespace = ?`, namespace,
	).Scan(&n)
	if err != nil {
		return 0, memoryStoreError("count", err)
	}
	return n, nil
}

// matchQuery builds a safe FTS5 MATCH expression from raw text: every
// whitespace token becomes a quoted phrase (FTS5 syntax from the payload
// cannot break out), quotes are stripped from tokens, and the result is
// bounded (64 tokens). Empty/blank input yields "" (no query).
func matchQuery(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) > 512 {
		text = text[:512]
	}
	fields := strings.Fields(text)
	if len(fields) > 64 {
		fields = fields[:64]
	}
	var b strings.Builder
	for _, f := range fields {
		f = strings.ReplaceAll(f, `"`, "")
		if f == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		b.WriteString(f)
		b.WriteByte('"')
	}
	return b.String()
}

// encodeEmbedding packs a float32 vector as little-endian bytes (the on-disk
// form of the embedding column).
func encodeEmbedding(vec []float32) []byte {
	if len(vec) == 0 {
		return nil
	}
	out := make([]byte, 4*len(vec))
	for i, v := range vec {
		binary.LittleEndian.PutUint32(out[4*i:], math.Float32bits(v))
	}
	return out
}

// errNamespaceRequired is the typed refusal of a namespace-less operation
// (ADR-SEC-07 §3: the predicate is mandatory, never implicit).
var errNamespaceRequired = domain.New(domain.CodeInvalidRequest,
	domain.WithParams(map[string]string{"reason": "memory namespace is mandatory"}),
)

// IsNamespaceRequired reports whether err is the namespace-mandatory refusal.
func IsNamespaceRequired(err error) bool {
	var de *domain.DomainError
	if !errors.As(err, &de) {
		return false
	}
	return de.Code == domain.CodeInvalidRequest &&
		de.Params["reason"] == "memory namespace is mandatory"
}

func memoryStoreError(op string, err error) error {
	if sqlErr, ok := err.(*domain.DomainError); ok {
		return sqlErr
	}
	return domain.New(domain.CodeStoreOpenFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": "memory " + op + ": " + err.Error()}),
	)
}
