-- 0005_memory: durable context memory (F4 wave 3, ADR-SEC-07).
--
-- Every entry obeys the ADR's strict shape:
--
--   - namespace  : MANDATORY isolation scope, sha256 hex of the client key
--                  (ADR-SEC-07 §3). Every query filters on it; a namespace-less
--                  row cannot exist (NOT NULL) and every search/upsert/purge
--                  carries the WHERE namespace = ? predicate.
--   - content    : redacted memory text (the writer redacts through the central
--                  redactor BEFORE this table ever sees the row).
--   - embedding  : optional vector, float32 little-endian. NULL when the vector
--                  mode is off. Retrieval over it is a ROADMAP: the modernc
--                  driver does not embed sqlite-vec (probe: "no such module:
--                  vec0"), so lexical FTS5 is the only retrieval surface in v1.
--   - provenance : origin of the content (user|assistant|system). Memories are
--                  DATA with a declared origin, never instructions
--                  (anti-poisoning, ADR-SEC-07 §2).
--   - turn_id    : the request that produced the entry (audit trail).
--   - content_hash : dedup key (sha256 of namespace||content). The UNIQUE
--                  constraint makes re-delivery IDEMPOTENT at the storage
--                  layer: the same memory is never stored twice.
--   - created_at / expires_at : the injected-clock instants. TTL is NOT
--                  optional — every row expires (ADR-SEC-07 §4); the sweeper
--                  purges expires_at < now and Search never returns an expired
--                  row even between sweeps.
--
-- memories_fts is a STANDALONE FTS5 index (content duplicated on purpose: the
-- rows are small, local, and the standalone form keeps insert/purge trivially
-- transactional). memory_id is UNINDEXED: it joins back to memories.id and is
-- never matched against.
CREATE TABLE IF NOT EXISTS memories (
    id           TEXT PRIMARY KEY,
    namespace    TEXT NOT NULL,
    content      TEXT NOT NULL,
    embedding    BLOB,
    provenance   INTEGER NOT NULL,
    turn_id      TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    UNIQUE (namespace, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_memories_expires ON memories (expires_at);

CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
    content,
    memory_id UNINDEXED
);
