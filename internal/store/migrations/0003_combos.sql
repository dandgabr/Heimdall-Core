-- 0003_combos: named, validated routing combos (F3, ADR-0013).
--
-- A combo is a named, persisted route: a policy (one of the strategies of
-- ADR-0009) plus an ordered list of steps. The step body is stored as JSON; the
-- schema version is stored next to it so a newer format is refused fail-closed
-- (ADR-0013 §4) rather than reinterpreted.
--
-- depth is the DERIVED longest chain of combo-refs; it is recomputed on save and
-- stored so a load can reject an over-deep combo without walking the graph.
--
-- Rotation cursor (round-robin/fill-first) is deliberately NOT a column: it is
-- in-memory execution state that resets on restart (ADR-0013 §5). Only the
-- POLICY is durable.
CREATE TABLE IF NOT EXISTS combos (
    name        TEXT PRIMARY KEY,
    schema_ver  INTEGER NOT NULL,
    policy      TEXT NOT NULL,
    body        TEXT NOT NULL,
    depth       INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
