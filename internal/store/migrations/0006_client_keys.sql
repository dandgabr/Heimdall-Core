-- 0006_client_keys: downstream client keys for the inference gateway (F5.1,
-- ADR-SEC-06 §2).
--
-- A client key authenticates a NON-OPERATOR consumer of POST /v1/*. It is a
-- different credential class from the management token and must never be
-- interchangeable with it (separation of privilege, ADR-SEC-06 §2.1).
--
--   - key_hash : the SHA-256 hex of the presented key. The PLAINTEXT key is
--                shown once at creation and never persisted (hash-only, exactly
--                like the management token). Verification compares the presented
--                key's hash in constant time.
--   - revoked_at : the revocation instant, or '' for a live key. A soft delete
--                keeps the audit trail (who was revoked and when) instead of
--                losing the row; a revoked key fails authentication.
--   - UNIQUE(key_hash) : a hash identifies exactly one key, so a lookup by hash
--                is unambiguous and a collision could never silently grant the
--                wrong identity.
--   - rate_limit_rate / rate_limit_interval : per-key throttle overrides,
--                reserved for the F5 accounting layer. 0 means "use the global
--                gate configuration".
CREATE TABLE IF NOT EXISTS client_keys (
    id                  TEXT PRIMARY KEY,
    label               TEXT NOT NULL DEFAULT '',
    key_hash            TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL,
    revoked_at          TEXT NOT NULL DEFAULT '',
    rate_limit_rate     INTEGER NOT NULL DEFAULT 0,
    rate_limit_interval TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_client_keys_hash ON client_keys (key_hash);
