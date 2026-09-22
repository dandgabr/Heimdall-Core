-- 0002_credentials: the credential vault (F1, ADR-0001/ADR-SEC-01).
--
-- secret_blob holds ONLY the enc:v1 envelope produced by internal/secret.Seal.
-- Plaintext never reaches this table. The column is TEXT because the format is
-- a colon-separated base64 string, not a binary blob; keeping it text makes a
-- leaked row obviously opaque and greppable in the "no plaintext" test.
CREATE TABLE IF NOT EXISTS credentials (
    id          TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    auth_mode   TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    meta        TEXT NOT NULL DEFAULT '{}',
    secret_blob TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL DEFAULT ''
);

-- Lookup by family for per-provider listing and wildcard routing.
CREATE INDEX IF NOT EXISTS idx_credentials_provider ON credentials (provider);

-- NOTE: an earlier draft created a `credential_state` table here for
-- cooldown/quota state. It was never read or written by any Go code, so it was
-- removed rather than left as dead schema. Cooldown/quota persistence is F3
-- (`Dispatcher`/`Breaker`/`QuotaFilter`); when it lands it will add its own
-- migration with the shape the breaker actually needs, instead of a speculative
-- table that would have to be migrated away from.
