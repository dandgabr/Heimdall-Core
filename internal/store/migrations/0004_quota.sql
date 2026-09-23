-- 0004_quota: durable per-credential quota state (F3, ADR-0011 §4).
--
-- Quota is NOT a gate: the QuotaFilter (preflight) reads this state and the
-- UsageRecorder (observer) writes it. Two facts are DURABLE because forgetting
-- them would overspend the operator's plan after a restart:
--
--   - quota_windows: the consumed amount and the window's ResetsAt per
--     (credential, kind). Losing the spent short window on a reboot is exactly
--     the silent overspend the ADR forbids.
--   - usage_attempts: one row per attempt, keyed by the deterministic
--     AttemptKey, which is the IDEMPOTENCY key. A re-delivery (or an aborted
--     stream replacing a full one) upserts by key, so it never double-counts.
--
-- What is NOT here, deliberately:
--   - the breaker (ADR-0012 §6) is IN-MEMORY: a transient outage costs a few
--     attempts to reopen and a healthy provider recovers immediately. Only a
--     CREDENTIAL terminal may later be mirrored to `credentials`.
--   - per-credential in-flight pressure (p2c) is ephemeral process state.
--
-- limit_value = 0 means the upstream limit is UNKNOWN; the filter fail-opens on
-- that window and the counter is for observability only (ADR-0011 §2.4).
-- resets_at NULL means unknown; a Retry-After/reset hint re-anchors it.
CREATE TABLE IF NOT EXISTS quota_windows (
    credential_id TEXT NOT NULL,
    kind          INTEGER NOT NULL,   -- short|long|cost
    used          REAL NOT NULL,
    limit_value   REAL NOT NULL,      -- 0 = desconhecido
    resets_at     TEXT,               -- RFC3339, NULL = desconhecido
    source        INTEGER NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (credential_id, kind)
);

CREATE TABLE IF NOT EXISTS usage_attempts (
    attempt_key   TEXT PRIMARY KEY,   -- idempotência
    credential_id TEXT NOT NULL,
    provider_id   TEXT NOT NULL,
    model         TEXT NOT NULL,
    tokens        INTEGER NOT NULL,
    requests      INTEGER NOT NULL,
    cost_micros   INTEGER NOT NULL,
    outcome       TEXT NOT NULL,      -- ok|error|aborted
    created_at    TEXT NOT NULL
);

-- The snapshot reads every window of one credential; the PK already covers it.
-- This index serves the audit path that lists attempts per credential.
CREATE INDEX IF NOT EXISTS idx_usage_attempts_credential
    ON usage_attempts (credential_id);
