package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// This file provides a minimal fault-injecting database/sql driver so the
// SQL-error branches of the store can be exercised precisely.
//
// Operating on a closed pool (as some tests do) only yields one generic
// "database is closed" error and cannot distinguish statements, nor reach
// branches that sit after an earlier successful statement. A driver that fails
// on a chosen substring, and can return a canned schema_version, is the honest
// way to prove each branch.

// errInjected is the sentinel every injected failure wraps.
var errInjected = errors.New("injected driver failure")

// faultDriverConfig controls the injected behaviour.
type faultDriverConfig struct {
	// failOn fails any query whose text contains this substring ("" = never).
	failOn string
	// schemaVersion is returned for the schema_version SELECT when it does not
	// fail. "" means no row (treated as a brand-new database).
	schemaVersion string
	// failCommit makes every transaction's Commit fail.
	failCommit bool
	// failBegin makes BeginTx fail.
	failBegin bool
	// failRowsAffected makes Exec's result report an error from RowsAffected.
	failRowsAffected bool
	// failRowsNext makes a data-returning query error on the first Next call.
	failRowsNext bool
	// failClose makes Conn.Close report an error.
	failClose bool
	// failPing makes Ping report an error.
	failPing bool
	// zeroRowsAffected makes Exec report that zero rows changed, exercising the
	// "combo not found on update/delete" branch.
	zeroRowsAffected bool
	// combosRow makes a combos SELECT return one valid row, so a caller reaches
	// the code past a successful read (e.g. the RowsAffected==0 update branch).
	combosRow bool
	// combosBadRow makes a combos SELECT return one row whose body is invalid
	// JSON, reaching scanCombo's decode-error branch.
	combosBadRow bool
	// quotaRow makes a quota_windows SELECT return one valid 6-column row.
	quotaRow bool
	// quotaOneColRow makes a quota_windows SELECT return a 1-column row, so the
	// 6-destination scan fails.
	quotaOneColRow bool
	// quotaRowsErr makes a quota_windows SELECT yield one clean row then error,
	// so rows.Err() is non-nil.
	quotaRowsErr bool
	// quotaBadResets makes the quota row carry an unparsable resets_at.
	quotaBadResets bool
	// quotaBadUpdated makes the quota row carry an unparsable updated_at.
	quotaBadUpdated bool
	// usageRow makes a usage_attempts SELECT return one valid 7-column row.
	usageRow bool
	// usageOneColRow makes a usage_attempts SELECT return a 1-column row, so the
	// 7-destination scan fails.
	usageOneColRow bool
	// failNthExec fails the Nth ExecContext call on the connection (1-based),
	// for statement sequences whose texts are indistinguishable by substring
	// (e.g. the memory insert pair).
	failNthExec int
	// memoryRow makes the memory search SELECT return one valid 6-column row.
	memoryRow bool
	// memoryOneColRow makes the memory search SELECT return a 1-column row, so
	// the 6-destination scan fails.
	memoryOneColRow bool
	// memoryBadCreated makes the memory row carry an unparsable created_at.
	memoryBadCreated bool
	// memoryBadExpires makes the memory row carry an unparsable expires_at.
	memoryBadExpires bool
	// memoryRowsErr makes the memory search yield one clean row then error.
	memoryRowsErr bool
}

type faultConnector struct{ cfg faultDriverConfig }

func (c faultConnector) Connect(context.Context) (driver.Conn, error) {
	return &faultConn{cfg: c.cfg}, nil
}
func (c faultConnector) Driver() driver.Driver { return faultDriver{} }

type faultDriver struct{}

func (faultDriver) Open(string) (driver.Conn, error) { return &faultConn{}, nil }

type faultConn struct {
	cfg       faultDriverConfig
	execCount int
}

func (c *faultConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *faultConn) Close() error {
	if c.cfg.failClose {
		return errInjected
	}
	return nil
}
func (c *faultConn) Begin() (driver.Tx, error) { return c.begin() }

func (c *faultConn) begin() (driver.Tx, error) {
	if c.cfg.failBegin {
		return nil, errInjected
	}
	return faultTx{failCommit: c.cfg.failCommit}, nil
}

func (c *faultConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.begin()
}

func (c *faultConn) Ping(context.Context) error {
	if c.cfg.failPing {
		return errInjected
	}
	return nil
}

func (c *faultConn) fails(q string) bool {
	return c.cfg.failOn != "" && strings.Contains(q, c.cfg.failOn)
}

func (c *faultConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	c.execCount++
	if c.fails(q) || (c.cfg.failNthExec > 0 && c.execCount == c.cfg.failNthExec) {
		return nil, errInjected
	}
	if c.cfg.failRowsAffected {
		return &errResult{}, nil
	}
	if c.cfg.zeroRowsAffected {
		return driver.RowsAffected(0), nil
	}
	return driver.RowsAffected(1), nil
}

// errResult is a driver.Result whose RowsAffected reports an error.
type errResult struct{}

func (*errResult) LastInsertId() (int64, error) { return 0, errInjected }
func (*errResult) RowsAffected() (int64, error) { return 0, errInjected }

func (c *faultConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if c.fails(q) {
		return nil, errInjected
	}
	// The schema_version read must succeed for the migration branches to be
	// reached; every other read returns no rows.
	if strings.Contains(q, "FROM meta") && len(args) == 1 {
		if key, ok := args[0].Value.(string); ok && key == SchemaVersionKey {
			if c.cfg.schemaVersion == "" {
				// Simulate a fresh database: the meta table does not exist yet,
				// which schemaVersion recognises by the error text.
				return nil, errors.New("no such table: meta")
			}
			return &oneRow{value: c.cfg.schemaVersion}, nil
		}
	}
	// A credential SELECT gets a scan-compatible 9-column row so a test can
	// reach either the scan error or the rows.Err() error past a valid row.
	if strings.Contains(q, "FROM credentials") {
		if c.cfg.failRowsNext {
			// First row scans cleanly, the next Next() errors -> rows.Err().
			return &credRows{}, nil
		}
		return &oneCredRow{}, nil
	}
	// A combos SELECT gets one valid 7-column row when combosRow is set, so an
	// update can reach the RowsAffected==0 branch. With failRowsNext it yields
	// one clean row then errors, so List reaches the rows.Err() branch.
	if strings.Contains(q, "FROM combos") {
		if c.cfg.failRowsNext {
			return &comboRowsErr{}, nil
		}
		if c.cfg.combosBadRow {
			return &oneComboBadRow{}, nil
		}
		if c.cfg.combosRow {
			return &oneComboRow{}, nil
		}
	}
	// A quota_windows SELECT gets one valid 6-column row so the snapshot paths
	// past a successful scan are reachable.
	if strings.Contains(q, "FROM quota_windows") {
		if c.cfg.quotaRowsErr {
			return &quotaRowsErr{}, nil
		}
		if c.cfg.quotaOneColRow {
			return &oneRow{value: "x"}, nil
		}
		if c.cfg.quotaRow || c.cfg.quotaBadResets || c.cfg.quotaBadUpdated {
			return &oneQuotaRow{badResets: c.cfg.quotaBadResets, badUpdated: c.cfg.quotaBadUpdated}, nil
		}
	}
	// The memory search SELECT gets one 6-column row per the configured knobs,
	// so the scan/parse/rowsErr branches are reachable.
	if strings.Contains(q, "memories_fts MATCH") {
		if c.cfg.memoryRowsErr {
			return &memoryRowsErrRows{}, nil
		}
		if c.cfg.memoryOneColRow {
			return &oneRow{value: "x"}, nil
		}
		if c.cfg.memoryRow || c.cfg.memoryBadCreated || c.cfg.memoryBadExpires {
			return &oneMemoryRow{badCreated: c.cfg.memoryBadCreated, badExpires: c.cfg.memoryBadExpires}, nil
		}
	}
	// A usage_attempts SELECT gets one valid 7-column row for GetAttempt.
	if strings.Contains(q, "FROM usage_attempts") {
		if c.cfg.usageOneColRow {
			return &oneRow{value: "x"}, nil
		}
		if c.cfg.usageRow {
			return &oneUsageRow{}, nil
		}
	}
	return &emptyRows{}, nil
}

// credRows yields one valid 9-column row then errors on the next Next call, so
// scanning succeeds and rows.Err() is non-nil.
type credRows struct{ step int }

func (r *credRows) Columns() []string {
	return []string{"id", "provider", "auth_mode", "label", "meta", "secret_blob", "created_at", "updated_at", "expires_at"}
}
func (r *credRows) Close() error { return nil }
func (r *credRows) Next(dest []driver.Value) error {
	if r.step == 0 {
		r.step++
		for i := range dest {
			dest[i] = ""
		}
		dest[0] = "id-1"    // id
		dest[2] = "api_key" // auth_mode
		return nil
	}
	return errInjected
}

// oneComboRow yields a single valid 7-column combo row.
type oneComboRow struct{ done bool }

func (r *oneComboRow) Columns() []string {
	return []string{"name", "schema_ver", "policy", "body", "depth", "created_at", "updated_at"}
}
func (r *oneComboRow) Close() error { return nil }
func (r *oneComboRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	for i := range dest {
		dest[i] = ""
	}
	dest[0] = "existing"
	dest[1] = int64(2)
	dest[2] = "auto"
	dest[3] = "[]"
	dest[4] = int64(0)
	dest[5] = "2026-01-01T00:00:00Z"
	dest[6] = "2026-01-01T00:00:00Z"
	return nil
}

// oneComboBadRow yields one combo row whose body is invalid JSON.
type oneComboBadRow struct{ done bool }

func (r *oneComboBadRow) Columns() []string {
	return []string{"name", "schema_ver", "policy", "body", "depth", "created_at", "updated_at"}
}
func (r *oneComboBadRow) Close() error { return nil }
func (r *oneComboBadRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	for i := range dest {
		dest[i] = ""
	}
	dest[0] = "bad"
	dest[1] = int64(2)
	dest[2] = "auto"
	dest[3] = "{not json"
	dest[4] = int64(0)
	dest[5] = "2026-01-01T00:00:00Z"
	dest[6] = "2026-01-01T00:00:00Z"
	return nil
}

// comboRowsErr yields one valid combo row then errors on the next Next call, so
// scanning succeeds and rows.Err() is non-nil.
type comboRowsErr struct{ step int }

func (r *comboRowsErr) Columns() []string {
	return []string{"name", "schema_ver", "policy", "body", "depth", "created_at", "updated_at"}
}
func (r *comboRowsErr) Close() error { return nil }
func (r *comboRowsErr) Next(dest []driver.Value) error {
	if r.step == 0 {
		r.step++
		for i := range dest {
			dest[i] = ""
		}
		dest[0] = "existing"
		dest[1] = int64(2)
		dest[2] = "auto"
		dest[3] = "[]"
		dest[4] = int64(0)
		dest[5] = "2026-01-01T00:00:00Z"
		dest[6] = "2026-01-01T00:00:00Z"
		return nil
	}
	return errInjected
}

// oneCredRow yields a single valid credential row.
type oneCredRow struct{ done bool }

func (r *oneCredRow) Columns() []string {
	return []string{"id", "provider", "auth_mode", "label", "meta", "secret_blob", "created_at", "updated_at", "expires_at"}
}
func (r *oneCredRow) Close() error { return nil }
func (r *oneCredRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	for i := range dest {
		dest[i] = ""
	}
	dest[0] = "id-1"
	dest[1] = "z.ai"
	dest[2] = "api_key"
	return nil
}

// oneQuotaRow yields a single valid 6-column quota_windows row. It can carry a
// malformed timestamp to reach the parse-error branches.
type oneQuotaRow struct {
	done       bool
	badResets  bool
	badUpdated bool
}

func (r *oneQuotaRow) Columns() []string {
	return []string{"kind", "used", "limit_value", "resets_at", "source", "updated_at"}
}
func (r *oneQuotaRow) Close() error { return nil }
func (r *oneQuotaRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(0) // short
	dest[1] = 10.0
	dest[2] = 100.0
	if r.badResets {
		dest[3] = "not-a-time"
	} else {
		dest[3] = "2026-09-22T12:00:00Z"
	}
	dest[4] = int64(2)
	if r.badUpdated {
		dest[5] = "not-a-time"
	} else {
		dest[5] = "2026-09-22T12:00:00Z"
	}
	return nil
}

// quotaRowsErr yields one valid quota row then errors on the next Next call.
type quotaRowsErr struct{ step int }

func (r *quotaRowsErr) Columns() []string {
	return []string{"kind", "used", "limit_value", "resets_at", "source", "updated_at"}
}
func (r *quotaRowsErr) Close() error { return nil }
func (r *quotaRowsErr) Next(dest []driver.Value) error {
	if r.step == 0 {
		r.step++
		dest[0] = int64(0)
		dest[1] = 10.0
		dest[2] = 100.0
		dest[3] = ""
		dest[4] = int64(0)
		dest[5] = "2026-09-22T12:00:00Z"
		return nil
	}
	return errInjected
}

// oneUsageRow yields a single valid 7-column usage_attempts row.
type oneUsageRow struct{ done bool }

func (r *oneUsageRow) Columns() []string {
	return []string{"credential_id", "provider_id", "model", "tokens", "requests", "cost_micros", "outcome"}
}
func (r *oneUsageRow) Close() error { return nil }
func (r *oneUsageRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = "acct-1"
	dest[1] = "zai"
	dest[2] = "glm"
	dest[3] = int64(120)
	dest[4] = int64(1)
	dest[5] = int64(7)
	dest[6] = "ok"
	return nil
}

type faultTx struct{ failCommit bool }

func (t faultTx) Commit() error {
	if t.failCommit {
		return errInjected
	}
	return nil
}
func (faultTx) Rollback() error { return nil }

// emptyRows is a zero-column, zero-row result set.
type emptyRows struct{ done bool }

func (r *emptyRows) Columns() []string { return nil }
func (r *emptyRows) Close() error      { return nil }
func (r *emptyRows) Next([]driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	return io.EOF
}

// oneRow yields exactly one row with a single string column.
type oneRow struct {
	value string
	done  bool
}

func (r *oneRow) Columns() []string { return []string{"value"} }
func (r *oneRow) Close() error      { return nil }
func (r *oneRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}

// oneMemoryRow yields a single valid 6-column memories-search row. It can
// carry malformed timestamps to reach the parse-error branches.
type oneMemoryRow struct {
	done       bool
	badCreated bool
	badExpires bool
}

func (r *oneMemoryRow) Columns() []string {
	return []string{"id", "content", "provenance", "turn_id", "created_at", "expires_at"}
}
func (r *oneMemoryRow) Close() error { return nil }
func (r *oneMemoryRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = "m-1"
	dest[1] = "the deploy window is tuesday"
	dest[2] = int64(0)
	dest[3] = "req-1"
	if r.badCreated {
		dest[4] = "not-a-time"
	} else {
		dest[4] = "2026-09-22T12:00:00Z"
	}
	if r.badExpires {
		dest[5] = "not-a-time"
	} else {
		dest[5] = "2026-09-23T12:00:00Z"
	}
	return nil
}

// memoryRowsErrRows yields one valid memory row then errors on the next Next.
type memoryRowsErrRows struct{ step int }

func (r *memoryRowsErrRows) Columns() []string {
	return []string{"id", "content", "provenance", "turn_id", "created_at", "expires_at"}
}
func (r *memoryRowsErrRows) Close() error { return nil }
func (r *memoryRowsErrRows) Next(dest []driver.Value) error {
	if r.step == 0 {
		r.step++
		dest[0] = "m-1"
		dest[1] = "content"
		dest[2] = int64(0)
		dest[3] = "req-1"
		dest[4] = "2026-09-22T12:00:00Z"
		dest[5] = "2026-09-23T12:00:00Z"
		return nil
	}
	return errInjected
}

// faultyDB builds a *sql.DB backed by the fault driver.
func faultyDB(cfg faultDriverConfig) *sql.DB {
	db := sql.OpenDB(faultConnector{cfg: cfg})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db
}

// faultyStore returns a Store whose pools are the fault driver, sharing one DB
// so both the read and write paths hit the same injected rules.
func faultyStore(t *testing.T, cfg faultDriverConfig) *Store {
	t.Helper()
	db := faultyDB(cfg)
	t.Cleanup(func() { _ = db.Close() })
	return &Store{path: ":faulty:", write: db, read: db}
}
