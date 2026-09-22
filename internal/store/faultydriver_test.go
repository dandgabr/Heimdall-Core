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
}

type faultConnector struct{ cfg faultDriverConfig }

func (c faultConnector) Connect(context.Context) (driver.Conn, error) {
	return &faultConn{cfg: c.cfg}, nil
}
func (c faultConnector) Driver() driver.Driver { return faultDriver{} }

type faultDriver struct{}

func (faultDriver) Open(string) (driver.Conn, error) { return &faultConn{}, nil }

type faultConn struct{ cfg faultDriverConfig }

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
	if c.fails(q) {
		return nil, errInjected
	}
	if c.cfg.failRowsAffected {
		return &errResult{}, nil
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
