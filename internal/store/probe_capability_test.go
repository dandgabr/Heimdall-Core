package store

import (
	"context"
	"path/filepath"
	"testing"
)

// TestProbeFTS5AndVec0 pins the driver capabilities the memory store depends
// on: FTS5 MUST be available (the lexical retrieval is built on it); vec0 is
// probed and only REPORTED — if it ever becomes available, vector retrieval
// should be implemented on top of it (roadmap, SEC-07).
func TestProbeFTS5AndVec0(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	if _, err := s.write.ExecContext(ctx, `CREATE VIRTUAL TABLE probe_fts USING fts5(content, ref UNINDEXED)`); err != nil {
		t.Fatalf("FTS5 is NOT available in the driver: %v", err)
	}
	if _, err := s.write.ExecContext(ctx, `INSERT INTO probe_fts(content, ref) VALUES ('giselda e oDFuchs', 'r1')`); err != nil {
		t.Fatalf("FTS5 insert failed: %v", err)
	}
	rows, err := s.read.QueryContext(ctx, `SELECT ref FROM probe_fts WHERE probe_fts MATCH ?`, `"giselda"`)
	if err != nil {
		t.Fatalf("FTS5 MATCH failed: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if ref == "r1" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if !found {
		t.Fatal("FTS5 MATCH did not find the inserted row")
	}

	if _, err := s.write.ExecContext(ctx, `CREATE VIRTUAL TABLE probe_vec USING vec0(a float[4])`); err != nil {
		t.Logf("vec0 NOT available in modernc driver (roadmap, SEC-07): %v", err)
	} else {
		t.Log("vec0 IS available: vector retrieval can be implemented on it")
	}
}
