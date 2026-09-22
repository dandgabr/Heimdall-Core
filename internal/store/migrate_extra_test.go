package store

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fstestMap builds an in-memory FS whose files all live under migrations/.
func fstestMap(files map[string]string) fstest.MapFS {
	m := make(fstest.MapFS, len(files))
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func tempDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "heimdall.db")
}

func writeFileAt(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func mkdirAt(path string) error {
	return os.Mkdir(path, 0o700)
}

// mkfifo creates a named pipe for the non-regular-file test.
func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0o600)
}

// TestMigrateErrorTyped covers the migrateError helper (0% before).
func TestMigrateErrorTyped(t *testing.T) {
	err := migrateError(migration{version: 3, name: "0003_x.sql"}, errStub{})
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeStoreMigrateFailed {
		t.Fatalf("migrateError = %v", err)
	}
	if !strings.Contains(de.Params["reason"], "0003_x.sql") {
		t.Errorf("reason = %q, want the migration name", de.Params["reason"])
	}
}

type errStub struct{}

func (errStub) Error() string { return "boom" }

// TestMigrateFromAppliesAndIsIdempotent drives migrateFrom with a synthetic FS
// so the apply loop and the "already applied" branch are exercised on known
// input, independent of the embedded files.
func TestMigrateFromAppliesAndIsIdempotent(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")

	// Reset the recorded version so the synthetic migrations apply cleanly.
	if _, err := st.write.Exec(`UPDATE meta SET value = '0' WHERE key = ?`, SchemaVersionKey); err != nil {
		t.Fatalf("reset: %v", err)
	}

	fsys := fstestMap(map[string]string{
		"migrations/0001_init.sql": `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
		"migrations/0002_add.sql":  `CREATE TABLE IF NOT EXISTS probe_tbl (id TEXT PRIMARY KEY);`,
	})
	if err := st.migrateFrom(fsys); err != nil {
		t.Fatalf("migrateFrom: %v", err)
	}
	if v, _, _ := st.GetMeta(SchemaVersionKey); v != "2" {
		t.Errorf("schema_version = %q, want 2", v)
	}
	// Second run: both steps are already applied, nothing re-runs.
	if err := st.migrateFrom(fsys); err != nil {
		t.Fatalf("second migrateFrom: %v", err)
	}
}

// TestMigrateFromBadSQLFailsClosed covers the transaction-rollback branch: a
// malformed statement must fail and leave the version unchanged.
func TestMigrateFromBadSQLFailsClosed(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	before, _, _ := st.GetMeta(SchemaVersionKey)

	fsys := fstestMap(map[string]string{
		"migrations/0009_bad.sql": `THIS IS NOT SQL;`,
	})
	err := st.migrateFrom(fsys)
	if err == nil {
		t.Fatal("bad SQL accepted")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeStoreMigrateFailed {
		t.Fatalf("err = %v, want store.migrate_failed", err)
	}
	if after, _, _ := st.GetMeta(SchemaVersionKey); after != before {
		t.Errorf("schema_version advanced despite a failed migration: %q -> %q", before, after)
	}
}

// TestLoadMigrationsRejectsBadName covers the malformed-filename branch.
func TestLoadMigrationsRejectsBadName(t *testing.T) {
	fsys := fstestMap(map[string]string{
		"migrations/nounderscore.sql": `SELECT 1;`,
	})
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("migration without a numeric prefix accepted")
	}
}

// TestLoadMigrationsRejectsNonNumericPrefix covers the Atoi-error branch.
func TestLoadMigrationsRejectsNonNumericPrefix(t *testing.T) {
	fsys := fstestMap(map[string]string{
		"migrations/abc_init.sql": `SELECT 1;`,
	})
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("non-numeric migration version accepted")
	}
}

// TestLoadMigrationsRejectsDuplicateVersion covers the duplicate-version branch.
func TestLoadMigrationsRejectsDuplicateVersion(t *testing.T) {
	fsys := fstestMap(map[string]string{
		"migrations/0001_a.sql": `SELECT 1;`,
		"migrations/0001_b.sql": `SELECT 1;`,
	})
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("duplicate migration version accepted")
	}
}

// TestLoadMigrationsReadDirError covers the ReadDir error branch (no migrations
// directory).
func TestLoadMigrationsReadDirError(t *testing.T) {
	if _, err := loadMigrations(fstestMap(map[string]string{})); err == nil {
		t.Fatal("missing migrations directory accepted")
	}
}

// readingDirFS lists files but fails to open them, so loadMigrations'
// ReadFile-error branch is reachable.
type readingDirFS struct{ fstest.MapFS }

func (readingDirFS) ReadFile(string) ([]byte, error) { return nil, os.ErrPermission }

// TestLoadMigrationsReadFileError covers the per-migration read error.
func TestLoadMigrationsReadFileError(t *testing.T) {
	fsys := readingDirFS{fstest.MapFS{
		"migrations/0001_init.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	}}
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("read-file failure accepted")
	}
}

// TestLoadMigrationsIsOrderedAndValid covers the embedded loader directly:
// versions must be ascending and unique.
func TestLoadMigrationsIsOrderedAndValid(t *testing.T) {
	steps, err := loadMigrations(migrationsFS)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(steps) < 2 {
		t.Fatalf("expected at least 2 migrations, got %d", len(steps))
	}
	for i, m := range steps {
		if m.version != i+1 {
			t.Errorf("step %d has version %d, want %d", i, m.version, i+1)
		}
		if strings.TrimSpace(m.sql) == "" {
			t.Errorf("step %d (%s) is empty", i, m.name)
		}
	}
}

// TestSchemaVersionRejectsGarbage covers the Atoi-error branch by writing a
// non-numeric schema_version after a normal open.
func TestSchemaVersionRejectsGarbage(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	if _, err := st.write.Exec(`UPDATE meta SET value = 'not-a-number' WHERE key = ?`, SchemaVersionKey); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := st.schemaVersion(); err == nil {
		t.Fatal("non-numeric schema_version accepted")
	}
}

// TestMigrateAfterVersionReset re-runs Migrate against a database whose version
// was reset, exercising the apply loop again (idempotence preserved).
func TestMigrateAfterVersionReset(t *testing.T) {
	st, _, _ := newTestVault(t, tempDB(t), "material")
	// Reset the recorded version to 0 so Migrate reapplies every step.
	if _, err := st.write.Exec(`UPDATE meta SET value = '0' WHERE key = ?`, SchemaVersionKey); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := st.Migrate(); err != nil {
		t.Fatalf("re-Migrate: %v", err)
	}
	if v, _, _ := st.GetMeta(SchemaVersionKey); v == "0" {
		t.Error("Migrate did not advance the schema version")
	}
}

// TestOpenOnNonDirectoryParentFails covers the ensurePermissions MkdirAll error
// branch: a parent path that is a FILE cannot be a directory.
func TestOpenOnNonDirectoryParentFails(t *testing.T) {
	base := t.TempDir()
	filePath := base + "/a-file"
	if err := writeFileAt(filePath, "x"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Put the database "inside" the file.
	if _, err := Open(filePath + "/heimdall.db"); err == nil {
		t.Fatal("database under a file path accepted")
	}
}

// TestOpenRejectsExistingNonRegular covers the non-regular-file branch: a path
// that is a directory must be refused.
func TestOpenRejectsDirectoryPath(t *testing.T) {
	base := t.TempDir()
	dirPath := base + "/as-dir"
	if err := mkdirAt(dirPath); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// A directory already exists at the path; O_EXCL fails with EEXIST and the
	// IsRegular check must reject it.
	_, err := Open(dirPath)
	if err == nil {
		t.Fatal("directory path accepted as a database")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeStoreOpenFailed {
		t.Fatalf("err = %v, want store.open_failed", err)
	}
}
