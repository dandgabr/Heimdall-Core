package store

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migration is one embedded schema step.
type migration struct {
	version int
	name    string
	sql     string
}

// Migrate applies every embedded migration newer than the recorded
// schema_version. Each step runs in its own transaction, so a failure leaves
// the database at the last good version rather than half-migrated.
func (s *Store) Migrate() error {
	return s.migrateFrom(migrationsFS)
}

// migrateFrom is Migrate with an injectable migration source. Production passes
// the embedded FS; a test passes an fs.FS so the malformed-name, duplicate-
// version and bad-SQL branches are reachable without shipping bad SQL.
func (s *Store) migrateFrom(fsys fs.FS) error {
	current, err := s.schemaVersion()
	if err != nil {
		return err
	}
	steps, err := loadMigrations(fsys)
	if err != nil {
		return err
	}

	for _, m := range steps {
		if m.version <= current {
			continue
		}
		tx, err := s.write.Begin()
		if err != nil {
			return migrateError(m, err)
		}
		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return migrateError(m, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO meta (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			SchemaVersionKey, strconv.Itoa(m.version),
		); err != nil {
			_ = tx.Rollback()
			return migrateError(m, err)
		}
		if err := tx.Commit(); err != nil {
			return migrateError(m, err)
		}
	}
	return nil
}

// schemaVersion reads the applied version, treating a missing meta table (a
// brand-new file) as version 0.
func (s *Store) schemaVersion() (int, error) {
	var raw string
	err := s.write.QueryRow(`SELECT value FROM meta WHERE key = ?`, SchemaVersionKey).Scan(&raw)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, domain.New(domain.CodeStoreMigrateFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot read schema_version"}),
		)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, domain.New(domain.CodeStoreMigrateFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "invalid schema_version " + raw}),
		)
	}
	return n, nil
}

// loadMigrations reads and orders the migration files under migrations/. The
// numeric prefix of the filename is the version; a malformed name is an error,
// not a silent skip.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, domain.New(domain.CodeStoreMigrateFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot list migrations"}))
	}

	var out []migration
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		idx := strings.IndexByte(base, '_')
		if idx <= 0 {
			return nil, domain.New(domain.CodeStoreMigrateFailed,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": "bad migration name " + e.Name()}))
		}
		version, err := strconv.Atoi(base[:idx])
		if err != nil {
			return nil, domain.New(domain.CodeStoreMigrateFailed,
				domain.WithHTTPStatus(500), domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "bad migration version " + e.Name()}))
		}
		body, err := fs.ReadFile(fsys, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, domain.New(domain.CodeStoreMigrateFailed,
				domain.WithHTTPStatus(500), domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "cannot read " + e.Name()}))
		}
		out = append(out, migration{version: version, name: e.Name(), sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, domain.New(domain.CodeStoreMigrateFailed,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{
					"reason": fmt.Sprintf("duplicate migration version %d", out[i].version),
				}))
		}
	}
	return out, nil
}

func migrateError(m migration, err error) error {
	return domain.New(domain.CodeStoreMigrateFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": m.name + ": " + err.Error()}),
	)
}
