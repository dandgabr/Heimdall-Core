package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// withVaultFS swaps the vault filesystem seams for the duration of fn and
// restores them, so a test can inject OS failures the host will not produce.
func withVaultFS(t *testing.T, fs vaultFS, fn func()) {
	t.Helper()
	old := vaultFileOps
	vaultFileOps = fs
	t.Cleanup(func() { vaultFileOps = old })
	fn()
	vaultFileOps = old
}

// TestEnsurePermissionsMkdirError covers the MkdirAll failure branch.
func TestEnsurePermissionsMkdirError(t *testing.T) {
	fs := defaultVaultFS
	fs.MkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	withVaultFS(t, fs, func() {
		err := ensurePermissions("/some/dir/heimdall.db")
		if err == nil {
			t.Fatal("mkdir failure accepted")
		}
		if de := toDomain(t, err); de.Code != domain.CodeStoreOpenFailed {
			t.Fatalf("code = %q", de.Code)
		}
	})
}

// TestEnsurePermissionsDirStatError covers the directory stat failure branch.
func TestEnsurePermissionsDirStatError(t *testing.T) {
	fs := defaultVaultFS
	fs.MkdirAll = func(string, os.FileMode) error { return nil }
	fs.Stat = func(string) (os.FileInfo, error) { return nil, errors.New("stat denied") }
	withVaultFS(t, fs, func() {
		if err := ensurePermissions("/some/dir/heimdall.db"); err == nil {
			t.Fatal("dir stat failure accepted")
		}
	})
}

// TestEnsurePermissionsFileStatError covers the file stat failure after an
// EEXIST open.
func TestEnsurePermissionsFileStatError(t *testing.T) {
	fs := defaultVaultFS
	fs.MkdirAll = func(string, os.FileMode) error { return nil }
	// The directory stat succeeds with a benign mode; the file stat fails.
	fs.Stat = func(path string) (os.FileInfo, error) {
		if dirLike(path) {
			return fakeFileInfo{mode: os.ModeDir | 0o700}, nil
		}
		return nil, errors.New("file stat denied")
	}
	fs.OpenFile = func(string, int, os.FileMode) (*os.File, error) {
		// Simulate an existing file: return the EEXIST sentinel shape.
		return nil, &os.PathError{Op: "open", Err: os.ErrExist}
	}
	fs.IsExist = func(error) bool { return true }
	withVaultFS(t, fs, func() {
		if err := ensurePermissions("/d/heimdall.db"); err == nil {
			t.Fatal("file stat failure accepted")
		}
	})
}

// TestEnsurePermissionsOpenFileError covers the non-EEXIST open failure.
func TestEnsurePermissionsOpenFileError(t *testing.T) {
	fs := defaultVaultFS
	fs.MkdirAll = func(string, os.FileMode) error { return nil }
	fs.Stat = func(string) (os.FileInfo, error) { return fakeFileInfo{mode: os.ModeDir | 0o700}, nil }
	fs.OpenFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("open denied")
	}
	fs.IsExist = func(error) bool { return false }
	withVaultFS(t, fs, func() {
		if err := ensurePermissions("/d/heimdall.db"); err == nil {
			t.Fatal("open failure accepted")
		}
	})
}

// TestEnsurePermissionsRejectsNonRegular covers the non-regular-file branch with
// an existing path whose mode is not regular.
func TestEnsurePermissionsRejectsNonRegular(t *testing.T) {
	fs := defaultVaultFS
	fs.MkdirAll = func(string, os.FileMode) error { return nil }
	fs.OpenFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Err: os.ErrExist}
	}
	fs.IsExist = func(error) bool { return true }
	fs.Stat = func(path string) (os.FileInfo, error) {
		if dirLike(path) {
			return fakeFileInfo{mode: os.ModeDir | 0o700}, nil
		}
		return fakeFileInfo{mode: os.ModeNamedPipe | 0o600}, nil
	}
	withVaultFS(t, fs, func() {
		err := ensurePermissions("/d/heimdall.db")
		if err == nil {
			t.Fatal("non-regular file accepted")
		}
	})
}

// fakeFileInfo is a minimal os.FileInfo for the injected stat results.
type fakeFileInfo struct {
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// dirLike reports whether a path is the directory component of the test path.
func dirLike(path string) bool { return path == "/d" || path == "/some/dir" }

// withSQLOpen swaps the sql.Open seam for fn, restoring it after.
func withSQLOpen(t *testing.T, fn func(name, dsn string) (*sql.DB, error), body func()) {
	t.Helper()
	old := sqlOpen
	sqlOpen = fn
	t.Cleanup(func() { sqlOpen = old })
	body()
	sqlOpen = old
}

// TestOpenWriteHandleError covers Open's first (write-pool) sql.Open error.
func TestOpenWriteHandleError(t *testing.T) {
	withSQLOpen(t, func(string, string) (*sql.DB, error) { return nil, errors.New("write open denied") },
		func() {
			if _, err := Open(tempDB(t)); err == nil {
				t.Fatal("Open succeeded when the write handle failed")
			}
		})
}

// TestOpenReadHandleError covers Open's second (read-pool) sql.Open error, which
// must also close the already-opened write pool.
func TestOpenReadHandleError(t *testing.T) {
	calls := 0
	withSQLOpen(t, func(name, dsn string) (*sql.DB, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("read open denied")
		}
		return sql.Open(name, dsn)
	}, func() {
		if _, err := Open(tempDB(t)); err == nil {
			t.Fatal("Open succeeded when the read handle failed")
		}
	})
}

// TestOpenPingError covers Open's Ping-failure branch: sqlOpen returns a
// fault-driver DB whose Ping fails, so Open must abort after closing the pool.
func TestOpenPingError(t *testing.T) {
	faultDB := faultyDB(faultDriverConfig{failPing: true})
	t.Cleanup(func() { _ = faultDB.Close() })
	withSQLOpen(t, func(string, string) (*sql.DB, error) { return faultDB, nil },
		func() {
			if _, err := Open(tempDB(t)); err == nil {
				t.Fatal("Open succeeded when Ping failed")
			}
		})
}

// TestStoreCloseWriteError covers Close's write-pool error branch: the injected
// driver's Conn.Close fails, so database/sql surfaces it from DB.Close.
func TestStoreCloseWriteError(t *testing.T) {
	s := faultyStore(t, faultDriverConfig{failClose: true})
	// Force a connection to be opened (and pooled) so Close has something to
	// close.
	_ = s.write.Ping()
	_ = s.read.Ping()
	if err := s.Close(); err == nil {
		t.Fatal("Close swallowed a driver close error")
	}
}

// TestOpenMigrateError covers Open's Migrate-failure branch: the schema_version
// read fails so Migrate returns before the store is usable.
func TestOpenMigrateError(t *testing.T) {
	// Real store, then a corrupt schema_version forces Migrate to fail on a
	// second open.
	path := tempDB(t)
	st, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := st.write.Exec(`UPDATE meta SET value = 'garbage' WHERE key = ?`, SchemaVersionKey); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	_ = st.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("Open succeeded with a corrupt schema_version")
	}
}

// toDomain extracts the DomainError from an error.
func toDomain(t *testing.T, err error) *domain.DomainError {
	t.Helper()
	var de *domain.DomainError
	if !asDomain(err, &de) {
		t.Fatalf("err = %v is not a DomainError", err)
	}
	return de
}

// TestEnsurePermissionsRealCreate covers the real create path: a missing file
// is created 0600.
func TestEnsurePermissionsRealCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.db")
	if err := ensurePermissions(path); err != nil {
		t.Fatalf("ensurePermissions: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != VaultFileMode {
		t.Errorf("mode = %#o, want %#o", info.Mode().Perm(), VaultFileMode)
	}
}

// TestEnsurePermissionsChmodFileError covers the branch where the newly created
// file cannot be chmod-ed to 0600, via the ChmodFile seam (a real fchmod cannot
// fail on a healthy Linux host).
func TestEnsurePermissionsChmodFileError(t *testing.T) {
	fs := defaultVaultFS
	fs.MkdirAll = func(string, os.FileMode) error { return nil }
	fs.OpenFile = os.OpenFile
	fs.Stat = os.Stat
	fs.ChmodFile = func(*os.File, os.FileMode) error { return errors.New("fchmod denied") }
	fs.IsExist = os.IsExist
	withVaultFS(t, fs, func() {
		dir := t.TempDir()
		err := ensurePermissions(filepath.Join(dir, "heimdall.db"))
		if err == nil {
			t.Fatal("ensurePermissions accepted a failed file chmod")
		}
		if de := toDomain(t, err); de.Code != domain.CodeStoreOpenFailed {
			t.Fatalf("code = %q", de.Code)
		}
	})
}
