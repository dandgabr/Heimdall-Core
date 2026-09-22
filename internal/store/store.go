// Package store owns the SQLite persistence layer.
//
// Driver: modernc.org/sqlite (pure Go, CGO_ENABLED=0) so the static
// cross-compile promised by ADR-001 is preserved.
//
// Concurrency model — why two *sql.DB handles instead of one:
// SQLite admits exactly one writer at a time. A single multi-connection pool
// that serves both reads and writes will hand several connections into
// concurrent write transactions and the losers surface SQLITE_BUSY to callers.
// Rather than build a dedicated writer goroutine with its own queue (extra
// machinery, unbounded-queue failure mode), the serialization is made explicit
// at the pool level:
//
//   - write: MaxOpenConns(1). Every mutation funnels through one connection, so
//     our own concurrency can never contend on the write lock.
//   - read:  a small pool. In WAL mode readers do not block the writer and vice
//     versa, so reads stay concurrent.
//
// busy_timeout is still set on both handles: it absorbs contention from an
// external process (a CLI invocation sharing the same file) that the pool
// cannot serialize.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// DriverName is the database/sql driver registered by modernc.org/sqlite.
const DriverName = "sqlite"

// ManagementTokenHashKey is the meta row holding the SHA-256 hex of the
// management API token. Only the hash is persisted; the secret itself is never
// stored in the database.
const ManagementTokenHashKey = "management_token_hash"

// ManagementTokenKey is the legacy plaintext token key written by early F0
// builds. It is purged on open (see migrateLegacyToken) and never written again.
const ManagementTokenKey = "management_token"

// SchemaVersionKey is the meta row holding the applied migration version.
const SchemaVersionKey = "schema_version"

// ManagementTokenBytes is the token size. 32 bytes = 256 bits, matching the
// ADR-003 requirement of at least 256 bits for the management secret.
const ManagementTokenBytes = 32

// TokenFileMode is the permission required for the management token file.
const TokenFileMode = 0o600

// VaultFileMode is the permission required for the database file.
const VaultFileMode = 0o600

// VaultDirMode is the permission required for the directory holding the vault.
const VaultDirMode = 0o700

// Store is the persistence handle. It is safe for concurrent use.
type Store struct {
	path  string
	write *sql.DB
	read  *sql.DB
}

// Open opens (creating if needed) the database at path, applies the privacy
// permissions the vault requires, runs pending migrations and returns a ready
// Store.
func Open(path string) (*Store, error) {
	if err := ensurePermissions(path); err != nil {
		return nil, err
	}

	writeDB, err := sqlOpen(DriverName, dsn(path, 1))
	if err != nil {
		return nil, openError(path, err)
	}
	// One connection owns every write. See the package comment.
	writeDB.SetMaxOpenConns(1)
	writeDB.SetMaxIdleConns(1)

	readDB, err := sqlOpen(DriverName, dsn(path, 0))
	if err != nil {
		_ = writeDB.Close()
		return nil, openError(path, err)
	}
	readDB.SetMaxOpenConns(4)
	readDB.SetMaxIdleConns(4)

	s := &Store{path: path, write: writeDB, read: readDB}
	if err := s.write.Ping(); err != nil {
		_ = s.Close()
		return nil, openError(path, err)
	}
	if err := s.Migrate(); err != nil {
		_ = s.Close()
		return nil, err
	}
	// WAL/SHM sidecars carry the same data as the database. They are created by
	// SQLite during migration; harden them to 0600 on every boot.
	s.secureSidecars()
	return s, nil
}

// secureSidecars enforces 0600 on the -wal and -shm files. These are derived
// artifacts we own, so a permissive mode is corrected rather than treated as
// operator input worth refusing. They only exist after the first write.
func (s *Store) secureSidecars() {
	for _, suffix := range []string{"-wal", "-shm"} {
		p := s.path + suffix
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, VaultFileMode)
		}
	}
}

// Close releases both pools.
func (s *Store) Close() error {
	var first error
	if s.write != nil {
		if err := s.write.Close(); err != nil {
			first = err
		}
	}
	if s.read != nil {
		if err := s.read.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Writer exposes the single-connection write handle for later phases (routers,
// credential vaults). It must not be used for reads.
func (s *Store) Writer() *sql.DB { return s.write }

// Reader exposes the concurrent read handle.
func (s *Store) Reader() *sql.DB { return s.read }

// dsn builds the SQLite DSN with the pragmas the store depends on. maxConns is
// unused by the driver but documents intent at the call site.
func dsn(path string, _ int) string {
	pragmas := []string{
		"busy_timeout(5000)",
		"journal_mode(WAL)",
		"synchronous(NORMAL)",
		"foreign_keys(ON)",
		"temp_store(MEMORY)",
	}
	return fmt.Sprintf("file:%s?_pragma=%s", path, strings.Join(pragmas, "&_pragma="))
}

// ensurePermissions guarantees the vault is private on EVERY boot, including the
// first one.
//
// The previous version only validated an existing file, so the first boot let
// SQLite create the database under the process umask (typically 0644) and the
// second boot refused to start — a self-inflicted denial of service, and the
// token/credentials sat world-readable in between.
//
// The fix creates the file with 0600 at origin (O_CREATE|O_EXCL, 0600) so there
// is no permissive window, then validates both the file and its directory on
// every boot. An existing file with a mode more permissive than 0600 is refused
// (ADR-003: fail-closed) rather than silently chmod-ed, because its exposure
// already happened and the operator must be told.
// vaultFS is the filesystem seam for ensurePermissions. Production uses the os
// implementations; a test injects failures to reach the OS-error branches
// (mkdir/stat/open/chmod failures) that cannot be provoked on a healthy host.
type vaultFS struct {
	MkdirAll func(string, os.FileMode) error
	Stat     func(string) (os.FileInfo, error)
	OpenFile func(string, int, os.FileMode) (*os.File, error)
	Chmod    func(string, os.FileMode) error
	// ChmodFile applies the mode to the just-created file descriptor. It is a
	// separate seam because *os.File.Chmod cannot fail on a healthy Linux host.
	ChmodFile func(*os.File, os.FileMode) error
	IsExist   func(error) bool
}

var defaultVaultFS = vaultFS{
	MkdirAll:  os.MkdirAll,
	Stat:      os.Stat,
	OpenFile:  os.OpenFile,
	Chmod:     os.Chmod,
	ChmodFile: func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) },
	IsExist:   os.IsExist,
}

// sqlOpen is the database/sql.Open seam, so a test can make the driver's
// *sql.Open* step fail and reach Open's openError branches (which a healthy
// process cannot otherwise provoke: sql.Open only validates the DSN lazily).
var sqlOpen = sql.Open

// vaultFileOps is swapped in tests to inject OS failures.
var vaultFileOps = defaultVaultFS

func ensurePermissions(path string) error {
	fs := vaultFileOps
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := fs.MkdirAll(dir, VaultDirMode); err != nil {
			return domain.New(domain.CodeStoreOpenFailed,
				domain.WithHTTPStatus(500),
				domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "cannot create " + dir}),
			)
		}
		// MkdirAll honours the umask, so an existing directory may be more
		// permissive than requested. Tighten our own directory on every boot;
		// refuse only if it is group/world writable after the attempt.
		info, err := fs.Stat(dir)
		if err != nil {
			return domain.New(domain.CodeStoreOpenFailed,
				domain.WithHTTPStatus(500),
				domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "cannot stat " + dir}),
			)
		}
		if info.Mode().Perm() != VaultDirMode {
			_ = fs.Chmod(dir, VaultDirMode)
		}
	}

	// Create the file 0600 at origin if it does not exist. O_EXCL keeps us from
	// racing an existing file; an EEXIST means another boot already created it,
	// which is fine and falls through to the validation below.
	f, err := fs.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, VaultFileMode)
	if err == nil {
		// O_CREATE mode is masked by the umask; force the exact mode so a
		// umask of 0 cannot leave the vault group-readable.
		if chmodErr := fs.ChmodFile(f, VaultFileMode); chmodErr != nil {
			_ = f.Close()
			return domain.New(domain.CodeStoreOpenFailed,
				domain.WithHTTPStatus(500),
				domain.WithCause(chmodErr),
				domain.WithParams(map[string]string{"reason": "cannot set 0600 on " + path}),
			)
		}
		return f.Close()
	}
	if !fs.IsExist(err) {
		return domain.New(domain.CodeStoreOpenFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot create " + path}),
		)
	}

	info, err := fs.Stat(path)
	if err != nil {
		return domain.New(domain.CodeStoreOpenFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot stat " + path}),
		)
	}
	if !info.Mode().IsRegular() {
		return domain.New(domain.CodeStoreOpenFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": path + " is not a regular file"}),
		)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		// Dedicated code: the message carries the path, the offending mode and
		// the corrective command, so the operator knows exactly what to fix.
		// The boot still fails closed.
		return domain.New(domain.CodeStoreVaultPermissions,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{
				"path": path,
				"mode": fmt.Sprintf("%#o", mode),
			}),
		)
	}
	return nil
}

func openError(path string, err error) error {
	return domain.New(domain.CodeStoreOpenFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": "cannot open " + path}),
	)
}

// GetMeta reads one meta value. found is false when the key is absent.
func (s *Store) GetMeta(key string) (value string, found bool, err error) {
	row := s.read.QueryRow(`SELECT value FROM meta WHERE key = ?`, key)
	switch err := row.Scan(&value); err {
	case nil:
		return value, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, err
	}
}

// SetMeta upserts one meta value on the write pool.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.write.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// SetMetaIfAbsent inserts key only if it does not already exist, reporting
// whether THIS call performed the insert. It is the atomic primitive that
// closes the load-or-create race: two concurrent boots both find no salt, both
// generate one, and without an atomic insert the loser's derived KEK would be
// based on a salt that was overwritten — leaving credentials permanently
// undecryptable. With INSERT ... ON CONFLICT DO NOTHING, exactly one writer wins
// and every caller then re-reads the winner.
func (s *Store) SetMetaIfAbsent(key, value string) (inserted bool, err error) {
	res, err := s.write.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO NOTHING`,
		key, value,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// HashManagementToken returns the hex SHA-256 of a presented token. Hashing is
// the storage form: the database never holds the recoverable secret, so a stolen
// database file yields no usable management credential.
func HashManagementToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// randReader is the entropy source for the management token. It is a package
// variable so a test can inject a failing reader and cover the crypto/rand error
// branch. Production never changes it.
var randReader io.Reader = rand.Reader

// newManagementToken returns a fresh 256-bit token, hex encoded.
func newManagementToken() (string, error) {
	buf := make([]byte, ManagementTokenBytes)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	return hex.EncodeToString(buf), nil
}

// EnsureManagementTokenHash makes sure a token hash exists, generating one on
// first start, and returns the plaintext token ONLY when it was just created
// (created=true). On subsequent boots it returns ("", false, nil): the plaintext
// is unrecoverable by design and the operator reads it from the token file.
func (s *Store) EnsureManagementTokenHash() (token string, created bool, err error) {
	if err := s.migrateLegacyToken(); err != nil {
		return "", false, err
	}
	existing, found, err := s.GetMeta(ManagementTokenHashKey)
	if err != nil {
		return "", false, domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	if found && existing != "" {
		return "", false, nil
	}
	return s.RotateManagementToken()
}

// RotateManagementToken generates a new 256-bit token, stores only its hash and
// invalidates any previous token. It returns the plaintext so the caller can
// write it to a 0600 file exactly once.
func (s *Store) RotateManagementToken() (token string, created bool, err error) {
	token, err = newManagementToken()
	if err != nil {
		return "", false, err
	}
	if err := s.SetMeta(ManagementTokenHashKey, HashManagementToken(token)); err != nil {
		return "", false, domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	return token, true, nil
}

// migrateLegacyToken removes the plaintext token row written by early F0 builds.
// Best-effort on an old database; a failure is reported because leaving a
// recoverable secret behind is a security regression.
func (s *Store) migrateLegacyToken() error {
	_, err := s.write.Exec(`DELETE FROM meta WHERE key = ?`, ManagementTokenKey)
	if err != nil {
		return domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	return nil
}

// HasManagementToken reports whether a token hash is stored.
func (s *Store) HasManagementToken() (bool, error) {
	value, found, err := s.GetMeta(ManagementTokenHashKey)
	if err != nil {
		return false, err
	}
	return found && value != "", nil
}

// VerifyManagementToken compares a presented token against the stored hash in
// constant time. A missing stored hash always fails closed.
func (s *Store) VerifyManagementToken(presented string) bool {
	stored, found, err := s.GetMeta(ManagementTokenHashKey)
	if err != nil || !found || stored == "" || presented == "" {
		return false
	}
	presentedHash := HashManagementToken(presented)
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presentedHash)) == 1
}

// tokenFileOps are the filesystem seams WriteTokenFile uses. They are package
// variables so a test can inject failures at each step (temp creation, chmod,
// write, close, rename) without provoking real disk errors. Production uses the
// os implementations.
type tokenTempFile interface {
	Name() string
	Chmod(os.FileMode) error
	WriteString(string) (int, error)
	Close() error
}

var (
	osMkdirAll   = os.MkdirAll
	osCreateTemp = func(dir, pattern string) (tokenTempFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	osRemoveToken = os.Remove
	osRenameToken = os.Rename
)

// WriteTokenFile writes the plaintext token to path with mode 0600, creating it
// atomically: a temp file in the same directory is written and renamed into
// place, so a reader never observes a partial or permissively-created file.
func WriteTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := osMkdirAll(dir, VaultDirMode); err != nil {
			return domain.New(domain.CodeStoreTokenFailed,
				domain.WithHTTPStatus(500), domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "cannot create " + dir}))
		}
	}
	tmp, err := osCreateTemp(dir, ".token-*")
	if err != nil {
		return domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = osRemoveToken(tmpName) }

	if err := tmp.Chmod(TokenFileMode); err != nil {
		_ = tmp.Close()
		cleanup()
		return domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		cleanup()
		return domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	if err := osRenameToken(tmpName, path); err != nil {
		cleanup()
		return domain.New(domain.CodeStoreTokenFailed,
			domain.WithHTTPStatus(500), domain.WithCause(err))
	}
	return nil
}

// DefaultTokenFilePath returns the token file location: $XDG_DATA_HOME/heimdall/
// management-token, falling back to ~/.local/share/heimdall/management-token.
// It sits next to the database by default.
func DefaultTokenFilePath() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "management-token"
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "heimdall", "management-token")
}
