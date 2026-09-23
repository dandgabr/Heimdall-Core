package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// cheapParams keeps the suite fast; production uses secret.DefaultKDFParams.
var cheapParams = secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32}

// newTestVault opens a database and a SecretStore over the same salt, returning
// both plus the raw KEK so a test can build a second store (different key).
func newTestVault(t *testing.T, dbPath string, material string) (*Store, *secret.Store, []byte) {
	t.Helper()
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	kek, err := secret.DeriveKEK([]byte(material), salt, cheapParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	sec, err := secret.NewWithKEK(kek)
	if err != nil {
		t.Fatalf("NewWithKEK: %v", err)
	}
	return st, sec, kek
}

func sampleCredential(t *testing.T, sec *secret.Store, id, token string) contracts.Credential {
	t.Helper()
	sealed, err := sec.Seal([]byte(token))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return contracts.Credential{
		ID:        domain.CredentialID(id),
		Provider:  domain.ProviderID("zai"),
		AuthMode:  contracts.AuthAPIKey,
		Label:     "work account",
		Meta:      contracts.AccountMeta{Email: "user@example.com", Plan: "pro"},
		Sealed:    []byte(sealed),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
}

func TestLatestMigrationCreatesSchema(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")

	version, found, err := st.GetMeta(SchemaVersionKey)
	if err != nil || !found {
		t.Fatalf("schema_version missing: %v", err)
	}
	// The latest embedded migration is 0004_quota. A new migration bumps this.
	if version != "4" {
		t.Fatalf("schema_version = %q, want 4", version)
	}

	// Idempotence: a second Migrate must not change anything.
	if err := st.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if again, _, _ := st.GetMeta(SchemaVersionKey); again != version {
		t.Errorf("schema_version drifted: %q -> %q", version, again)
	}

	// The tables are usable.
	if _, err := st.read.Query(`SELECT id FROM credentials`); err != nil {
		t.Fatalf("credentials table unusable: %v", err)
	}
	if _, err := st.read.Query(`SELECT name FROM combos`); err != nil {
		t.Fatalf("combos table unusable: %v", err)
	}
	if _, err := st.read.Query(`SELECT credential_id FROM quota_windows`); err != nil {
		t.Fatalf("quota_windows table unusable: %v", err)
	}
	if _, err := st.read.Query(`SELECT attempt_key FROM usage_attempts`); err != nil {
		t.Fatalf("usage_attempts table unusable: %v", err)
	}
}

func TestCredentialStoreRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, sec, _ := newTestVault(t, dbPath, "material")
	cs := NewCredentialStore(st)

	cred := sampleCredential(t, sec, "cred-1", "sk-live-secret-token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := cs.Get(context.Background(), cred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Provider != cred.Provider || got.AuthMode != cred.AuthMode || got.Label != cred.Label {
		t.Errorf("metadata mismatch: %+v", got)
	}
	if got.Meta.Email != "user@example.com" {
		t.Errorf("meta not persisted: %+v", got.Meta)
	}

	// The sealed blob must open back to the original token.
	plaintext, err := sec.Open(string(got.Sealed))
	if err != nil {
		t.Fatalf("Open sealed blob: %v", err)
	}
	if string(plaintext) != "sk-live-secret-token" {
		t.Errorf("plaintext = %q", plaintext)
	}

	// Upsert replaces rather than duplicates.
	cred.Label = "renamed"
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	list, err := cs.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Label != "renamed" {
		t.Fatalf("upsert did not replace: %+v", list)
	}
}

func TestCredentialStoreGetNotFound(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)

	_, err := cs.Get(context.Background(), "missing")
	if !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestCredentialStoreDelete(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)

	cred := sampleCredential(t, sec, "cred-del", "token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := cs.Delete(context.Background(), cred.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.Get(context.Background(), cred.ID); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := cs.Delete(context.Background(), cred.ID); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("second delete: %v, want ErrNotFound", err)
	}
}

// TestUpsertRejectsPlaintextBlob is the P1-2 regression guard: a Sealed that is
// not a valid enc:v1 envelope must be refused before the INSERT, so a caller
// that forgot to seal can never write a raw token to disk.
func TestUpsertRejectsPlaintextBlob(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, _, _ := newTestVault(t, dbPath, "material")
	cs := NewCredentialStore(st)

	const rawToken = "sk-live-raw-token-that-was-never-sealed"

	bad := []struct {
		name   string
		sealed string
	}{
		{"raw token", rawToken},
		{"wrong prefix", "plain:v1:AAAAAAAAAAAAAAAA:BBBB:CCCCCCCCCCCCCCCC"},
		{"unknown version", "enc:v9:AAAAAAAAAAAAAAAA:BBBB:CCCCCCCCCCCCCCCC"},
		{"short iv", "enc:v1:AAAA:BBBB:CCCCCCCCCCCCCCCC"},
		{"not base64", "enc:v1:!!!!:BBBB:CCCCCCCCCCCCCCCC"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			cred := contracts.Credential{
				ID:       domain.CredentialID("bad-" + tt.name),
				Provider: "z.ai",
				AuthMode: contracts.AuthAPIKey,
				Sealed:   []byte(tt.sealed),
			}
			if err := cs.Upsert(context.Background(), cred); err == nil {
				t.Fatalf("Upsert accepted %q as a sealed blob", tt.sealed)
			}
			// The credential must not exist.
			if _, err := cs.Get(context.Background(), cred.ID); !errors.Is(err, contracts.ErrNotFound) {
				t.Fatalf("rejected credential was nevertheless persisted")
			}
		})
	}

	// Prove the raw token never reached the SQLite file.
	if _, err := st.write.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", path, err)
		}
		if bytes.Contains(raw, []byte(rawToken)) {
			t.Fatalf("plaintext token reached %s", path)
		}
	}
}

// TestUpsertAcceptsValidEnvelope keeps the fail-closed check from being
// over-eager: a real SecretStore output is accepted.
func TestUpsertAcceptsValidEnvelope(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)

	cred := sampleCredential(t, sec, "good", "valid-token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert with a valid envelope: %v", err)
	}
}

func TestCredentialStoreRejectsEmptySecretForAuthMode(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)

	cred := contracts.Credential{
		ID:       "no-secret",
		Provider: "zai",
		AuthMode: contracts.AuthAPIKey,
		// Sealed intentionally empty.
	}
	if err := cs.Upsert(context.Background(), cred); err == nil {
		t.Fatal("APIKey credential with an empty secret was accepted")
	}

	// AuthNone with an empty secret is valid.
	cred.AuthMode = contracts.AuthNone
	cred.ID = "local"
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("AuthNone with empty secret rejected: %v", err)
	}
}

// TestNoPlaintextInDatabase is the brief's grep test: the token must not appear
// anywhere in the SQLite file.
func TestNoPlaintextInDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, sec, _ := newTestVault(t, dbPath, "material")
	cs := NewCredentialStore(st)

	const token = "sk-live-THIS-MUST-NOT-APPEAR-1234567890"
	cred := sampleCredential(t, sec, "cred-grep", token)
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Force WAL pages to be written to the main file so the grep covers them.
	if _, err := st.write.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", path, err)
		}
		if bytes.Contains(raw, []byte(token)) {
			t.Fatalf("plaintext token found in %s", path)
		}
	}

	// Sanity: the row exists and holds an enc:v1 blob.
	// (Reopen to read without the cleanup double-close.)
	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	var blob string
	if err := st2.read.QueryRow(`SELECT secret_blob FROM credentials WHERE id = 'cred-grep'`).Scan(&blob); err != nil {
		t.Fatalf("select blob: %v", err)
	}
	if !strings.HasPrefix(blob, "enc:v1:") {
		t.Fatalf("secret_blob = %q, want an enc:v1 envelope", blob)
	}
}

// TestDatabaseWithoutKEKIsUnreadable is acceptance criterion 3: copying the DB
// without the KEK must not yield the credential. A different key fails closed.
func TestDatabaseWithoutKEKIsUnreadable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, sec, _ := newTestVault(t, dbPath, "correct-installation-material")
	cs := NewCredentialStore(st)

	const token = "sk-live-original-token"
	cred := sampleCredential(t, sec, "cred-1", token)
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// A second SecretStore with the SAME salt but a DIFFERENT KEK (as an
	// attacker with the copied DB but not the key would have).
	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	wrongKEK, err := secret.DeriveKEK([]byte("attacker-guess"), salt, cheapParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	wrongStore, err := secret.NewWithKEK(wrongKEK)
	if err != nil {
		t.Fatalf("NewWithKEK: %v", err)
	}

	got, err := cs.Get(context.Background(), cred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	plaintext, err := wrongStore.Open(string(got.Sealed))
	if err == nil {
		t.Fatalf("wrong KEK decrypted the credential: %q", plaintext)
	}
	if plaintext != nil {
		t.Error("failure returned partial plaintext")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretDecryptFailed {
		t.Fatalf("err = %v, want secret.decrypt_failed", err)
	}
}

// TestSamePassphraseDifferentSaltsProduceDistinctKEKs covers the "two vaults,
// same passphrase" acceptance criterion end to end.
func TestSamePassphraseDifferentSaltsProduceDistinctKEKs(t *testing.T) {
	dbA := filepath.Join(t.TempDir(), "a.db")
	dbB := filepath.Join(t.TempDir(), "b.db")

	stA, err := Open(dbA)
	if err != nil {
		t.Fatalf("Open A: %v", err)
	}
	defer stA.Close()
	stB, err := Open(dbB)
	if err != nil {
		t.Fatalf("Open B: %v", err)
	}
	defer stB.Close()

	const passphrase = "identical-passphrase"
	saltA, _ := secret.LoadOrCreateSalt(stA)
	saltB, _ := secret.LoadOrCreateSalt(stB)
	if bytes.Equal(saltA, saltB) {
		t.Fatal("two vaults share a salt")
	}
	kekA, _ := secret.DeriveKEK([]byte(passphrase), saltA, cheapParams)
	kekB, _ := secret.DeriveKEK([]byte(passphrase), saltB, cheapParams)
	if bytes.Equal(kekA, kekB) {
		t.Fatal("same passphrase and different salts produced the same KEK")
	}
}

// TestRotationPreservesReading uses the store's Rewrap to prove the format
// tolerates incremental migration: records sealed under the old key stay
// readable after their DEK is re-wrapped under the new one.
func TestRotationPreservesReading(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, sec, oldKEK := newTestVault(t, dbPath, "old-material")
	cs := NewCredentialStore(st)

	cred := sampleCredential(t, sec, "cred-rot", "rotate-this-token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	newKEK, err := secret.DeriveKEK([]byte("new-material"), bytes.Repeat([]byte{0x9a}, secret.SaltSize), cheapParams)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	nextStore, err := sec.RotateTo(newKEK, "")
	if err != nil {
		t.Fatalf("RotateTo: %v", err)
	}

	// Re-wrap the stored record's DEK, persist it back, and read via the new key.
	got, _ := cs.Get(context.Background(), cred.ID)
	rewrapped, err := sec.Rewrap(newKEK, string(got.Sealed))
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	got.Sealed = []byte(rewrapped)
	got.Label = "rotated"
	if err := cs.Upsert(context.Background(), got); err != nil {
		t.Fatalf("Upsert rotated: %v", err)
	}

	final, _ := cs.Get(context.Background(), cred.ID)
	plaintext, err := nextStore.Open(string(final.Sealed))
	if err != nil {
		t.Fatalf("new store cannot read rotated record: %v", err)
	}
	if string(plaintext) != "rotate-this-token" {
		t.Errorf("plaintext = %q", plaintext)
	}

	// The old key must no longer read the rotated record.
	if _, err := secret.Open(oldKEK, string(final.Sealed)); err == nil {
		t.Error("old KEK still reads a rotated record")
	}
}

// TestRefreshLockSingleFlight is the brief's acceptance test: N concurrent
// goroutines must produce EXACTLY ONE upstream execution.
//
// The collapse is the lock plus the canonical caller pattern documented on
// contracts.CredentialStore.RefreshLock: each caller acquires the lock, re-reads
// the credential and skips the refresh if ExpiresAt has already moved past now.
// Without the re-read, N holders would each refresh in turn — mutual exclusion
// alone does not collapse the work. refreshIfStale below is therefore the real
// pattern, not a test fiction.
func TestRefreshLockSingleFlight(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, sec, _ := newTestVault(t, dbPath, "material")
	cs := NewCredentialStore(st)

	// A credential that is already EXPIRED, so the first holder must refresh.
	cred := sampleCredential(t, sec, "cred-lock", "old-token")
	cred.ExpiresAt = time.Now().Add(-time.Minute)
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	var executions int64
	const goroutines = 16

	// refreshIfStale: the canonical single-flight pattern.
	refreshIfStale := func() error {
		unlock, err := cs.RefreshLock(context.Background(), cred.ID)
		if err != nil {
			return err
		}
		defer unlock()

		current, err := cs.Get(context.Background(), cred.ID)
		if err != nil {
			return err
		}
		if current.ExpiresAt.After(time.Now()) {
			return nil // another holder already refreshed; nothing to do
		}

		// Only here is the "upstream call" made.
		atomic.AddInt64(&executions, 1)
		time.Sleep(5 * time.Millisecond) // widen the window for the other goroutines

		current.ExpiresAt = time.Now().Add(time.Hour)
		return cs.Upsert(context.Background(), current)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release together to maximise contention
			if err := refreshIfStale(); err != nil {
				t.Errorf("refreshIfStale: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&executions); got != 1 {
		t.Fatalf("upstream executions = %d, want exactly 1", got)
	}

	// The persisted expiry must have moved forward.
	final, _ := cs.Get(context.Background(), cred.ID)
	if !final.ExpiresAt.After(time.Now()) {
		t.Error("credential was not refreshed")
	}
}

// TestRefreshLockProvidesMutualExclusion isolates the lock's own guarantee —
// at most one holder inside at a time — independent of the caller pattern.
func TestRefreshLockProvidesMutualExclusion(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	const id = domain.CredentialID("cred-mutex")

	const goroutines = 16
	var inside, maxInside int64

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := cs.RefreshLock(context.Background(), id)
			if err != nil {
				t.Errorf("RefreshLock: %v", err)
				return
			}
			defer unlock()

			cur := atomic.AddInt64(&inside, 1)
			for {
				old := atomic.LoadInt64(&maxInside)
				if cur <= old || atomic.CompareAndSwapInt64(&maxInside, old, cur) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt64(&inside, -1)
		}()
	}
	wg.Wait()

	if maxInside != 1 {
		t.Fatalf("mutual exclusion violated: %d holders inside at once", maxInside)
	}
}

// TestRefreshLockHonoursContext checks a cancelled wait returns the i18n error
// instead of blocking forever, and that the unlock is idempotent.
func TestRefreshLockHonoursContext(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	const id = domain.CredentialID("cred-ctx")

	unlock, err := cs.RefreshLock(context.Background(), id)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	// A second acquirer with an already-cancelled context must fail fast.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cs.RefreshLock(ctx, id); err == nil {
		t.Fatal("cancelled wait acquired the lock")
	} else {
		de, ok := err.(*domain.DomainError)
		if !ok || de.Code != domain.CodeCredentialRefreshWait {
			t.Fatalf("err = %v, want credential.refresh_wait_cancelled", err)
		}
	}

	// Unlock twice: the second call must be a no-op, not a panic/deadlock.
	unlock()
	unlock()

	// After release a fresh acquire succeeds.
	unlock2, err := cs.RefreshLock(context.Background(), id)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	unlock2()
}

func TestRefreshLockDifferentCredentialsDoNotBlock(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)

	unlockA, err := cs.RefreshLock(context.Background(), "a")
	if err != nil {
		t.Fatalf("lock a: %v", err)
	}
	defer unlockA()

	// B must not be blocked by A: the lock is per credential.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlockB, err := cs.RefreshLock(ctx, "b")
	if err != nil {
		t.Fatalf("lock b blocked by a: %v", err)
	}
	unlockB()
}

func TestCredentialStorePersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, sec, _ := newTestVault(t, dbPath, "material")
	cs := NewCredentialStore(st)
	cred := sampleCredential(t, sec, "persist", "token")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen: the row survives and still opens with the same KEK.
	st2, sec2, _ := newTestVault(t, dbPath, "material")
	cs2 := NewCredentialStore(st2)
	got, err := cs2.Get(context.Background(), "persist")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	plaintext, err := sec2.Open(string(got.Sealed))
	if err != nil || string(plaintext) != "token" {
		t.Fatalf("reopen decrypt: %q, %v", plaintext, err)
	}
}

func TestParseAuthModeRoundTrips(t *testing.T) {
	for _, mode := range []contracts.AuthMode{contracts.AuthNone, contracts.AuthAPIKey, contracts.AuthOAuth} {
		got, err := parseAuthMode(mode.String())
		if err != nil || got != mode {
			t.Errorf("parseAuthMode(%q) = %v, %v; want %v", mode.String(), got, err, mode)
		}
	}
	if _, err := parseAuthMode("bogus"); err == nil {
		t.Error("unknown auth mode accepted")
	}
}

func TestSealedBlobIsBase64NotRawToken(t *testing.T) {
	st, sec, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewCredentialStore(st)
	cred := sampleCredential(t, sec, "c", "abcdefghijklmnop")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, _ := cs.Get(context.Background(), "c")
	blob := string(got.Sealed)
	// The blob must not contain the raw token as a substring.
	if strings.Contains(blob, "abcdefghijklmnop") {
		t.Fatalf("sealed blob exposes the token: %s", blob)
	}
	// And each part between colons must be valid base64.
	for _, part := range strings.Split(blob, ":")[2:] {
		if _, err := base64.RawStdEncoding.DecodeString(part); err != nil {
			t.Errorf("part %q is not base64: %v", part, err)
		}
	}
}
