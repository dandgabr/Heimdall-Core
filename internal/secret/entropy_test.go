package secret

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// failingReader always fails, so the crypto/rand error branches become
// reachable through the randReader seam.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

// withFailingRand swaps the package entropy source for the duration of fn and
// restores it immediately after, so the broken reader cannot leak into another
// assertion or test. A t.Cleanup is registered as a belt-and-braces restore for
// the case where fn panics.
func withFailingRand(t *testing.T, fn func()) {
	t.Helper()
	old := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = old })
	fn()
	randReader = old
}

func TestSealFailsOnEntropyError(t *testing.T) {
	kek := testKEK(t)
	withFailingRand(t, func() {
		if _, err := Seal(kek, []byte("x")); err == nil {
			t.Fatal("Seal succeeded without entropy")
		}
	})
}

func TestRewrapFailsOnEntropyError(t *testing.T) {
	kek := testKEK(t)
	encoded, err := Seal(kek, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	newKEK, _ := DeriveKEK([]byte("n"), bytes.Repeat([]byte{1}, SaltSize), testParams)
	withFailingRand(t, func() {
		if _, err := Rewrap(kek, newKEK, encoded); err == nil {
			t.Fatal("Rewrap succeeded without entropy")
		}
	})
}

func TestNewSaltFailsOnEntropyError(t *testing.T) {
	withFailingRand(t, func() {
		if _, err := NewSalt(); err == nil {
			t.Fatal("NewSalt succeeded without entropy")
		}
	})
}

func TestWrapKEKForRecoveryFailsOnEntropyError(t *testing.T) {
	kek := testKEK(t)
	withFailingRand(t, func() {
		if _, err := WrapKEKForRecovery(kek, []byte("pass"), testParams); err == nil {
			t.Fatal("WrapKEKForRecovery succeeded without entropy")
		}
	})
}

// TestWrapKEKForRecoveryFailsOnSecondEntropyRead covers the IV read failure
// inside WrapKEKForRecovery: the salt read succeeds, then the reader fails.
func TestWrapKEKForRecoveryFailsOnSecondEntropyRead(t *testing.T) {
	kek := testKEK(t)
	old := randReader
	randReader = &partialReader{remaining: SaltSize}
	t.Cleanup(func() { randReader = old })
	if _, err := WrapKEKForRecovery(kek, []byte("pass"), testParams); err == nil {
		t.Fatal("WrapKEKForRecovery succeeded when the IV read failed")
	}
	randReader = old
}

// TestRotateToProbeSealEntropyError covers RotateTo's Seal-failure branch (the
// empty-sample probe cannot be produced without entropy).
func TestRotateToProbeSealEntropyError(t *testing.T) {
	kek := testKEK(t)
	s, _ := NewWithKEK(kek)
	newKEK, _ := DeriveKEK([]byte("n"), bytes.Repeat([]byte{7}, SaltSize), testParams)
	old := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = old })
	if _, err := s.RotateTo(newKEK, ""); err == nil {
		t.Fatal("RotateTo succeeded without entropy for its probe")
	}
	randReader = old
}

// TestDeriveKEKKeyLenRegression is the regression guard for the nil-pointer
// panic: KeyLen == 0 makes argon2's blake2b hash nil, which the library then
// dereferences. Every non-32 KeyLen must return an ERROR, never panic, and
// KeyLen == 32 must succeed. recover() turns any panic into a test failure so a
// future KDF swap cannot silently reintroduce the fault.
func TestDeriveKEKKeyLenRegression(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltSize)
	material := []byte("material")

	for _, keyLen := range []uint32{0, 1, 16, 31, 33, 64} {
		keyLen := keyLen
		t.Run("rejected", func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DeriveKEK panicked for KeyLen=%d: %v", keyLen, r)
				}
			}()
			params := testParams
			params.KeyLen = keyLen
			out, err := DeriveKEK(material, salt, params)
			if err == nil {
				t.Fatalf("DeriveKEK accepted KeyLen=%d (returned %d bytes)", keyLen, len(out))
			}
			if out != nil {
				t.Errorf("DeriveKEK returned bytes alongside the error for KeyLen=%d", keyLen)
			}
			if de, ok := err.(*domain.DomainError); !ok || de.Code != domain.CodeSecretKDFFailed {
				t.Errorf("KeyLen=%d: err = %v, want secret.kdf_failed", keyLen, err)
			}
		})
	}

	t.Run("accepted", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DeriveKEK panicked for KeyLen=32: %v", r)
			}
		}()
		params := testParams
		params.KeyLen = KEKSize
		out, err := DeriveKEK(material, salt, params)
		if err != nil {
			t.Fatalf("DeriveKEK rejected KeyLen=32: %v", err)
		}
		if len(out) != KEKSize {
			t.Errorf("derived %d bytes, want %d", len(out), KEKSize)
		}
	})
}

// TestValidateRejectsEveryDegenerateParam pins Validate's preconditions,
// including KeyLen, which is the panic guard for argon2.
func TestValidateRejectsEveryDegenerateParam(t *testing.T) {
	cases := map[string]KDFParams{
		"zero all":     {},
		"memory zero":  {Time: 1, Threads: 1, KeyLen: KEKSize},
		"time zero":    {Memory: 8, Threads: 1, KeyLen: KEKSize},
		"threads zero": {Memory: 8, Time: 1, KeyLen: KEKSize},
		"keylen zero":  {Memory: 8, Time: 1, Threads: 1, KeyLen: 0},
		"keylen 16":    {Memory: 8, Time: 1, Threads: 1, KeyLen: 16},
		"keylen 64":    {Memory: 8, Time: 1, Threads: 1, KeyLen: 64},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if err := params.Validate(); err == nil {
				t.Fatal("Validate accepted a degenerate parameter set")
			}
		})
	}
	if err := testParams.Validate(); err != nil {
		t.Fatalf("Validate rejected valid params: %v", err)
	}
}

// TestDeriveKEKPostDeriveGuard covers the defence-in-depth length guard with a
// fake KDF that returns a wrong-length key (the real KDF with KeyLen==32 always
// returns 32 bytes, so the guard is otherwise unreachable).
func TestDeriveKEKPostDeriveGuard(t *testing.T) {
	old := deriveKeyFn
	deriveKeyFn = func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
		return bytes.Repeat([]byte{0}, 16) // wrong length
	}
	t.Cleanup(func() { deriveKeyFn = old })

	_, err := DeriveKEK([]byte("m"), bytes.Repeat([]byte{1}, SaltSize), testParams)
	if err == nil {
		t.Fatal("DeriveKEK accepted a 16-byte derived key")
	}
	if de, ok := err.(*domain.DomainError); !ok || de.Code != domain.CodeSecretKDFFailed {
		t.Fatalf("err = %v, want secret.kdf_failed", err)
	}
	deriveKeyFn = old
}

// TestWrapRandTyped covers wrapRand directly (0% before): it wraps the cause and
// carries the kdf code.
func TestWrapRandTyped(t *testing.T) {
	err := wrapRand(errors.New("boom"))
	if err == nil {
		t.Fatal("wrapRand returned nil")
	}
	if !errors.Is(err, io.EOF) && err.Error() == "" {
		t.Error("wrapRand produced an empty error")
	}
}

// TestSealEntropySeamRestores ensures the seam helper restores the real reader,
// so a later test in the same package still works.
func TestSealEntropySeamRestores(t *testing.T) {
	kek := testKEK(t)
	withFailingRand(t, func() { _, _ = Seal(kek, []byte("x")) })
	if _, err := Seal(kek, []byte("x")); err != nil {
		t.Fatalf("entropy source not restored: %v", err)
	}
}

// TestLoadOrCreateSaltNewSaltEntropyError covers LoadOrCreateSalt's NewSalt
// failure branch.
func TestLoadOrCreateSaltNewSaltEntropyError(t *testing.T) {
	old := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = old })
	if _, err := LoadOrCreateSalt(newMemMeta()); err == nil {
		t.Fatal("LoadOrCreateSalt succeeded without entropy")
	}
	randReader = old
}

// TestRotateToRewrapEntropyError covers RotateTo's Rewrap-failure branch: the
// Seal probe succeeds (56 bytes of entropy) and the reader then fails during the
// Rewrap IV read.
func TestRotateToRewrapEntropyError(t *testing.T) {
	kek := testKEK(t)
	s, _ := NewWithKEK(kek)
	newKEK, _ := DeriveKEK([]byte("n"), bytes.Repeat([]byte{7}, SaltSize), testParams)
	old := randReader
	// DEK(32) + recordIV(12) + wrapIV(12) = 56 for Seal, then Rewrap needs 12.
	randReader = &partialReader{remaining: 56}
	t.Cleanup(func() { randReader = old })
	if _, err := s.RotateTo(newKEK, ""); err == nil {
		t.Fatal("RotateTo succeeded when the Rewrap read failed")
	}
	randReader = old
}

// failGCM forces every newGCMFn call to fail, reaching the callers' GCM-error
// propagation branches (which cipher.NewGCM cannot produce for a valid key).
func withFailingGCM(t *testing.T, fn func()) {
	t.Helper()
	old := newGCMFn
	newGCMFn = func([]byte) (cipher.AEAD, error) { return nil, errors.New("gcm denied") }
	t.Cleanup(func() { newGCMFn = old })
	fn()
	newGCMFn = old
}

// TestSealGCMError covers Seal's two newGCMFn error branches.
func TestSealGCMError(t *testing.T) {
	withFailingGCM(t, func() {
		if _, err := Seal(testKEK(t), []byte("x")); err == nil {
			t.Fatal("Seal succeeded with a failing GCM")
		}
	})
}

// TestOpenGCMError covers Open's newGCMFn error branches (both the KEK wrap and
// the record DEK).
func TestOpenGCMError(t *testing.T) {
	kek := testKEK(t)
	encoded, err := Seal(kek, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	withFailingGCM(t, func() {
		if _, err := Open(kek, encoded); err == nil {
			t.Fatal("Open succeeded with a failing GCM")
		}
	})
}

// TestRewrapGCMError covers Rewrap's newGCMFn error branches.
func TestRewrapGCMError(t *testing.T) {
	kek := testKEK(t)
	encoded, _ := Seal(kek, []byte("x"))
	newKEK, _ := DeriveKEK([]byte("n"), bytes.Repeat([]byte{1}, SaltSize), testParams)
	withFailingGCM(t, func() {
		if _, err := Rewrap(kek, newKEK, encoded); err == nil {
			t.Fatal("Rewrap succeeded with a failing GCM")
		}
	})
}

// TestRecoveryGCMError covers WrapKEKForRecovery's and UnwrapKEKFromRecovery's
// newGCMFn error branches.
func TestRecoveryGCMError(t *testing.T) {
	kek := testKEK(t)
	blob, err := WrapKEKForRecovery(kek, []byte("pass"), testParams)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	withFailingGCM(t, func() {
		if _, err := WrapKEKForRecovery(kek, []byte("pass"), testParams); err == nil {
			t.Error("WrapKEKForRecovery succeeded with a failing GCM")
		}
		if _, err := UnwrapKEKFromRecovery(blob, []byte("pass"), testParams); err == nil {
			t.Error("UnwrapKEKFromRecovery succeeded with a failing GCM")
		}
	})
}

// withGCMFailingOn swaps newGCMFn to fail on the Nth call (1-based) and succeed
// before, so a two-GCM operation (Seal, Open) reaches its SECOND call's error
// branch.
func withGCMFailingOn(t *testing.T, n int, fn func()) {
	t.Helper()
	old := newGCMFn
	calls := 0
	newGCMFn = func(key []byte) (cipher.AEAD, error) {
		calls++
		if calls == n {
			return nil, errors.New("gcm denied")
		}
		return old(key)
	}
	t.Cleanup(func() { newGCMFn = old })
	fn()
	newGCMFn = old
}

// TestSealSecondGCMError covers Seal's wrapAEAD newGCMFn error (the second call):
// the record AEAD builds, the wrap AEAD fails.
func TestSealSecondGCMError(t *testing.T) {
	withGCMFailingOn(t, 2, func() {
		if _, err := Seal(testKEK(t), []byte("x")); err == nil {
			t.Fatal("Seal succeeded when the wrap GCM failed")
		}
	})
}

// TestOpenSecondGCMError covers Open's recordAEAD newGCMFn error (the second
// call): the wrap GCM builds and unwraps, the record GCM fails.
func TestOpenSecondGCMError(t *testing.T) {
	kek := testKEK(t)
	encoded, err := Seal(kek, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	withGCMFailingOn(t, 2, func() {
		if _, err := Open(kek, encoded); err == nil {
			t.Fatal("Open succeeded when the record GCM failed")
		}
	})
}

// fakeAEAD is a cipher.AEAD whose Open always returns a caller-chosen plaintext,
// letting a test simulate a future format change that unwraps to a wrong-length
// DEK. It is the only way to reach Open's `len(dek) != DEKSize` defensive guard.
type fakeAEAD struct{ openReturn []byte }

func (f fakeAEAD) NonceSize() int { return IVSize }
func (f fakeAEAD) Overhead() int  { return TagSize }
func (f fakeAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return append(dst, plaintext...)
}
func (f fakeAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	return f.openReturn, nil
}

// TestOpenShortDEKGuard covers Open's defensive `len(dek) != DEKSize` guard by
// injecting a fake AEAD whose unwrap yields 16 bytes, simulating a format change
// that would otherwise silently accept a short DEK.
func TestOpenShortDEKGuard(t *testing.T) {
	kek := testKEK(t)
	encoded, err := Seal(kek, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	old := newGCMFn
	newGCMFn = func([]byte) (cipher.AEAD, error) { return fakeAEAD{openReturn: bytes.Repeat([]byte{1}, 16)}, nil }
	t.Cleanup(func() { newGCMFn = old })

	_, err = Open(kek, encoded)
	if err == nil {
		t.Fatal("Open accepted a 16-byte unwrapped DEK")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeSecretDecryptFailed {
		t.Fatalf("err = %v, want secret.decrypt_failed", err)
	}
	newGCMFn = old
}

// TestRotateToReopenFails covers RotateTo's `next.Open(rewrapped)` failure: the
// probe Seal, the Rewrap and the first GCM of next.Open succeed; the second GCM
// of next.Open fails, so the round-trip check rejects the new store.
func TestRotateToReopenFails(t *testing.T) {
	kek := testKEK(t)
	s, _ := NewWithKEK(kek)
	newKEK, _ := DeriveKEK([]byte("n"), bytes.Repeat([]byte{1}, SaltSize), testParams)

	// GCM call order inside RotateTo with an empty sample:
	//   1,2 = Seal(probe); 3,4 = Rewrap; 5,6 = next.Open.
	withGCMFailingOn(t, 6, func() {
		if _, err := s.RotateTo(newKEK, ""); err == nil {
			t.Fatal("RotateTo adopted a store that cannot read the rewrapped probe")
		}
	})
}

// TestNoEntryPanicsOnDegenerateParams audits every exported entry point that
// accepts KDFParams: a zeroed set (KeyLen=0 included) must be refused with an
// error, never a panic. recover() fails the test on any panic.
func TestNoEntryPanicsOnDegenerateParams(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a KDF-parsing entry point panicked on degenerate params: %v", r)
		}
	}()

	salt := bytes.Repeat([]byte{1}, SaltSize)
	bad := KDFParams{} // Memory/Time/Threads/KeyLen all zero
	kek, err := DeriveKEK([]byte("m"), salt, testParams)
	if err != nil {
		t.Fatalf("valid DeriveKEK: %v", err)
	}

	if _, err := DeriveKEK([]byte("m"), salt, bad); err == nil {
		t.Error("DeriveKEK accepted zeroed params")
	}
	if _, err := WrapKEKForRecovery(kek, []byte("p"), bad); err == nil {
		t.Error("WrapKEKForRecovery accepted zeroed params")
	}
	blob, err := WrapKEKForRecovery(kek, []byte("p"), testParams)
	if err != nil {
		t.Fatalf("valid WrapKEKForRecovery: %v", err)
	}
	if _, err := UnwrapKEKFromRecovery(blob, []byte("p"), bad); err == nil {
		t.Error("UnwrapKEKFromRecovery accepted zeroed params")
	}
	if _, err := New(Options{Salt: salt, Params: bad}); err == nil {
		t.Error("New accepted zeroed params")
	}
}
