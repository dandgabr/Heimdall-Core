package secret

import (
	"crypto/rand"
	"testing"
)

// This file is measurement-only: it adds benchmarks for the vault hot path and
// touches no production code. Run with:
//
//	go test ./internal/secret -bench . -benchmem -count=5

// benchKEK returns a random 32-byte KEK.
func benchKEK(b *testing.B) []byte {
	b.Helper()
	kek := make([]byte, KEKSize)
	if _, err := rand.Read(kek); err != nil {
		b.Fatalf("rand: %v", err)
	}
	return kek
}

// benchPayload returns a deterministic byte slice of the given size.
func benchPayload(size int) []byte {
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

// payloadSizes are the record sizes a credential field realistically takes:
// an API key (256 B), a token bundle / small JSON (4 KiB) and a large OAuth
// blob (64 KiB).
var payloadSizes = []struct {
	name string
	size int
}{
	{"256B", 256},
	{"4KiB", 4 << 10},
	{"64KiB", 64 << 10},
}

func BenchmarkSeal(b *testing.B) {
	kek := benchKEK(b)
	for _, ps := range payloadSizes {
		b.Run(ps.name, func(b *testing.B) {
			payload := benchPayload(ps.size)
			b.SetBytes(int64(ps.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Seal(kek, payload); err != nil {
					b.Fatalf("Seal: %v", err)
				}
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	kek := benchKEK(b)
	for _, ps := range payloadSizes {
		b.Run(ps.name, func(b *testing.B) {
			sealed, err := Seal(kek, benchPayload(ps.size))
			if err != nil {
				b.Fatalf("Seal: %v", err)
			}
			b.SetBytes(int64(ps.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Open(kek, sealed); err != nil {
					b.Fatalf("Open: %v", err)
				}
			}
		})
	}
}

// BenchmarkParseEnvelope isolates the format validation from the decryption, so
// the share of Open that is pure string/parse work is visible.
func BenchmarkParseEnvelope(b *testing.B) {
	kek := benchKEK(b)
	sealed, err := Seal(kek, benchPayload(256))
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseEnvelope(sealed); err != nil {
			b.Fatalf("ParseEnvelope: %v", err)
		}
	}
}

func BenchmarkRewrap(b *testing.B) {
	oldKEK := benchKEK(b)
	newKEK := benchKEK(b)
	sealed, err := Seal(oldKEK, benchPayload(256))
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Rewrap(oldKEK, newKEK, sealed); err != nil {
			b.Fatalf("Rewrap: %v", err)
		}
	}
}

// BenchmarkStoreRewrap is the whole-vault rotation primitive per record, as the
// caller uses it (through the Store, which owns the current KEK).
func BenchmarkStoreRewrap(b *testing.B) {
	oldKEK := benchKEK(b)
	s, err := NewWithKEK(oldKEK)
	if err != nil {
		b.Fatalf("NewWithKEK: %v", err)
	}
	newKEK := benchKEK(b)
	sealed, err := s.Seal(benchPayload(256))
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Rewrap(newKEK, sealed); err != nil {
			b.Fatalf("Rewrap: %v", err)
		}
	}
}

// BenchmarkRotateTo measures the one-shot rotation gate: prove the current key
// reads the sample, rewrap under the new key, prove the new key round-trips.
func BenchmarkRotateTo(b *testing.B) {
	kek := benchKEK(b)
	s, err := NewWithKEK(kek)
	if err != nil {
		b.Fatalf("NewWithKEK: %v", err)
	}
	newKEK := benchKEK(b)
	sealed, err := s.Seal(benchPayload(256))
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.RotateTo(newKEK, sealed); err != nil {
			b.Fatalf("RotateTo: %v", err)
		}
	}
}

// BenchmarkDeriveKEK is the boot-cost measurement. The production parameters are
// deliberately expensive (memory-hard); the reduced set is the test one, kept
// here so the two are directly comparable.
func BenchmarkDeriveKEK(b *testing.B) {
	material := []byte("correct horse battery staple")
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		b.Fatalf("rand: %v", err)
	}

	b.Run("production-64MiB-t2-p4", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := DeriveKEK(material, salt, DefaultKDFParams); err != nil {
				b.Fatalf("DeriveKEK: %v", err)
			}
		}
	})

	b.Run("reduced-8KiB-t1-p1", func(b *testing.B) {
		params := KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := DeriveKEK(material, salt, params); err != nil {
				b.Fatalf("DeriveKEK: %v", err)
			}
		}
	})
}
