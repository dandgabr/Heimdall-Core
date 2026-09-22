package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/secret"
)

// This file is measurement-only: it benchmarks the credential store (with the
// vault sealing the blob), the migration cost and the single-writer contention.
// No production code is touched.
//
//	go test ./internal/store -bench . -benchmem -count=5

// benchParams keeps the derivation cheap; the KDF cost is measured separately in
// internal/secret.
var benchParams = secret.KDFParams{Memory: 8, Time: 1, Threads: 1, KeyLen: 32}

func benchVault(b *testing.B) (*Store, *secret.Store, *CredentialStore) {
	b.Helper()
	st, err := Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { _ = st.Close() })

	salt, err := secret.LoadOrCreateSalt(st)
	if err != nil {
		b.Fatalf("LoadOrCreateSalt: %v", err)
	}
	kek, err := secret.DeriveKEK([]byte("bench-material"), salt, benchParams)
	if err != nil {
		b.Fatalf("DeriveKEK: %v", err)
	}
	sec, err := secret.NewWithKEK(kek)
	if err != nil {
		b.Fatalf("NewWithKEK: %v", err)
	}
	return st, sec, NewCredentialStore(st)
}

func benchCredential(b *testing.B, sec *secret.Store, id string) contracts.Credential {
	b.Helper()
	sealed, err := sec.Seal([]byte("sk-bench-credential-value-0123456789"))
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	return contracts.Credential{
		ID:        domain.CredentialID(id),
		Provider:  domain.ProviderID("z.ai"),
		AuthMode:  contracts.AuthAPIKey,
		Label:     "bench account",
		Meta:      contracts.AccountMeta{Email: "bench@example.com", Plan: "pro"},
		Sealed:    []byte(sealed),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
}

// BenchmarkUpsert measures the write path: envelope validation, meta marshal and
// the ON CONFLICT UPDATE on the single writer connection.
func BenchmarkUpsert(b *testing.B) {
	_, sec, cs := benchVault(b)
	cred := benchCredential(b, sec, "bench-cred")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cs.Upsert(ctx, cred); err != nil {
			b.Fatalf("Upsert: %v", err)
		}
	}
}

// BenchmarkGet measures the read path through the read pool: query, scan, meta
// unmarshal, timestamp parse.
func BenchmarkGet(b *testing.B) {
	_, sec, cs := benchVault(b)
	cred := benchCredential(b, sec, "bench-cred")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		b.Fatalf("Upsert: %v", err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cs.Get(ctx, cred.ID); err != nil {
			b.Fatalf("Get: %v", err)
		}
	}
}

func BenchmarkList(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("rows=%d", n), func(b *testing.B) {
			_, sec, cs := benchVault(b)
			ctx := context.Background()
			for i := 0; i < n; i++ {
				cred := benchCredential(b, sec, fmt.Sprintf("bench-cred-%03d", i))
				if err := cs.Upsert(ctx, cred); err != nil {
					b.Fatalf("seed Upsert: %v", err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := cs.List(ctx); err != nil {
					b.Fatalf("List: %v", err)
				}
			}
		})
	}
}

// BenchmarkGetParallel is the pure-read baseline: it shows how far the read pool
// scales on its own, before any writer contends.
func BenchmarkGetParallel(b *testing.B) {
	_, sec, cs := benchVault(b)
	cred := benchCredential(b, sec, "bench-cred")
	if err := cs.Upsert(context.Background(), cred); err != nil {
		b.Fatalf("Upsert: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			if _, err := cs.Get(ctx, cred.ID); err != nil {
				b.Errorf("Get: %v", err)
				return
			}
		}
	})
}

// BenchmarkGetWithWriterContention is the single-writer exposure: R readers call
// Get while one goroutine hammers Upsert for the whole measured window. Compare
// each reader count against BenchmarkGetParallel to read the write lock's cost.
func BenchmarkGetWithWriterContention(b *testing.B) {
	_, sec, cs := benchVault(b)
	cred := benchCredential(b, sec, "bench-cred")
	ctx := context.Background()
	if err := cs.Upsert(ctx, cred); err != nil {
		b.Fatalf("seed Upsert: %v", err)
	}

	for _, readers := range []int{1, 4, 8} {
		b.Run(fmt.Sprintf("readers=%d", readers), func(b *testing.B) {
			stop := make(chan struct{})
			var writer sync.WaitGroup
			writer.Add(1)
			go func() {
				defer writer.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = cs.Upsert(ctx, cred)
					}
				}
			}()

			b.ReportAllocs()
			b.ResetTimer()
			var inner sync.WaitGroup
			per := b.N / readers
			for i := 0; i < readers; i++ {
				n := per
				if i == 0 {
					n += b.N % readers
				}
				inner.Add(1)
				go func(n int) {
					defer inner.Done()
					for j := 0; j < n; j++ {
						_, _ = cs.Get(ctx, cred.ID)
					}
				}(n)
			}
			inner.Wait()
			b.StopTimer()
			close(stop)
			writer.Wait()
		})
	}
}

// BenchmarkOpenFresh is the cold-boot cost: file creation with 0600/0700,
// pragmas, and both embedded migrations.
func BenchmarkOpenFresh(b *testing.B) {
	dir := b.TempDir()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := Open(filepath.Join(dir, fmt.Sprintf("fresh-%d.db", i)))
		if err != nil {
			b.Fatalf("Open: %v", err)
		}
		if err := st.Close(); err != nil {
			b.Fatalf("Close: %v", err)
		}
	}
}

// BenchmarkMigrateNoop is the per-boot cost on an already-migrated database: read
// the version, list the embedded migrations, decide there is nothing to do.
func BenchmarkMigrateNoop(b *testing.B) {
	st, _, _ := benchVault(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.Migrate(); err != nil {
			b.Fatalf("Migrate: %v", err)
		}
	}
}
