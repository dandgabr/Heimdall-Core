package oauth

import "testing"

// This file is measurement-only: it benchmarks the PKCE/state generators, which
// run once per interactive authorization attempt. No production code is touched.
//
//	go test ./internal/auth/oauth -bench . -benchmem -count=5

func BenchmarkNewState(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewState(); err != nil {
			b.Fatalf("NewState: %v", err)
		}
	}
}

func BenchmarkNewPKCEVerifier(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := NewPKCEVerifier(); err != nil {
			b.Fatalf("NewPKCEVerifier: %v", err)
		}
	}
}
