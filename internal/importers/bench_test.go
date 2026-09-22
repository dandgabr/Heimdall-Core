package importers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This file is measurement-only: it benchmarks the import path (read the harness
// auth files, parse the JSON, seal, upsert) and the bare JSON parse. No
// production code is touched.
//
//	go test ./internal/importers -bench . -benchmem -count=5

const benchOpenCodeAuth = `{
	"zai-coding-plan": {"type": "api", "key": "zai-bench-key-000000000000"},
	"ollama-cloud":    {"type": "api", "key": "ollama-bench-key-1111111111"},
	"opencode-go":     {"type": "api", "key": "cc-bench-key-22222222222222"},
	"unknown-harness": {"type": "api", "key": "ignored-bench-key"}
}`

const benchCommandCodeAuth = `{
	"apiKey": "cc-bench-live-key-333333333333333333",
	"userId": "u-bench",
	"userName": "bench",
	"keyName": "bench-key",
	"authenticatedAt": "2026-09-22T00:00:00Z"
}`

// benchImporter lays out the two harness files in a temp HOME and returns an
// importer over an in-memory store (the same fakes the suite uses).
func benchImporter(b *testing.B) *Importer {
	b.Helper()
	home := b.TempDir()

	ocDir := filepath.Join(home, ".local", "share", "opencode")
	if err := os.MkdirAll(ocDir, 0o700); err != nil {
		b.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ocDir, "auth.json"), []byte(benchOpenCodeAuth), 0o600); err != nil {
		b.Fatalf("write opencode auth: %v", err)
	}
	ccDir := filepath.Join(home, ".commandcode")
	if err := os.MkdirAll(ccDir, 0o700); err != nil {
		b.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ccDir, "auth.json"), []byte(benchCommandCodeAuth), 0o600); err != nil {
		b.Fatalf("write commandcode auth: %v", err)
	}

	return &Importer{Store: newMemStore(), Sealer: fakeSealer{}, Home: home, Env: map[string]string{}}
}

// BenchmarkImportAll is the whole import path: two file reads, two JSON parses,
// four seals and four upserts.
func BenchmarkImportAll(b *testing.B) {
	im := benchImporter(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := im.ImportAll(ctx); err != nil {
			b.Fatalf("ImportAll: %v", err)
		}
	}
}

// BenchmarkParseOpenCodeAuth isolates the opencode schema parse (a map of
// heterogeneous entries, so the decode is dynamic).
func BenchmarkParseOpenCodeAuth(b *testing.B) {
	raw := []byte(benchOpenCodeAuth)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var auth opencodeAuth
		if err := json.Unmarshal(raw, &auth); err != nil {
			b.Fatalf("Unmarshal: %v", err)
		}
	}
}

// BenchmarkParseCommandCodeAuth isolates the command-code schema parse (a flat
// struct).
func BenchmarkParseCommandCodeAuth(b *testing.B) {
	raw := []byte(benchCommandCodeAuth)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var cc commandCodeAuth
		if err := json.Unmarshal(raw, &cc); err != nil {
			b.Fatalf("Unmarshal: %v", err)
		}
	}
}
