package app

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestQuotaInfosEmptyAndWithCredential covers the inspect surface's quota read.
func TestQuotaInfosEmptyAndWithCredential(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	infos, err := a.QuotaInfos()
	if err != nil {
		t.Fatalf("QuotaInfos (empty): %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("QuotaInfos = %+v, want none", infos)
	}

	seedCredential(t, a, "cred-a", contracts.AuthAPIKey, "sk-a")
	// Persist a window and prime the recorder so the with-state branch runs.
	if err := a.QuotaStore.UpsertWindow(context.Background(), "cred-a", contracts.QuotaWindow{
		Kind: contracts.WindowShort, Limit: 100, Used: 10, Remaining: 0.9, Source: contracts.SourceHeader,
	}); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}
	if _, ok := a.QuotaRec.Snapshot(context.Background(), "cred-a"); !ok {
		t.Fatal("recorder did not load the persisted window")
	}

	infos, err = a.QuotaInfos()
	if err != nil {
		t.Fatalf("QuotaInfos: %v", err)
	}
	if len(infos) != 1 || infos[0].Credential != "cred-a" || !infos[0].HasState || len(infos[0].Windows) != 1 {
		t.Fatalf("infos = %+v, want one credential with a window", infos)
	}
}

// TestQuotaInfosSorted proves multiple credentials are returned in deterministic
// id order.
func TestQuotaInfosSorted(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	seedCredential(t, a, "zeta", contracts.AuthAPIKey, "sk-z")
	seedCredential(t, a, "alpha", contracts.AuthAPIKey, "sk-a")
	infos, err := a.QuotaInfos()
	if err != nil {
		t.Fatalf("QuotaInfos: %v", err)
	}
	if len(infos) != 2 || infos[0].Credential != "alpha" || infos[1].Credential != "zeta" {
		t.Fatalf("infos = %+v, want alpha before zeta", infos)
	}
}

// TestQuotaInfoForUnknownAndState covers both branches of the single read.
func TestQuotaInfoForUnknownAndState(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	if _, found, err := a.QuotaInfoFor("missing"); err != nil || found {
		t.Fatalf("QuotaInfoFor(missing) = found=%v err=%v, want not found", found, err)
	}

	seedCredential(t, a, "cred-b", contracts.AuthAPIKey, "sk-b")
	// Record a window so the state is non-empty.
	if err := a.QuotaStore.UpsertWindow(context.Background(), "cred-b", contracts.QuotaWindow{
		Kind: contracts.WindowShort, Limit: 100, Used: 10, Remaining: 0.9, Source: contracts.SourceHeader,
	}); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}
	// Prime the recorder so it loads the persisted window.
	if _, ok := a.QuotaRec.Snapshot(context.Background(), "cred-b"); !ok {
		t.Fatal("recorder did not load the persisted window")
	}
	info, found, err := a.QuotaInfoFor("cred-b")
	if err != nil || !found {
		t.Fatalf("QuotaInfoFor(cred-b) = found=%v err=%v", found, err)
	}
	if !info.HasState || len(info.Windows) != 1 || info.Windows[0].Kind != "short" {
		t.Fatalf("info = %+v", info)
	}
}

// TestQuotaInfosListError covers the credential-list error branch.
func TestQuotaInfosListError(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	if _, err := a.Store.Writer().Exec(`DROP TABLE credentials`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := a.QuotaInfos(); err == nil {
		t.Fatal("QuotaInfos succeeded without the credentials table")
	}
	if _, _, err := a.QuotaInfoFor("x"); err == nil {
		t.Fatal("QuotaInfoFor succeeded without the credentials table")
	}
}

// TestGateInfosAndLookup covers the gate introspection: the logger gate is
// always in the chain, and the lookup finds it by name (and misses an unknown).
func TestGateInfosAndLookup(t *testing.T) {
	a := buildTestApp(t)
	infos := a.GateInfos()
	if len(infos) == 0 {
		t.Fatal("GateInfos returned none; the logger gate is always present")
	}
	sawLogger := false
	for _, g := range infos {
		if g.ID == "logger" {
			sawLogger = true
			if g.FailurePolicy == "" || len(g.Stages) == 0 || g.Group != "logger" {
				t.Fatalf("logger gate info incomplete: %+v", g)
			}
		}
	}
	if !sawLogger {
		t.Fatal("GateInfos is missing the logger gate")
	}
	if _, found := a.GateInfoByName("logger"); !found {
		t.Fatal("GateInfoByName(logger) not found")
	}
	if _, found := a.GateInfoByName("nope"); found {
		t.Fatal("GateInfoByName(nope) unexpectedly found")
	}
}

// TestGateInfosDedupeAcrossStages proves a gate acting in several stages appears
// once in the listing.
func TestGateInfosDedupeAcrossStages(t *testing.T) {
	a := buildTestApp(t)
	seen := map[string]int{}
	for _, g := range a.GateInfos() {
		seen[g.ID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("gate %q appears %d times, want once", id, n)
		}
	}
}

// TestGateGroupMapping covers every group classification and the unknown
// fallback.
func TestGateGroupMapping(t *testing.T) {
	cases := map[string]string{
		"logger": "logger", "token": "token",
		"memory-retriever": "memory", "memory-writer": "memory",
		"credential-masker": "security", "pii-masker": "security",
		"injection-guard": "security", "ssrf-guard": "security", "rate-limit": "security",
		"mystery": "unknown",
	}
	for id, want := range cases {
		if got := gateGroup(id); got != want {
			t.Errorf("gateGroup(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestGateInfosWithDeclaredFields proves a gate that declares a read/write set
// surfaces it (the security gates do).
func TestGateInfosWithDeclaredFields(t *testing.T) {
	a, _ := wireTestApp(t, func(c *config.Config) {
		c.Features.Gates.Security = true
	})
	for _, g := range a.GateInfos() {
		if g.ID == "pii-masker" {
			if len(g.Reads) == 0 || len(g.Writes) == 0 {
				t.Fatalf("pii-masker declared fields not surfaced: %+v", g)
			}
			return
		}
	}
	t.Fatal("pii-masker not in the effective chain")
}

var _ = domain.CodeCLIQuotaNoState
