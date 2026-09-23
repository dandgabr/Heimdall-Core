package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/api/mgmt"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestMgmtAdapterStatusErrors covers each List error branch in Status by
// dropping the backing table.
func TestMgmtAdapterStatusErrors(t *testing.T) {
	cases := []struct {
		table   string
		wantErr bool
	}{
		{"combos", true},
		{"credentials", true},
		{"client_keys", true},
	}
	for _, tc := range cases {
		t.Run(tc.table, func(t *testing.T) {
			a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
			if _, err := a.Store.Writer().Exec(`DROP TABLE ` + tc.table); err != nil {
				t.Fatalf("drop: %v", err)
			}
			if _, err := a.NewManagementService().Status(context.Background()); err == nil {
				t.Fatalf("Status succeeded without the %s table", tc.table)
			}
		})
	}
}

func TestMgmtAdapterProviderTestError(t *testing.T) {
	a := buildTestApp(t)
	// No credential for z.ai -> the typed error propagates through the adapter.
	if _, err := a.NewManagementService().ProviderTest(context.Background(), "z.ai"); err == nil {
		t.Fatal("ProviderTest succeeded with no credential")
	}
}

// TestMgmtAdapterProviderTestSuccess exercises the adapter's success return over
// a live httptest upstream.
func TestMgmtAdapterProviderTestSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	a := buildProviderApp(t, srv.URL+"/v1")
	seedCredential(t, a, "cred-z", contracts.AuthAPIKey, "sk-live")

	view, err := a.NewManagementService().ProviderTest(context.Background(), "z.ai")
	if err != nil {
		t.Fatalf("ProviderTest: %v", err)
	}
	if view.Provider != "z.ai" || view.CredentialID != "cred-z" || view.Status != http.StatusOK {
		t.Fatalf("view = %+v", view)
	}
}

func TestMgmtAdapterCredentialsErrors(t *testing.T) {
	a := buildTestApp(t)
	if _, err := a.Store.Writer().Exec(`DROP TABLE credentials`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	svc := a.NewManagementService()
	if _, err := svc.Credentials(context.Background()); err == nil {
		t.Fatal("Credentials succeeded without the table")
	}
	if _, err := svc.Quotas(context.Background()); err == nil {
		t.Fatal("Quotas succeeded without the credentials table")
	}
}

func TestMgmtAdapterAddCredentialError(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	svc := a.NewManagementService()
	// Unknown provider -> typed error.
	if _, err := svc.AddCredential(context.Background(), mgmt.AddCredentialRequest{
		Provider: "nope", Label: "x", Key: "sk-x"}); err == nil {
		t.Fatal("AddCredential succeeded for an unknown provider")
	}
}

func TestMgmtAdapterCombosErrors(t *testing.T) {
	a := buildTestApp(t)
	if _, err := a.Store.Writer().Exec(`DROP TABLE combos`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	svc := a.NewManagementService()
	if _, err := svc.Combos(context.Background()); err == nil {
		t.Fatal("Combos succeeded without the table")
	}
	// CreateCombo on a store whose combos table is gone surfaces the store error
	// (a combo with a valid name but no table to read/write).
	_, err := svc.CreateCombo(context.Background(), mgmt.ComboRequest{
		Name: "fast", Strategy: "fallback",
		Steps: []mgmt.ComboStepView{{Kind: "model", Ref: "glm-4.6"}},
	})
	if err == nil {
		t.Fatal("CreateCombo succeeded without the combos table")
	}
}

// TestMgmtAdapterCreateComboMappingError covers CreateCombo's mapper-error
// branch (an unknown strategy is rejected before any store access).
func TestMgmtAdapterCreateComboMappingError(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	_, err := a.NewManagementService().CreateCombo(context.Background(), mgmt.ComboRequest{
		Name: "bad", Strategy: "not-a-strategy",
	})
	if err == nil {
		t.Fatal("CreateCombo accepted an unknown strategy")
	}
}

func TestMgmtAdapterDeleteCredentialAndComboErrors(t *testing.T) {
	a := buildTestApp(t)
	svc := a.NewManagementService()
	if err := svc.DeleteCredential(context.Background(), "missing"); err == nil {
		t.Fatal("DeleteCredential succeeded for a missing id")
	}
	if err := svc.DeleteCombo(context.Background(), "missing"); err == nil {
		t.Fatal("DeleteCombo succeeded for a missing combo")
	}
}

func TestMgmtAdapterUsageError(t *testing.T) {
	a := buildTestApp(t)
	if _, err := a.Store.Writer().Exec(`DROP TABLE usage_attempts`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := a.NewManagementService().Usage(context.Background()); err == nil {
		t.Fatal("Usage succeeded without the usage_attempts table")
	}
}

func TestMgmtAdapterRotateTokenError(t *testing.T) {
	a := buildTestApp(t)
	// Point the token path under a file so the write fails.
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	a.Config.Store.TokenPath = filepath.Join(blocker, "token")
	if _, err := a.NewManagementService().RotateToken(context.Background()); err == nil {
		t.Fatal("RotateToken succeeded with an unwritable token path")
	}
}

func TestMgmtAdapterClientKeysError(t *testing.T) {
	a := buildTestApp(t)
	if _, err := a.Store.Writer().Exec(`DROP TABLE client_keys`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	svc := a.NewManagementService()
	if _, err := svc.ClientKeys(context.Background()); err == nil {
		t.Fatal("ClientKeys succeeded without the table")
	}
	if _, err := svc.CreateClientKey(context.Background(), "x"); err == nil {
		t.Fatal("CreateClientKey succeeded without the table")
	}
}

func TestMgmtAdapterRevokeClientKeyError(t *testing.T) {
	a := buildTestApp(t)
	if err := a.NewManagementService().RevokeClientKey(context.Background(), "missing"); err == nil {
		t.Fatal("RevokeClientKey succeeded for a missing id")
	}
}

// TestMgmtAdapterQuotasWithWindows records a window so the snapshot's non-empty
// branch (terminal + windows) is exercised.
func TestMgmtAdapterQuotasWithWindows(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	seedCredential(t, a, "cred-w", contracts.AuthAPIKey, "sk-w")

	// Persist a window through the durable store, then read it via the API.
	if err := a.QuotaStore.UpsertWindow(context.Background(), "cred-w", contracts.QuotaWindow{
		Kind:      contracts.WindowShort,
		Limit:     100,
		Used:      10,
		Remaining: 0.9,
		Source:    contracts.SourceHeader,
	}); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}
	// Prime the recorder's lazy cache from the durable store BEFORE marking the
	// terminal (a state loaded after SetTerminal would not re-read the store).
	if _, ok := a.QuotaRec.Snapshot(context.Background(), "cred-w"); !ok {
		t.Fatal("snapshot did not load the persisted window")
	}
	a.QuotaRec.SetTerminal("cred-w", domain.CodeQuotaExhausted)

	views, err := a.NewManagementService().Quotas(context.Background())
	if err != nil {
		t.Fatalf("Quotas: %v", err)
	}
	if len(views) != 1 || len(views[0].Windows) != 1 {
		t.Fatalf("views = %+v", views)
	}
	if views[0].TerminalCode != domain.CodeQuotaExhausted {
		t.Fatalf("terminal = %q", views[0].TerminalCode)
	}
	if views[0].Windows[0].Kind != "short" || views[0].Windows[0].Source != "header" {
		t.Fatalf("window = %+v", views[0].Windows[0])
	}
	if views[0].Windows[0].ResetsAt != "" {
		t.Fatalf("resets_at = %q, want empty for an unknown reset", views[0].Windows[0].ResetsAt)
	}
}

// TestMgmtAdapterRotateTokenValueIsTrimmed proves the returned token has no
// trailing newline (the file appends one).
func TestMgmtAdapterRotateTokenTrimmed(t *testing.T) {
	a := buildTestApp(t)
	view, err := a.NewManagementService().RotateToken(context.Background())
	if err != nil {
		t.Fatalf("RotateToken: %v", err)
	}
	if view.Token == "" || view.Token[len(view.Token)-1] == '\n' {
		t.Fatalf("token = %q", view.Token)
	}
	if view.Path != a.Config.Store.TokenPath {
		t.Fatalf("path = %q", view.Path)
	}
}
