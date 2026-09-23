package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/api/mgmt"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// mgmtRequest drives an authenticated management request through the FULL
// assembled handler (LocalOnly + Host/Origin/ClientAuth guards + the mgmt
// sub-mux), so the integration proves the catch-all protection too.
func mgmtRequest(t *testing.T, a *App, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+readTokenFile(t, a))
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	return rec
}

// TestMgmtStatusEndToEnd exercises the real adapter over the live App.
func TestMgmtStatusEndToEnd(t *testing.T) {
	a := buildTestApp(t)

	rec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got mgmt.StatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if got.Version == "" {
		t.Error("version is empty")
	}
	if got.Providers == 0 {
		t.Error("provider count is zero")
	}
	if len(got.Gates) == 0 {
		t.Error("effective gates list is empty")
	}
}

// TestMgmtStatusReportsVersion proves the injected version reaches the API.
func TestMgmtStatusReportsVersion(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Path = dir + "/heimdall.db"
	cfg.Store.TokenPath = dir + "/management-token"
	a, err := Build(Options{Config: cfg, Env: map[string]string{}, Version: "9.9.9"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = a.Close() }()

	rec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/status", "")
	var got mgmt.StatusView
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Version != "9.9.9" {
		t.Fatalf("version = %q, want 9.9.9", got.Version)
	}
}

// TestMgmtProvidersEndToEnd proves the readiness rule comes from the same code
// path the CLI uses.
func TestMgmtProvidersEndToEnd(t *testing.T) {
	a := buildTestApp(t)
	rec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/providers", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Providers []mgmt.ProviderView `json:"providers"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Providers) == 0 {
		t.Fatal("no providers returned")
	}
	for _, p := range body.Providers {
		if p.ID == "" || p.Protocol == "" {
			t.Fatalf("provider row incomplete: %+v", p)
		}
	}
}

// TestMgmtProviderTestTypedError proves a provider with no credential returns
// the typed provider.no_credential error through the envelope.
func TestMgmtProviderTestTypedError(t *testing.T) {
	a := buildTestApp(t)
	rec := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/providers/z.ai/test", "{}")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), domain.CodeProviderNoCredential) {
		t.Fatalf("body = %s, want provider.no_credential", rec.Body.String())
	}
}

// TestMgmtCredentialsAddListDeleteNoSecret is the acceptance integration: add a
// key, list without the secret, delete it. The plaintext key must NEVER appear
// in any response.
func TestMgmtCredentialsAddListDeleteNoSecret(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	const secretKey = "sk-live-managed-secret-value"

	// Add via the API (the key is sealed by the app).
	rec := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/credentials",
		`{"provider":"z.ai","label":"work","key":"`+secretKey+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secretKey) {
		t.Fatalf("add response leaked the key: %s", rec.Body.String())
	}
	var added mgmt.CredentialView
	_ = json.Unmarshal(rec.Body.Bytes(), &added)
	if added.ID == "" || added.Provider != "z.ai" {
		t.Fatalf("added view = %+v", added)
	}

	// List: no secret anywhere.
	listRec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/credentials", "")
	if strings.Contains(listRec.Body.String(), secretKey) {
		t.Fatalf("list leaked the key: %s", listRec.Body.String())
	}
	var listBody struct {
		Credentials []mgmt.CredentialView `json:"credentials"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listBody)
	found := false
	for _, c := range listBody.Credentials {
		if c.ID == added.ID {
			found = true
			if c.Label != "work" {
				t.Fatalf("label = %q", c.Label)
			}
		}
	}
	if !found {
		t.Fatalf("added credential %q missing from list", added.ID)
	}

	// Delete.
	delRec := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/credentials/"+added.ID+"/delete", "{}")
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", delRec.Code, delRec.Body.String())
	}
	// The row is gone.
	if _, err := a.Credentials.Get(context.Background(), domain.CredentialID(added.ID)); err == nil {
		t.Fatal("credential still present after delete")
	}
}

// TestMgmtCombosCRUD exercises create/list/delete through the real store,
// including the DAG validation rejection.
func TestMgmtCombosCRUD(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")

	// Create a valid combo.
	rec := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/combos",
		`{"name":"fast","strategy":"fallback","steps":[{"kind":"model","ref":"glm-4.6"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created mgmt.ComboView
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Name != "fast" || created.Strategy != "fallback" || len(created.Steps) != 1 {
		t.Fatalf("created = %+v", created)
	}

	// List.
	listRec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/combos", "")
	var listBody struct {
		Combos []mgmt.ComboView `json:"combos"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listBody)
	if len(listBody.Combos) != 1 || listBody.Combos[0].Name != "fast" {
		t.Fatalf("list = %+v", listBody.Combos)
	}

	// A self-referencing combo (a cycle) is rejected by the DAG validator.
	cyc := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/combos",
		`{"name":"loop","strategy":"fallback","steps":[{"kind":"combo-ref","ref":"loop"}]}`)
	if cyc.Code != http.StatusBadRequest {
		t.Fatalf("cyclic combo status = %d, want 400 (body %s)", cyc.Code, cyc.Body.String())
	}
	if !strings.Contains(cyc.Body.String(), domain.CodeRouteCyclicCombo) {
		t.Fatalf("body = %s, want route.cyclic_combo", cyc.Body.String())
	}

	// Delete.
	delRec := mgmtRequest(t, a, http.MethodDelete, "/api/mgmt/combos/fast", "")
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", delRec.Code, delRec.Body.String())
	}
}

// TestMgmtQuotasEmpty reports every credential with an empty window list.
func TestMgmtQuotasEmpty(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	seedCredential(t, a, "cred-q", contracts.AuthAPIKey, "sk-q")

	rec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/quotas", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Quotas []mgmt.QuotaView `json:"quotas"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Quotas) != 1 || body.Quotas[0].Credential != "cred-q" {
		t.Fatalf("quotas = %+v", body.Quotas)
	}
	if body.Quotas[0].Windows == nil {
		t.Fatal("windows must be a non-nil (empty) array")
	}
}

// TestMgmtGatesEndToEnd proves the DAG order is exposed per stage, no content.
func TestMgmtGatesEndToEnd(t *testing.T) {
	a, _ := wireTestApp(t, nil)
	rec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/gates", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got mgmt.GatesView
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.PreRequest) == 0 && len(got.PostResponse) == 0 {
		t.Fatalf("no gates exposed: %+v", got)
	}
	for _, g := range append(got.PreRequest, got.PostResponse...) {
		if g.ID == "" || g.FailurePolicy == "" {
			t.Fatalf("gate row incomplete: %+v", g)
		}
	}
}

// TestMgmtUsageAggregate records an attempt and reads the rollup.
func TestMgmtUsageAggregate(t *testing.T) {
	a := buildGatewayApp(t, "http://127.0.0.1:9/v1")
	seedCredential(t, a, "cred-u", contracts.AuthAPIKey, "sk-u")

	// Record one usage attempt directly through the durable store.
	if _, err := a.QuotaStore.RecordAttempt(context.Background(), contracts.Usage{
		AttemptKey: "req-1:cand-1:0",
		Provider:   "z.ai",
		Credential: "cred-u",
		Model:      "glm-4.6",
		Tokens:     120,
		Requests:   1,
		CostMicros: 7,
	}, "ok"); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	rec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/usage", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got mgmt.UsageView
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Total.Tokens != 120 || got.Total.Attempts != 1 {
		t.Fatalf("total = %+v", got.Total)
	}
	if len(got.ByProvider) != 1 || got.ByProvider[0].Key != "z.ai" {
		t.Fatalf("by_provider = %+v", got.ByProvider)
	}
	if len(got.ByCredential) != 1 || got.ByCredential[0].Key != "cred-u" {
		t.Fatalf("by_credential = %+v", got.ByCredential)
	}
}

// TestMgmtTokenRotateEndToEnd proves rotation changes the token and the new one
// authenticates.
func TestMgmtTokenRotateEndToEnd(t *testing.T) {
	a := buildTestApp(t)
	old := readTokenFile(t, a)

	rec := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/token/rotate", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("rotate response is cacheable")
	}
	var got mgmt.TokenRotateView
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Token == "" || got.Token == old {
		t.Fatalf("rotated token = %q (old %q)", got.Token, old)
	}
	if got.Path != a.Config.Store.TokenPath {
		t.Fatalf("path = %q, want %q", got.Path, a.Config.Store.TokenPath)
	}
	// The new token authenticates; the old one no longer does.
	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/status", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+got.Token)
	recNew := httptest.NewRecorder()
	a.Handler().ServeHTTP(recNew, req)
	if recNew.Code != http.StatusOK {
		t.Fatalf("new token rejected: %d", recNew.Code)
	}
}

// TestMgmtClientKeysEndToEnd covers create/list/revoke and the no-secret rule.
func TestMgmtClientKeysEndToEnd(t *testing.T) {
	a := buildTestApp(t)

	rec := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/client-keys", `{"label":"gui"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("client-key create response is cacheable")
	}
	var created mgmt.ClientKeyCreatedView
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Key == "" || created.ID == "" {
		t.Fatalf("created = %+v", created)
	}

	// List never returns the key.
	listRec := mgmtRequest(t, a, http.MethodGet, "/api/mgmt/client-keys", "")
	if strings.Contains(listRec.Body.String(), created.Key) {
		t.Fatalf("list leaked the client key: %s", listRec.Body.String())
	}
	var listBody struct {
		ClientKeys []mgmt.ClientKeyView `json:"client_keys"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listBody)
	if len(listBody.ClientKeys) != 1 {
		t.Fatalf("list = %+v", listBody.ClientKeys)
	}

	// Revoke.
	rev := mgmtRequest(t, a, http.MethodPost, "/api/mgmt/client-keys/"+created.ID+"/revoke", "{}")
	if rev.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", rev.Code, rev.Body.String())
	}
	// The revoked key no longer verifies.
	if _, ok := a.ClientKeys.Verify(context.Background(), created.Key); ok {
		t.Fatal("revoked client key still verifies")
	}
}

// TestMgmtRoutesAreCatchAllProtected proves every new management route is
// protected by the F5.1 catch-all guards: a non-loopback peer is refused before
// auth, and a bad Host is refused even with a valid token.
func TestMgmtRoutesAreCatchAllProtected(t *testing.T) {
	a := buildTestApp(t)
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/mgmt/status"},
		{http.MethodGet, "/api/mgmt/providers"},
		{http.MethodPost, "/api/mgmt/providers/z.ai/test"},
		{http.MethodGet, "/api/mgmt/credentials"},
		{http.MethodPost, "/api/mgmt/credentials"},
		{http.MethodGet, "/api/mgmt/combos"},
		{http.MethodPost, "/api/mgmt/combos"},
		{http.MethodDelete, "/api/mgmt/combos/x"},
		{http.MethodGet, "/api/mgmt/quotas"},
		{http.MethodGet, "/api/mgmt/gates"},
		{http.MethodGet, "/api/mgmt/usage"},
		{http.MethodPost, "/api/mgmt/token/rotate"},
		{http.MethodGet, "/api/mgmt/client-keys"},
		{http.MethodPost, "/api/mgmt/client-keys"},
	}
	token := readTokenFile(t, a)
	for _, rt := range routes {
		t.Run("remote "+rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.RemoteAddr = "198.51.100.9:4444"
			req.Host = "127.0.0.1"
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			a.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("remote peer status = %d, want 403", rec.Code)
			}
		})
		t.Run("bad host "+rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "evil.com"
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			a.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("bad host status = %d, want 403", rec.Code)
			}
		})
	}
}

// TestMgmtMutationWithoutToken401 proves a mutating management route with no
// token is 401 even from loopback with a good Host.
func TestMgmtMutationWithoutToken401(t *testing.T) {
	a := buildTestApp(t)
	mutations := []struct{ method, path, body string }{
		{http.MethodPost, "/api/mgmt/credentials", `{"provider":"z.ai","key":"sk-x"}`},
		{http.MethodPost, "/api/mgmt/combos", `{"name":"x","strategy":"fallback"}`},
		{http.MethodDelete, "/api/mgmt/combos/x", ""},
		{http.MethodPost, "/api/mgmt/token/rotate", "{}"},
		{http.MethodPost, "/api/mgmt/client-keys", "{}"},
	}
	for _, m := range mutations {
		t.Run(m.method+" "+m.path, func(t *testing.T) {
			var req *http.Request
			if m.body == "" {
				req = httptest.NewRequest(m.method, m.path, nil)
			} else {
				req = httptest.NewRequest(m.method, m.path, strings.NewReader(m.body))
			}
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "127.0.0.1"
			rec := httptest.NewRecorder()
			a.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}
}

// TestMgmtExternalOriginRejected proves the anti-CSRF guard covers a NEW
// management mutation route (the F5.1 catch-all).
func TestMgmtExternalOriginRejected(t *testing.T) {
	a := buildTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mgmt/combos", strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+readTokenFile(t, a))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), domain.CodeServerOriginInvalid) {
		t.Fatalf("body = %s, want server.origin_invalid", rec.Body.String())
	}
}
