package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// fakeService is a configurable Service for the handler tests. Each method
// returns the configured view/error so a handler branch is reachable without a
// live App.
type fakeService struct {
	status       StatusView
	statusErr    error
	providers    []ProviderView
	providersErr error
	testView     ProviderTestView
	testErr      error
	creds        []CredentialView
	credsErr     error
	addView      CredentialView
	addErr       error
	delCredErr   error
	combos       []ComboView
	combosErr    error
	comboView    ComboView
	comboErr     error
	delComboErr  error
	quotas       []QuotaView
	quotasErr    error
	gates        GatesView
	gatesErr     error
	usage        UsageView
	usageErr     error
	rotate       TokenRotateView
	rotateErr    error
	keys         []ClientKeyView
	keysErr      error
	createKey    ClientKeyCreatedView
	createKeyErr error
	revokeKeyErr error

	// last captures the argument of the last mutating call, so a test can
	// assert what the handler passed through.
	lastAdd      AddCredentialRequest
	lastCombo    ComboRequest
	lastLabel    string
	lastProvider domain.ProviderID
	lastCredID   domain.CredentialID
	lastComboID  domain.ComboID
	lastKeyID    domain.ClientID
}

func (f *fakeService) Status(context.Context) (StatusView, error) {
	return f.status, f.statusErr
}
func (f *fakeService) Providers(context.Context) ([]ProviderView, error) {
	return f.providers, f.providersErr
}
func (f *fakeService) ProviderTest(_ context.Context, id domain.ProviderID) (ProviderTestView, error) {
	f.lastProvider = id
	return f.testView, f.testErr
}
func (f *fakeService) Credentials(context.Context) ([]CredentialView, error) {
	return f.creds, f.credsErr
}
func (f *fakeService) AddCredential(_ context.Context, req AddCredentialRequest) (CredentialView, error) {
	f.lastAdd = req
	return f.addView, f.addErr
}
func (f *fakeService) DeleteCredential(_ context.Context, id domain.CredentialID) error {
	f.lastCredID = id
	return f.delCredErr
}
func (f *fakeService) Combos(context.Context) ([]ComboView, error) {
	return f.combos, f.combosErr
}
func (f *fakeService) CreateCombo(_ context.Context, req ComboRequest) (ComboView, error) {
	f.lastCombo = req
	return f.comboView, f.comboErr
}
func (f *fakeService) DeleteCombo(_ context.Context, id domain.ComboID) error {
	f.lastComboID = id
	return f.delComboErr
}
func (f *fakeService) Quotas(context.Context) ([]QuotaView, error) {
	return f.quotas, f.quotasErr
}
func (f *fakeService) Gates(context.Context) (GatesView, error) {
	return f.gates, f.gatesErr
}
func (f *fakeService) Usage(context.Context) (UsageView, error) {
	return f.usage, f.usageErr
}
func (f *fakeService) RotateToken(context.Context) (TokenRotateView, error) {
	return f.rotate, f.rotateErr
}
func (f *fakeService) ClientKeys(context.Context) ([]ClientKeyView, error) {
	return f.keys, f.keysErr
}
func (f *fakeService) CreateClientKey(_ context.Context, label string) (ClientKeyCreatedView, error) {
	f.lastLabel = label
	return f.createKey, f.createKeyErr
}
func (f *fakeService) RevokeClientKey(_ context.Context, id domain.ClientID) error {
	f.lastKeyID = id
	return f.revokeKeyErr
}

// newMux builds a mux with the management routes over the fake service, wrapping
// the token guard exactly as the app does.
func newMux(svc Service) *http.ServeMux {
	mux := http.NewServeMux()
	New(middleware.ManagementAuth{Verify: alwaysValid}, svc).Register(mux)
	return mux
}

// do runs one authenticated request and returns the recorder.
func do(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// decode unmarshals a success body or fails the test.
func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
}

// TestEveryRouteRequiresToken is the acceptance test: every management route
// (read or mutate) rejects a request with no token with 401.
func TestEveryRouteRequiresToken(t *testing.T) {
	svc := &fakeService{}
	mux := newMux(svc)
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/mgmt/status"},
		{http.MethodGet, "/api/mgmt/providers"},
		{http.MethodPost, "/api/mgmt/providers/z.ai/test"},
		{http.MethodGet, "/api/mgmt/credentials"},
		{http.MethodPost, "/api/mgmt/credentials"},
		{http.MethodPost, "/api/mgmt/credentials/c1/delete"},
		{http.MethodGet, "/api/mgmt/combos"},
		{http.MethodPost, "/api/mgmt/combos"},
		{http.MethodDelete, "/api/mgmt/combos/fast"},
		{http.MethodGet, "/api/mgmt/quotas"},
		{http.MethodGet, "/api/mgmt/gates"},
		{http.MethodGet, "/api/mgmt/usage"},
		{http.MethodPost, "/api/mgmt/token/rotate"},
		{http.MethodGet, "/api/mgmt/client-keys"},
		{http.MethodPost, "/api/mgmt/client-keys"},
		{http.MethodPost, "/api/mgmt/client-keys/k1/revoke"},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "api.mgmt.token_invalid") {
				t.Fatalf("body = %q, want the i18n envelope", rec.Body.String())
			}
		})
	}
}

// TestEveryRouteAcceptsValidToken proves the routes are actually mounted (a 401
// is not a 404 masked) and answer with the fake service's payload.
func TestEveryRouteAcceptsValidToken(t *testing.T) {
	svc := &fakeService{}
	mux := newMux(svc)

	cases := []struct {
		method, path, body string
		wantStatus         int
	}{
		{http.MethodGet, "/api/mgmt/status", "", http.StatusOK},
		{http.MethodGet, "/api/mgmt/providers", "", http.StatusOK},
		{http.MethodPost, "/api/mgmt/providers/z.ai/test", "{}", http.StatusOK},
		{http.MethodGet, "/api/mgmt/credentials", "", http.StatusOK},
		{http.MethodPost, "/api/mgmt/credentials", `{"provider":"z.ai","key":"sk-x"}`, http.StatusCreated},
		{http.MethodPost, "/api/mgmt/credentials/c1/delete", "{}", http.StatusOK},
		{http.MethodGet, "/api/mgmt/combos", "", http.StatusOK},
		{http.MethodPost, "/api/mgmt/combos", `{"name":"fast","strategy":"fallback"}`, http.StatusCreated},
		{http.MethodDelete, "/api/mgmt/combos/fast", "", http.StatusOK},
		{http.MethodGet, "/api/mgmt/quotas", "", http.StatusOK},
		{http.MethodGet, "/api/mgmt/gates", "", http.StatusOK},
		{http.MethodGet, "/api/mgmt/usage", "", http.StatusOK},
		{http.MethodPost, "/api/mgmt/token/rotate", "{}", http.StatusOK},
		{http.MethodGet, "/api/mgmt/client-keys", "", http.StatusOK},
		{http.MethodPost, "/api/mgmt/client-keys", `{"label":"x"}`, http.StatusCreated},
		{http.MethodPost, "/api/mgmt/client-keys/k1/revoke", "{}", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := do(t, mux, tc.method, tc.path, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Fatalf("content-type = %q", ct)
			}
		})
	}
}

// TestStatusView passes through the aggregate snapshot.
func TestStatusView(t *testing.T) {
	svc := &fakeService{status: StatusView{
		Version: "1.2.3", UptimeSeconds: 42, Providers: 4, Combos: 2,
		Credentials: 3, ClientKeys: 1, Gates: []string{"logger", "token"},
	}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/status", "")
	var got StatusView
	decode(t, rec, &got)
	if got.Version != "1.2.3" || got.UptimeSeconds != 42 || got.Providers != 4 ||
		got.Combos != 2 || got.Credentials != 3 || got.ClientKeys != 1 || len(got.Gates) != 2 {
		t.Fatalf("status = %+v", got)
	}
}

func TestStatusServiceError(t *testing.T) {
	svc := &fakeService{statusErr: domain.New("boom", domain.WithHTTPStatus(500))}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/status", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestProvidersEmptyListSerializesAsArray proves an empty list is [] not null.
func TestProvidersEmptyListSerializesAsArray(t *testing.T) {
	rec := do(t, newMux(&fakeService{}), http.MethodGet, "/api/mgmt/providers", "")
	var body map[string]json.RawMessage
	decode(t, rec, &body)
	if string(body["providers"]) != "[]" {
		t.Fatalf("providers = %s, want []", body["providers"])
	}
}

func TestProvidersServiceError(t *testing.T) {
	svc := &fakeService{providersErr: domain.New("x", domain.WithHTTPStatus(500))}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/providers", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

// TestProviderTestPassesIDAndReturnsTypedError covers both branches and the
// path-value extraction.
func TestProviderTestPassesIDAndReturnsTypedError(t *testing.T) {
	svc := &fakeService{testView: ProviderTestView{Provider: "z.ai", CredentialID: "c1", Status: 200}}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/providers/z.ai/test", "{}")
	if svc.lastProvider != "z.ai" {
		t.Fatalf("provider = %q, want z.ai", svc.lastProvider)
	}
	var got ProviderTestView
	decode(t, rec, &got)
	if got.Status != 200 || got.CredentialID != "c1" {
		t.Fatalf("test view = %+v", got)
	}

	svc2 := &fakeService{testErr: domain.New(domain.CodeProviderNoCredential,
		domain.WithHTTPStatus(404), domain.WithParams(map[string]string{"provider": "z.ai"}))}
	rec2 := do(t, newMux(svc2), http.MethodPost, "/api/mgmt/providers/z.ai/test", "{}")
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("typed error status = %d, want 404", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), domain.CodeProviderNoCredential) {
		t.Fatalf("body = %q, want the typed code", rec2.Body.String())
	}
}

// TestAddCredentialRejectsMissingFields covers the required-field guard and
// proves the key still reaches the service when present.
func TestAddCredentialRejectsMissingFields(t *testing.T) {
	svc := &fakeService{}
	mux := newMux(svc)

	for _, body := range []string{
		`{"key":"sk-x"}`,
		`{"provider":"z.ai"}`,
		`{"provider":"  ","key":"sk-x"}`,
	} {
		rec := do(t, mux, http.MethodPost, "/api/mgmt/credentials", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s -> status %d, want 400", body, rec.Code)
		}
	}
	// Valid: the key reaches the service (it is sealed there).
	rec := do(t, mux, http.MethodPost, "/api/mgmt/credentials",
		`{"provider":"z.ai","label":"work","key":"sk-secret"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if svc.lastAdd.Provider != "z.ai" || svc.lastAdd.Key != "sk-secret" || svc.lastAdd.Label != "work" {
		t.Fatalf("lastAdd = %+v", svc.lastAdd)
	}
}

// TestAddCredentialNeverEchoesKey is the acceptance test: the supplied key must
// not appear in the response body.
func TestAddCredentialNeverEchoesKey(t *testing.T) {
	svc := &fakeService{addView: CredentialView{ID: "key-z.ai-abc", Provider: "z.ai", AuthMode: "api_key"}}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/credentials",
		`{"provider":"z.ai","key":"sk-live-super-secret"}`)
	if strings.Contains(rec.Body.String(), "sk-live-super-secret") {
		t.Fatalf("response leaked the key: %s", rec.Body.String())
	}
}

func TestAddCredentialServiceError(t *testing.T) {
	svc := &fakeService{addErr: domain.New(domain.CodeProviderNotFound, domain.WithHTTPStatus(404))}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/credentials", `{"provider":"nope","key":"sk-x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestDeleteCredential(t *testing.T) {
	svc := &fakeService{}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/credentials/c9/delete", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if svc.lastCredID != "c9" {
		t.Fatalf("deleted id = %q", svc.lastCredID)
	}
	var body map[string]string
	decode(t, rec, &body)
	if body["deleted"] != "c9" {
		t.Fatalf("body = %v", body)
	}

	svc2 := &fakeService{delCredErr: domain.New(domain.CodeNotFound, domain.WithHTTPStatus(404))}
	rec2 := do(t, newMux(svc2), http.MethodPost, "/api/mgmt/credentials/missing/delete", "{}")
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec2.Code)
	}
}

// TestCreateComboValidation drives the combo mapping and the DAG-error pass
// through.
func TestCreateComboValidation(t *testing.T) {
	svc := &fakeService{comboView: ComboView{Name: "fast", Strategy: "fallback", Depth: 0}}
	mux := newMux(svc)

	// Missing name.
	if rec := do(t, mux, http.MethodPost, "/api/mgmt/combos", `{"strategy":"fallback"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name status = %d, want 400", rec.Code)
	}
	// Valid: the request reaches the service.
	rec := do(t, mux, http.MethodPost, "/api/mgmt/combos",
		`{"name":"fast","strategy":"fallback","steps":[{"kind":"model","ref":"glm-4.6"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if svc.lastCombo.Name != "fast" || len(svc.lastCombo.Steps) != 1 {
		t.Fatalf("lastCombo = %+v", svc.lastCombo)
	}
	// A DAG error from the service surfaces as its typed code.
	svc.comboErr = domain.New(domain.CodeRouteCyclicCombo, domain.WithHTTPStatus(400))
	rec2 := do(t, mux, http.MethodPost, "/api/mgmt/combos", `{"name":"a","strategy":"fallback"}`)
	if rec2.Code != http.StatusBadRequest || !strings.Contains(rec2.Body.String(), domain.CodeRouteCyclicCombo) {
		t.Fatalf("cyclic status = %d body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestDeleteCombo(t *testing.T) {
	svc := &fakeService{}
	rec := do(t, newMux(svc), http.MethodDelete, "/api/mgmt/combos/fast", "")
	if rec.Code != http.StatusOK || svc.lastComboID != "fast" {
		t.Fatalf("status = %d id = %q", rec.Code, svc.lastComboID)
	}

	svc2 := &fakeService{delComboErr: domain.New(domain.CodeNotFound, domain.WithHTTPStatus(404))}
	rec2 := do(t, newMux(svc2), http.MethodDelete, "/api/mgmt/combos/missing", "")
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec2.Code)
	}
}

func TestCombosListAndError(t *testing.T) {
	svc := &fakeService{combos: []ComboView{{Name: "a"}, {Name: "b"}}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/combos", "")
	var body struct {
		Combos []ComboView `json:"combos"`
	}
	decode(t, rec, &body)
	if len(body.Combos) != 2 {
		t.Fatalf("combos = %+v", body.Combos)
	}
	svc2 := &fakeService{combosErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodGet, "/api/mgmt/combos", ""); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestQuotas(t *testing.T) {
	svc := &fakeService{quotas: []QuotaView{{
		Credential: "c1", Provider: "z.ai",
		Windows: []QuotaWindowView{{Kind: "short", Limit: 100, Used: 10, Remaining: 0.9, Source: "header"}},
	}}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/quotas", "")
	var body struct {
		Quotas []QuotaView `json:"quotas"`
	}
	decode(t, rec, &body)
	if len(body.Quotas) != 1 || body.Quotas[0].Windows[0].Kind != "short" {
		t.Fatalf("quotas = %+v", body.Quotas)
	}
	svc2 := &fakeService{quotasErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodGet, "/api/mgmt/quotas", ""); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
	// Empty list serializes as [].
	recEmpty := do(t, newMux(&fakeService{}), http.MethodGet, "/api/mgmt/quotas", "")
	var raw map[string]json.RawMessage
	decode(t, recEmpty, &raw)
	if string(raw["quotas"]) != "[]" {
		t.Fatalf("quotas = %s, want []", raw["quotas"])
	}
}

func TestGates(t *testing.T) {
	svc := &fakeService{gates: GatesView{
		PreRequest: []GateView{{ID: "logger", Stages: []string{"pre_request"}, FailurePolicy: "fail_open"}},
	}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/gates", "")
	var got GatesView
	decode(t, rec, &got)
	if len(got.PreRequest) != 1 || got.PreRequest[0].ID != "logger" {
		t.Fatalf("gates = %+v", got)
	}
	svc2 := &fakeService{gatesErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodGet, "/api/mgmt/gates", ""); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestUsage(t *testing.T) {
	svc := &fakeService{usage: UsageView{
		Total:      UsageAggView{Key: "total", Tokens: 100, Requests: 2, Attempts: 2},
		ByProvider: []UsageAggView{{Key: "z.ai", Tokens: 100}},
	}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/usage", "")
	var got UsageView
	decode(t, rec, &got)
	if got.Total.Tokens != 100 || len(got.ByProvider) != 1 {
		t.Fatalf("usage = %+v", got)
	}
	svc2 := &fakeService{usageErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodGet, "/api/mgmt/usage", ""); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
}

// TestRotateTokenNoStoreAndReveal covers the one-time reveal and the no-store
// header, plus the error branch.
func TestRotateTokenNoStoreAndReveal(t *testing.T) {
	svc := &fakeService{rotate: TokenRotateView{Token: "new-token-plaintext", Path: "/tmp/tok"}}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/token/rotate", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("rotated token response is cacheable")
	}
	var got TokenRotateView
	decode(t, rec, &got)
	if got.Token != "new-token-plaintext" || got.Path != "/tmp/tok" {
		t.Fatalf("rotate view = %+v", got)
	}

	svc2 := &fakeService{rotateErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodPost, "/api/mgmt/token/rotate", "{}"); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
}

// TestClientKeysListNoHash proves the list carries no key/hash field.
func TestClientKeysListNoHash(t *testing.T) {
	svc := &fakeService{keys: []ClientKeyView{{ID: "k1", Label: "editor"}}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/client-keys", "")
	var body map[string]json.RawMessage
	decode(t, rec, &body)
	text := string(body["client_keys"])
	if strings.Contains(text, "key") && strings.Contains(text, "hash") {
		t.Fatalf("client key list may carry a hash: %s", text)
	}
	var list []ClientKeyView
	if err := json.Unmarshal(body["client_keys"], &list); err != nil || len(list) != 1 {
		t.Fatalf("client_keys = %s", body["client_keys"])
	}
	svc2 := &fakeService{keysErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodGet, "/api/mgmt/client-keys", ""); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
	// Empty list serializes as [].
	recEmpty := do(t, newMux(&fakeService{}), http.MethodGet, "/api/mgmt/client-keys", "")
	decode(t, recEmpty, &body)
	if string(body["client_keys"]) != "[]" {
		t.Fatalf("client_keys = %s, want []", body["client_keys"])
	}
}

func TestCreateClientKeyNoStoreAndLabel(t *testing.T) {
	svc := &fakeService{createKey: ClientKeyCreatedView{
		ClientKeyView: ClientKeyView{ID: "k1", Label: "editor"},
		Key:           "hmd_live_abc",
	}}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/client-keys", `{"label":"editor"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("client key response is cacheable")
	}
	if svc.lastLabel != "editor" {
		t.Fatalf("label = %q", svc.lastLabel)
	}
	var got ClientKeyCreatedView
	decode(t, rec, &got)
	if got.Key != "hmd_live_abc" {
		t.Fatalf("key = %q", got.Key)
	}

	svc2 := &fakeService{createKeyErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodPost, "/api/mgmt/client-keys", `{}`); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRevokeClientKey(t *testing.T) {
	svc := &fakeService{}
	rec := do(t, newMux(svc), http.MethodPost, "/api/mgmt/client-keys/k1/revoke", "{}")
	if rec.Code != http.StatusOK || svc.lastKeyID != "k1" {
		t.Fatalf("status = %d id = %q", rec.Code, svc.lastKeyID)
	}
	svc2 := &fakeService{revokeKeyErr: domain.New(domain.CodeClientKeyNotFound, domain.WithHTTPStatus(404))}
	if rec := do(t, newMux(svc2), http.MethodPost, "/api/mgmt/client-keys/nope/revoke", "{}"); rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestCredentialsListNoSealedField proves the credential DTO cannot carry a
// sealed secret.
func TestCredentialsListNoSealedField(t *testing.T) {
	svc := &fakeService{creds: []CredentialView{{ID: "c1", Provider: "z.ai", AuthMode: "api_key", Label: "work"}}}
	rec := do(t, newMux(svc), http.MethodGet, "/api/mgmt/credentials", "")
	if strings.Contains(rec.Body.String(), "sealed") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("credential list carries a secret field: %s", rec.Body.String())
	}
	svc2 := &fakeService{credsErr: domain.New("x", domain.WithHTTPStatus(500))}
	if rec := do(t, newMux(svc2), http.MethodGet, "/api/mgmt/credentials", ""); rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
}

// TestDecodeBodyBranches covers every decodeBody failure: empty, oversized,
// invalid JSON, unknown field, and a read error.
func TestDecodeBodyBranches(t *testing.T) {
	mux := newMux(&fakeService{})

	// Empty body.
	if rec := do(t, mux, http.MethodPost, "/api/mgmt/combos", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body status = %d", rec.Code)
	}
	// Invalid JSON.
	if rec := do(t, mux, http.MethodPost, "/api/mgmt/combos", `{not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d", rec.Code)
	}
	// Unknown field (DisallowUnknownFields).
	if rec := do(t, mux, http.MethodPost, "/api/mgmt/combos", `{"name":"a","strategy":"fallback","bogus":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", rec.Code)
	}
	// Oversized body.
	big := `{"name":"a","strategy":"fallback","prompt":"` + strings.Repeat("x", MaxBodyBytes+10) + `"}`
	if rec := do(t, mux, http.MethodPost, "/api/mgmt/combos", big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status = %d", rec.Code)
	}
}

// TestDecodeBodyReadError covers the io.ReadAll error branch.
func TestDecodeBodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/mgmt/combos", nil)
	req.Body = errReadCloser{}
	if err := decodeBody(req, &ComboRequest{}); err == nil {
		t.Fatal("decodeBody tolerated a read error")
	}
}

// TestHandlerBodyReadErrorRoutes covers the decode-error branch of addCredential
// and createClientKey at the handler level (the read fails before any service
// call).
func TestHandlerBodyReadErrorRoutes(t *testing.T) {
	mux := newMux(&fakeService{})
	for _, path := range []string{"/api/mgmt/credentials", "/api/mgmt/client-keys"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Body = errReadCloser{}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", path, rec.Code)
		}
	}
}

// errReadCloser fails every Read, so decodeBody's read-error branch runs.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (errReadCloser) Close() error             { return nil }

// TestComboFromRequestMapping covers the wire->domain mapper including the
// unknown-strategy and unknown-kind rejections.
func TestComboFromRequestMapping(t *testing.T) {
	combo, err := ComboFromRequest(ComboRequest{
		Name:     "fast",
		Strategy: "fallback",
		Steps: []ComboStepView{
			{Kind: "model", Ref: "glm-4.6", Weight: 3, Prompt: "p", Allowed: []string{"c1", "c2"}, QuotaOnly: true},
			{Kind: "combo-ref", Ref: "other"},
		},
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if combo.Name != "fast" || combo.Strategy != contracts.StrategyFallback || len(combo.Steps) != 2 {
		t.Fatalf("combo = %+v", combo)
	}
	s := combo.Steps[0]
	if s.Kind != combos.StepModel || s.Ref != "glm-4.6" || s.Weight != 3 || s.Prompt != "p" ||
		len(s.AllowedConnections) != 2 || !s.FallbackOnlyOnQuota {
		t.Fatalf("step = %+v", s)
	}

	// Unknown strategy.
	if _, err := ComboFromRequest(ComboRequest{Name: "x", Strategy: "nope"}); !isRouteInvalid(err) {
		t.Fatalf("unknown strategy err = %v", err)
	}
	// Unknown step kind.
	if _, err := ComboFromRequest(ComboRequest{Name: "x", Strategy: "fallback",
		Steps: []ComboStepView{{Kind: "bogus", Ref: "y"}}}); !isRouteInvalid(err) {
		t.Fatalf("unknown kind err = %v", err)
	}
}

func isRouteInvalid(err error) bool {
	de, ok := err.(*domain.DomainError)
	return ok && de.Code == domain.CodeRouteInvalidCombo
}

// TestComboToViewMapping covers the domain->wire mapper, including steps and
// allowed connections.
func TestComboToViewMapping(t *testing.T) {
	c := combos.NewCombo("fast", contracts.StrategyWeighted, []combos.Step{{
		Kind: combos.StepModel, Ref: "glm-4.6", Weight: 2, Prompt: "hi",
		AllowedConnections: []domain.CredentialID{"c1"}, FallbackOnlyOnQuota: true,
	}})
	c.Depth = 1
	v := ComboToView(c)
	if v.Name != "fast" || v.Strategy != "weighted" || v.Depth != 1 || len(v.Steps) != 1 {
		t.Fatalf("view = %+v", v)
	}
	if v.Steps[0].Kind != "model" || v.Steps[0].Weight != 2 || len(v.Steps[0].Allowed) != 1 || !v.Steps[0].QuotaOnly {
		t.Fatalf("step view = %+v", v.Steps[0])
	}
}

// TestNonNil covers both branches of the slice helper.
func TestNonNil(t *testing.T) {
	if got := nonNil[int](nil); got == nil || len(got) != 0 {
		t.Fatalf("nonNil(nil) = %v, want empty non-nil", got)
	}
	in := []int{1, 2}
	if got := nonNil(in); len(got) != 2 {
		t.Fatalf("nonNil = %v", got)
	}
}

// TestRegisterCatchAllSubtree proves a route added under /api/mgmt/ later is
// protected: the guard is on the subtree, and a path with no registered handler
// still runs the token guard before the sub-mux 404.
func TestRegisterCatchAllSubtree(t *testing.T) {
	mux := http.NewServeMux()
	h := New(middleware.ManagementAuth{Verify: alwaysValid}, &fakeService{})
	h.Register(mux)

	// A path under the subtree with no explicit route: the guard runs first.
	req := httptest.NewRequest(http.MethodGet, "/api/mgmt/not-a-real-route", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated unknown subtree route = %d, want 401", rec.Code)
	}

	// With a valid token the sub-mux answers its own 404 for the unknown route,
	// proving the guard admits it to the subtree handler.
	req2 := httptest.NewRequest(http.MethodGet, "/api/mgmt/not-a-real-route", nil)
	req2.Header.Set("Authorization", "Bearer "+testToken)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("authenticated unknown subtree route = %d, want 404", rec2.Code)
	}
}
