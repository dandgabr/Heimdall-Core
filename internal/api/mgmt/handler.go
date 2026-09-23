package mgmt

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// MaxBodyBytes bounds the management request body. The largest legitimate body
// is a combo with a handful of steps or an API key; 1 MiB is generous and stops
// an unbounded read.
const MaxBodyBytes = 1 << 20

// Handler serves the management routes.
type Handler struct {
	auth middleware.ManagementAuth
	svc  Service
	// rotation throttles the token-rotation route (ADR-SEC-06 §4.2). It is
	// built with the default window; a test may replace it with a tighter or
	// clock-injected one.
	rotation *RotationThrottle
}

// New builds the management handler. auth is applied to EVERY route (no
// management route is public), and svc is the composition-root implementation
// of the management port.
func New(auth middleware.ManagementAuth, svc Service) *Handler {
	return &Handler{auth: auth, svc: svc, rotation: NewRotationThrottle(DefaultRotationWindow, nil)}
}

// WithRotationThrottle replaces the rotation throttle, so the composition root
// can share ONE throttle across Handler() instances (a per-Handler throttle
// would forget the last rotation and never enforce the window). A nil throttle
// disables rotation limiting.
func (h *Handler) WithRotationThrottle(t *RotationThrottle) *Handler {
	h.rotation = t
	return h
}

// Register mounts the management routes on mux.
//
// All routes live under the "/api/mgmt/" subtree, and the WHOLE subtree is
// wrapped in ONE authenticated sub-mux. Registering with the subtree pattern
// means a route added later is guarded by construction: it cannot be mounted
// under /api/mgmt/ without inheriting the token guard, exactly the catch-all
// rule ADR-SEC-06 §1.2 mandates (LocalOnly wraps the outer mux the same way).
//
// Route classes (ADR-SEC-06 §1): every one of these is a MUTATION-class route
// (management surface), so every one requires the management token; there is no
// public management route. GET reads are authenticated because they expose
// operational state (credentials metadata, quotas, accounting).
func (h *Handler) Register(mux *http.ServeMux) {
	guarded := http.NewServeMux()

	// 1. Status.
	guarded.HandleFunc("GET /api/mgmt/status", h.status)

	// 2. Providers.
	guarded.HandleFunc("GET /api/mgmt/providers", h.providers)
	guarded.HandleFunc("POST /api/mgmt/providers/{id}/test", h.providerTest)

	// 3. Credentials.
	guarded.HandleFunc("GET /api/mgmt/credentials", h.credentials)
	guarded.HandleFunc("POST /api/mgmt/credentials", h.addCredential)
	guarded.HandleFunc("POST /api/mgmt/credentials/{id}/delete", h.deleteCredential)

	// 4. Combos.
	guarded.HandleFunc("GET /api/mgmt/combos", h.combos)
	guarded.HandleFunc("POST /api/mgmt/combos", h.createCombo)
	guarded.HandleFunc("DELETE /api/mgmt/combos/{name}", h.deleteCombo)

	// 5. Quotas.
	guarded.HandleFunc("GET /api/mgmt/quotas", h.quotas)

	// 6. Gates.
	guarded.HandleFunc("GET /api/mgmt/gates", h.gates)

	// 7. Usage accounting.
	guarded.HandleFunc("GET /api/mgmt/usage", h.usage)

	// 8. Management token rotation (one-time reveal).
	guarded.HandleFunc("POST /api/mgmt/token/rotate", h.rotateToken)

	// 9. Client keys (one-time reveal on create).
	guarded.HandleFunc("GET /api/mgmt/client-keys", h.clientKeys)
	guarded.HandleFunc("POST /api/mgmt/client-keys", h.createClientKey)
	guarded.HandleFunc("POST /api/mgmt/client-keys/{id}/revoke", h.revokeClientKey)

	// 10. Keep the F0 ping probe, now authenticated like the rest.
	guarded.HandleFunc("GET /api/mgmt/ping", h.ping)

	// The subtree handler mounts the authenticated server under the catch-all
	// "/api/mgmt/" pattern, so the token guard runs for EVERY path in it.
	mux.Handle("/api/mgmt/", h.auth.Middleware(guarded))
}

// --- handlers ---

func (h *Handler) ping(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"code":   domain.CodePingOK,
	})
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Status(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) providers(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Providers(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": nonNil(v)})
}

func (h *Handler) providerTest(w http.ResponseWriter, r *http.Request) {
	id := domain.ProviderID(r.PathValue("id"))
	v, err := h.svc.ProviderTest(r.Context(), id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) credentials(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Credentials(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": nonNil(v)})
}

func (h *Handler) addCredential(w http.ResponseWriter, r *http.Request) {
	var req AddCredentialRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if strings.TrimSpace(req.Provider) == "" || strings.TrimSpace(req.Key) == "" {
		writeError(w, r, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"reason": "provider and key are required"})))
		return
	}
	v, err := h.svc.AddCredential(r.Context(), req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *Handler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id := domain.CredentialID(r.PathValue("id"))
	if err := h.svc.DeleteCredential(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": string(id)})
}

func (h *Handler) combos(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Combos(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"combos": nonNil(v)})
}

func (h *Handler) createCombo(w http.ResponseWriter, r *http.Request) {
	var req ComboRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, r, domain.New(domain.CodeRouteInvalidCombo,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"name": req.Name, "reason": "name is required"})))
		return
	}
	v, err := h.svc.CreateCombo(r.Context(), req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *Handler) deleteCombo(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.svc.DeleteCombo(r.Context(), domain.ComboID(name)); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

func (h *Handler) quotas(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Quotas(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"quotas": nonNil(v)})
}

func (h *Handler) gates(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Gates(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Usage(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) clientKeys(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.ClientKeys(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client_keys": nonNil(v)})
}

func (h *Handler) createClientKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	v, err := h.svc.CreateClientKey(r.Context(), req.Label)
	if err != nil {
		writeError(w, r, err)
		return
	}
	// A new client key is a one-time secret: never cached.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, v)
}

func (h *Handler) revokeClientKey(w http.ResponseWriter, r *http.Request) {
	id := domain.ClientID(r.PathValue("id"))
	if err := h.svc.RevokeClientKey(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": string(id)})
}

// --- wire helpers ---

// writeJSON renders a success body. It is applied to DTOs that have no secret
// field by construction, so a handler cannot leak a secret through it.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError renders a DomainError through the shared i18n envelope, applying
// the central redactor to every param (ADR-0002). It reuses the middleware
// helper so the management surface shares one error format with every other
// handler.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	middleware.WriteError(w, r, err)
}

// decodeBody reads a bounded JSON body into dst. An unreadable, oversized or
// malformed body becomes error.invalid_request (400), never a 500. The body is
// never logged.
func decodeBody(r *http.Request, dst any) error {
	reader := io.LimitReader(r.Body, MaxBodyBytes+1)
	raw, err := io.ReadAll(reader)
	if err != nil {
		return invalidBody("could not read the body")
	}
	if int64(len(raw)) > MaxBodyBytes {
		return invalidBody("body too large")
	}
	if len(raw) == 0 {
		return invalidBody("empty body")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalidBody("invalid JSON body")
	}
	return nil
}

// invalidBody is a client-scoped, non-retryable 400 (error.invalid_request).
func invalidBody(reason string) error {
	return domain.New(domain.CodeInvalidRequest,
		domain.WithHTTPStatus(http.StatusBadRequest),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": reason}))
}

// nonNil returns a non-nil slice so an empty list serializes as [] rather than
// null, which a GUI can iterate without a nil check.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// ComboFromRequest converts a wire request into the domain combo the store
// validates and persists. It is exported so the composition root reuses the
// exact same mapping the handler would, keeping the DAG validation in one path.
//
// A step kind is parsed through the shared vocabulary; an unknown kind or
// strategy is a route.invalid_combo error at this boundary, so the store never
// sees a malformed request.
func ComboFromRequest(req ComboRequest) (combos.Combo, error) {
	strategy, ok := contracts.ParseStrategyKind(req.Strategy)
	if !ok {
		return combos.Combo{}, domain.New(domain.CodeRouteInvalidCombo,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{
				"name": req.Name, "reason": "unknown strategy " + req.Strategy}))
	}
	steps := make([]combos.Step, 0, len(req.Steps))
	for _, s := range req.Steps {
		kind := combos.StepKind(s.Kind)
		if !kind.IsKnown() {
			return combos.Combo{}, domain.New(domain.CodeRouteInvalidCombo,
				domain.WithHTTPStatus(http.StatusBadRequest),
				domain.WithScope(domain.ScopeRequest),
				domain.WithParams(map[string]string{
					"name": req.Name, "reason": "unknown step kind " + s.Kind}))
		}
		step := combos.Step{
			Kind:                kind,
			Ref:                 s.Ref,
			Weight:              s.Weight,
			Prompt:              s.Prompt,
			FallbackOnlyOnQuota: s.QuotaOnly,
		}
		for _, id := range s.Allowed {
			step.AllowedConnections = append(step.AllowedConnections, domain.CredentialID(id))
		}
		steps = append(steps, step)
	}
	return combos.NewCombo(req.Name, strategy, steps), nil
}

// ComboToView renders a persisted combo for the wire.
func ComboToView(c combos.Combo) ComboView {
	view := ComboView{
		Name:     c.Name,
		Strategy: c.Strategy.String(),
		Depth:    c.Depth,
		Steps:    make([]ComboStepView, 0, len(c.Steps)),
	}
	for _, s := range c.Steps {
		sv := ComboStepView{
			Kind:      string(s.Kind),
			Ref:       s.Ref,
			Weight:    s.Weight,
			Prompt:    s.Prompt,
			QuotaOnly: s.FallbackOnlyOnQuota,
		}
		for _, id := range s.AllowedConnections {
			sv.Allowed = append(sv.Allowed, string(id))
		}
		view.Steps = append(view.Steps, sv)
	}
	return view
}
