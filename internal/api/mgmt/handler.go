// Package mgmt exposes the local Management API.
//
// Every route here is wrapped by middleware.LocalOnly at the assembly point, and
// the auth guard is applied here for the routes that require it.
package mgmt

import (
	"encoding/json"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Handler serves the management routes.
type Handler struct {
	auth middleware.ManagementAuth
}

// New builds the management handler. auth is applied to every non-public route.
func New(auth middleware.ManagementAuth) *Handler {
	return &Handler{auth: auth}
}

// Register mounts the routes on mux. /api/mgmt/ping requires the management
// token; keeping it authenticated from F0 exercises the guard end-to-end.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/mgmt/ping", h.auth.Middleware(http.HandlerFunc(h.ping)))
}

func (h *Handler) ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"code":   domain.CodePingOK,
	})
}
