// Package openai exposes the OpenAI-compatible HTTP surface.
//
// F0 carries only the discovery routes. The chat completion passthrough lives
// in internal/passthrough and is mounted by the app assembly.
package openai

import (
	"encoding/json"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// Handler serves the OpenAI-compatible routes.
type Handler struct {
	bundle *i18n.Bundle
}

// New builds the handler.
func New(bundle *i18n.Bundle) *Handler {
	return &Handler{bundle: bundle}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /v1/models", h.models)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"code":   domain.CodeHealthOK,
	})
}

// models returns the model catalog. F0 has no providers wired, so the list is
// empty but the envelope matches the OpenAI shape a client expects.
func (h *Handler) models(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   []any{},
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
