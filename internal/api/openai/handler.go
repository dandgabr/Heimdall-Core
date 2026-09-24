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

// Model is one entry of the model catalog served by GET /v1/models: an OpenAI
// model id plus the provider that owns (declares) it.
type Model struct {
	// ID is the model id, e.g. "glm-4.6" or "gpt-oss:120b".
	ID string
	// Owner is the ProviderID that declares the model; it becomes owned_by.
	Owner string
}

// Catalog supplies the model list for GET /v1/models. The composition root
// adapts the provider registry and the enabled-provider configuration onto it,
// so this package stays a leaf (it imports only domain and i18n).
type Catalog interface {
	// Models returns the catalog entries in deterministic order.
	Models() []Model
}

// StaticCatalog is a Catalog over a fixed, already-ordered slice.
type StaticCatalog []Model

// Models implements Catalog.
func (s StaticCatalog) Models() []Model { return s }

// Handler serves the OpenAI-compatible routes.
type Handler struct {
	bundle  *i18n.Bundle
	catalog Catalog
}

// New builds the handler over the model catalog. A nil catalog yields an empty
// (but present) list, the shape a client expects from a build with no providers.
func New(bundle *i18n.Bundle, catalog Catalog) *Handler {
	if catalog == nil {
		catalog = StaticCatalog(nil)
	}
	return &Handler{bundle: bundle, catalog: catalog}
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

// modelEntry is one OpenAI `model` object.
type modelEntry struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

// models serves the declared-model catalog in the OpenAI envelope. It lists the
// models of the ENABLED providers, credential-independent: discovery is by
// declaration, while readiness (a usable credential) is the `provider status`
// concern, not the catalog's. An instance with no enabled provider returns an
// empty (but present) data array, never null.
func (h *Handler) models(w http.ResponseWriter, r *http.Request) {
	list := h.catalog.Models()
	data := make([]modelEntry, 0, len(list))
	for _, m := range list {
		data = append(data, modelEntry{ID: m.ID, Object: "model", OwnedBy: m.Owner})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
