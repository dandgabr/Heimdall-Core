package passthrough

import (
	"io"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Handler exposes the passthrough chat completion route.
type Handler struct {
	client *Client
}

// NewHandler builds the passthrough handler.
func NewHandler(client *Client) *Handler {
	return &Handler{client: client}
}

// Register mounts the route.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/chat/completions", h.chatCompletions)
}

func (h *Handler) chatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		middleware.WriteError(w, r, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "cannot read body"})))
		return
	}
	if int64(len(body)) > MaxRequestBytes {
		middleware.WriteError(w, r, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusRequestEntityTooLarge),
			domain.WithParams(map[string]string{"reason": "body too large"})))
		return
	}

	_, stream, err := readStreamFlag(body)
	if err != nil {
		middleware.WriteError(w, r, domain.New(domain.CodeInvalidRequest,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "invalid JSON body"})))
		return
	}

	if stream {
		if _, err := h.client.Stream(r.Context(), body, w); err != nil {
			middleware.WriteError(w, r, err)
		}
		return
	}

	out, err := h.client.Complete(r.Context(), body)
	if err != nil {
		middleware.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
