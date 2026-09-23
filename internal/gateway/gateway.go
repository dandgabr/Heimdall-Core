// Package gateway exposes the minimal inference path: an OpenAI-compatible
// POST /v1/chat/completions that resolves a route through the Router, executes
// it through the Dispatcher and runs the GateChain around the exchange.
//
// It is the THIN handler ADR-0010 §"Consequências" describes: it parses the
// canonical request, resolves the target (a named combo or automatic), calls the
// chain, the router and the dispatcher, and serializes the response (JSON or
// SSE). Failover, cooldown and accounting stay in the Dispatcher; routing stays
// in the Router. The gateway owns none of that.
//
// # Streaming invariants
//
// The dispatcher returns a stream already bound to a single candidate. The
// gateway relays each canonical chunk as an SSE `data:` frame, runs the chain's
// per-chunk stage (so a post-commit gate can Replace or Drop), and on a
// mid-stream error emits a terminal `event: error` frame instead of an HTTP
// status — the 200 was already sent (ADR-0010 §3, contracts executor invariants).
package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// MaxRequestBytes bounds the canonical request body the gateway reads. It is the
// same order as the passthrough limit: a router must not buffer an unbounded
// body on either side.
const MaxRequestBytes = 32 << 20

// Resolver is the Router port the gateway needs.
type Resolver interface {
	Resolve(ctx context.Context, req *contracts.Request, combo domain.ComboID) (contracts.RoutePlan, error)
}

// Dispatcher is the Dispatcher port the gateway needs.
type Dispatcher interface {
	Do(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan) (*contracts.Response, error)
	DoStream(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan) (contracts.Stream, error)
}

// ComboLoader reads a combo by id; it is used to decide whether the request's
// model names a combo. combos.ErrNotFound means "not a combo" (auto resolution).
type ComboLoader interface {
	Get(ctx context.Context, id domain.ComboID) (combos.Combo, error)
}

// Chain is the GateChain port: the pre-commit decision, the per-chunk stage and
// the post-exchange hook, plus whether any gate needs the request body delivered
// (ADR-SEC-03 §2). *pipeline.Chain satisfies it.
type Chain interface {
	PreRequest(ctx context.Context, in contracts.GateInput) (contracts.Decision, error)
	OnResponseChunk(ctx context.Context, in contracts.ChunkInput) (contracts.ChunkDecision, error)
	PostResponse(ctx context.Context, in contracts.GateInput) error
	// ConsumesRequestBody reports whether any pre-request gate needs the body.
	ConsumesRequestBody() bool
}

// Handler serves the chat completions route.
type Handler struct {
	resolver   Resolver
	dispatcher Dispatcher
	combos     ComboLoader
	chain      Chain
	bundle     *i18n.Bundle
	ids        contracts.IDGen
}

// New builds the handler. resolver and dispatcher are required.
func New(resolver Resolver, dispatcher Dispatcher, combosLoader ComboLoader, chain Chain, bundle *i18n.Bundle, ids contracts.IDGen) *Handler {
	if ids == nil {
		ids = domainIDGen{}
	}
	return &Handler{resolver: resolver, dispatcher: dispatcher, combos: combosLoader, chain: chain, bundle: bundle, ids: ids}
}

// domainIDGen adapts domain.NewRequestID.
type domainIDGen struct{}

func (domainIDGen) NewRequestID() domain.RequestID { return domain.NewRequestID() }

// ChatCompletionsPath is the route the gateway mounts (POST). It is exported
// so the composition root can exclude the route from the metadata-only
// observer, whose chain pass would otherwise duplicate the gateway's own.
const ChatCompletionsPath = "/v1/chat/completions"

// Register mounts POST /v1/chat/completions.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+ChatCompletionsPath, h.chat)
}

// parsed is the minimal view the gateway needs from the canonical body.
type parsed struct {
	Model  domain.ModelID
	Stream bool
}

// parse reads the model and stream flag from the canonical body. It does not
// validate the rest: the body is forwarded verbatim so a provider extension
// survives (contracts/executor.go canonical-payload decision).
func parse(body []byte) (parsed, error) {
	var head struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return parsed{}, err
	}
	return parsed{Model: domain.ModelID(head.Model), Stream: head.Stream}, nil
}

// chat is the route handler.
func (h *Handler) chat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		writeError(w, r, invalidBody("could not read the body"))
		return
	}
	if int64(len(body)) > MaxRequestBytes {
		writeError(w, r, invalidBody("body too large"))
		return
	}
	p, err := parse(body)
	if err != nil {
		writeError(w, r, invalidBody("invalid JSON body"))
		return
	}
	if p.Model == "" {
		writeError(w, r, invalidBody("missing model"))
		return
	}

	requestID := h.ids.NewRequestID()
	comboID, reqModel := h.resolveTarget(r.Context(), p.Model)

	req := &contracts.Request{
		ID:    requestID,
		Model: reqModel,
		Combo: comboID,
		// Headers carries NAMES ONLY: the Router uses them for routing hints and
		// must not see a client credential value.
		Headers: headerNamesOnly(r.Header),
	}
	// The upstream request body is forwarded verbatim; extra headers are NOT
	// forwarded, so a client's own Authorization never reaches the upstream (the
	// executor injects the credential's auth itself).
	wire := contracts.WireRequest{Body: body, Model: p.Model, Stream: p.Stream}

	gateIn := contracts.GateInput{
		RequestID: requestID,
		Model:     p.Model,
		Headers:   headerNamesOnly(r.Header),
		Meta:      map[string]string{"http.path": r.URL.Path},
	}
	// The client identity the request PRESENTS (never validated here — that is
	// F5/BD-01) keys the stateful gates: the rate limiter's per-key bucket and
	// the memory namespace (ADR-SEC-07 §3). Absent identity stays absent: no
	// gate may invent a shared identity for the client.
	if key := ClientKeyFromHeaders(r.Header); key != "" {
		gateIn.Meta[ClientKeyMeta] = key
	}
	// The body is delivered ONLY when a gate declared it needs it (ADR-SEC-03
	// §2): the token gate compresses the prompt, so it implements BodyConsumer.
	// Every other boundary (observer, gated executor) leaves Body nil.
	if h.chain != nil && h.chain.ConsumesRequestBody() {
		gateIn.Body = body
	}

	// PreRequest: a Block returns its Synthetic as a successful response (a
	// cache hit or a policy denial), a Reroute is refused until the allowlist
	// dispatcher lands, and a Modify rewrites the working request.
	if h.chain != nil {
		decision, cerr := h.chain.PreRequest(r.Context(), gateIn)
		if cerr != nil {
			writeError(w, r, cerr)
			return
		}
		// Reuse the request-scoped Derived the chain computed once (ADR-0014
		// §6) in every later stage, so the chunk path never recomputes it.
		if decision.Derived != nil {
			gateIn.Derived = decision.Derived
		}
		switch decision.Kind {
		case contracts.DecisionBlock:
			if decision.Synthetic == nil {
				writeError(w, r, errInternal("gate blocked without a synthetic"))
				return
			}
			writeSynthetic(w, decision.Synthetic)
			return
		case contracts.DecisionReroute:
			writeError(w, r, rerouteUnsupported())
			return
		case contracts.DecisionModify:
			if decision.Body != nil {
				wire.Body = decision.Body
				if p2, perr := parse(decision.Body); perr == nil {
					wire.Model = p2.Model
					req.Model = p2.Model
				}
			}
			// A gate may also rewrite request headers (the executor forwards
			// WireRequest.Headers). Applying them here keeps a Modify's intent
			// whole instead of dropping the header half.
			if decision.Headers != nil {
				wire.Headers = decision.Headers
			}
		}
	}

	plan, err := h.resolver.Resolve(r.Context(), req, comboID)
	if err != nil {
		writeError(w, r, err)
		return
	}

	if p.Stream {
		h.stream(w, r, wire, plan, gateIn)
		return
	}
	resp, err := h.dispatcher.Do(r.Context(), wire, plan)
	if err != nil {
		h.postResponse(r.Context(), gateIn)
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if resp.Wire.Status != 0 {
		w.WriteHeader(resp.Wire.Status)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(resp.Wire.Body)
	h.postResponse(r.Context(), gateIn)
}

// stream relays a streaming plan as SSE.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request, wire contracts.WireRequest, plan contracts.RoutePlan, gateIn contracts.GateInput) {
	stream, err := h.dispatcher.DoStream(r.Context(), wire, plan)
	if err != nil {
		h.postResponse(r.Context(), gateIn)
		writeError(w, r, err)
		return
	}
	defer func() {
		_ = stream.Close()
		h.postResponse(r.Context(), gateIn)
	}()

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	index := 0
	// doneRelayed records that a `[DONE]` sentinel already reached the client as
	// a relayed chunk. It is DEFENCE IN DEPTH: the decoders already consume
	// `[DONE]` and turn it into a clean EOF (D-01), so this should never fire —
	// but if a gate Replace or a legacy Stream ever delivers one as data, the
	// gateway must not append a SECOND sentinel at EOF and break strict clients.
	doneRelayed := false
	for {
		ch, rerr := stream.Recv()
		if rerr != nil {
			if rerr != io.EOF {
				writeSSEError(w, flusher, asDomain(rerr))
			} else if !doneRelayed {
				writeSSEDone(w, flusher)
			}
			return
		}
		if h.chain != nil {
			decision, ge := h.chain.OnResponseChunk(r.Context(), contracts.ChunkInput{
				RequestID: gateIn.RequestID,
				Model:     gateIn.Model,
				Headers:   gateIn.Headers,
				Body:      ch.Data,
				Index:     index,
				Committed: true,
				Meta:      gateIn.Meta,
				Derived:   gateIn.Derived,
			})
			index++
			if ge != nil {
				writeSSEError(w, flusher, asDomain(ge))
				return
			}
			switch decision.Kind {
			case contracts.ChunkDrop:
				continue
			case contracts.ChunkReplace:
				ch.Data = decision.Body
			}
		}
		if contracts.IsSSEDone(ch.Data) {
			doneRelayed = true
		}
		writeSSEChunk(w, flusher, ch)
	}
}

// postResponse runs the chain's post-exchange hook (best-effort).
func (h *Handler) postResponse(ctx context.Context, in contracts.GateInput) {
	if h.chain != nil {
		_ = h.chain.PostResponse(ctx, in)
	}
}

// resolveTarget decides whether the request's model names a combo. A combo id is
// returned with an empty model (the Router expands it); otherwise the model is
// returned with a zero combo (automatic resolution).
func (h *Handler) resolveTarget(ctx context.Context, model domain.ModelID) (domain.ComboID, domain.ModelID) {
	if h.combos == nil {
		return "", model
	}
	if _, err := h.combos.Get(ctx, domain.ComboID(model)); err == nil {
		return domain.ComboID(model), ""
	}
	return "", model
}

// writeSSEChunk writes one canonical chunk as an SSE data frame. A named event is
// forwarded as an `event:` line.
func writeSSEChunk(w http.ResponseWriter, flusher http.Flusher, ch contracts.Chunk) {
	var b strings.Builder
	if ch.Event != "" && ch.Event != "message" {
		b.WriteString("event: ")
		b.WriteString(ch.Event)
		b.WriteString("\n")
	}
	if ch.ID != "" {
		b.WriteString("id: ")
		b.WriteString(ch.ID)
		b.WriteString("\n")
	}
	b.WriteString("data: ")
	b.Write(ch.Data)
	b.WriteString("\n\n")
	_, _ = w.Write([]byte(b.String()))
	if flusher != nil {
		flusher.Flush()
	}
}

// writeSSEDone emits the OpenAI terminal sentinel.
func writeSSEDone(w http.ResponseWriter, flusher http.Flusher) {
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// writeSSEError emits a terminal error frame after the status line is committed.
func writeSSEError(w http.ResponseWriter, flusher http.Flusher, de *domain.DomainError) {
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{"code": de.Code, "params": de.Params}})
	_, _ = w.Write([]byte("event: error\ndata: " + string(payload) + "\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// writeSynthetic writes a gate's pre-commit synthetic response.
func writeSynthetic(w http.ResponseWriter, s *contracts.SyntheticResponse) {
	status := s.Status
	if status == 0 {
		status = http.StatusOK
	}
	for k, vs := range s.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	_, _ = w.Write(s.Body)
}

// headerNamesOnly returns the metadata-only header view a gate receives: names
// with empty values, so a token cannot be read from the map.
func headerNamesOnly(src http.Header) http.Header {
	names := make(http.Header, len(src))
	for name := range src {
		names[name] = nil
	}
	return names
}
