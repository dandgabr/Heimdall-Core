package pipeline

import (
	"context"
	"net/http"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// GatedExecutor wraps a contracts.Executor so the GateChain runs on the EXECUTION
// path too (F2.7): PreRequest before Do/DoStream and PostResponse after, with
// metadata-only inputs (no body, no header values).
//
// It is a decorator, not a different executor: the family's executor still owns
// transport+auth, and the pipeline only inserts the gate stages around it. The
// chain decides Block/Reroute pre-commit; a Block returns its Synthetic as the
// response, which is a success path (e.g. a semantic-cache hit), not an error.
//
// Invariant (plan v2): the chain runs with the MINIMUM content. This decorator
// passes the request's header NAMES only and never the body, so a gate cannot
// leak payload or credentials.
type GatedExecutor struct {
	inner contracts.Executor
	chain *Chain
}

var _ contracts.Executor = (*GatedExecutor)(nil)

// NewGatedExecutor builds the decorator. A nil inner executor or nil chain is a
// programming error and is rejected.
func NewGatedExecutor(inner contracts.Executor, chain *Chain) (*GatedExecutor, error) {
	if inner == nil {
		return nil, domain.New(domain.CodeInternal,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithParams(map[string]string{"reason": "gated executor: nil inner"}),
		)
	}
	if chain == nil {
		return nil, domain.New(domain.CodeInternal,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithParams(map[string]string{"reason": "gated executor: nil chain"}),
		)
	}
	return &GatedExecutor{inner: inner, chain: chain}, nil
}

// Family implements contracts.Executor.
func (g *GatedExecutor) Family() domain.ProviderID { return g.inner.Family() }

// gateInput builds the metadata-only input for the chain.
func (g *GatedExecutor) gateInput(req contracts.WireRequest, cred contracts.Credential) contracts.GateInput {
	meta := map[string]string{
		"executor.family": string(g.inner.Family()),
	}
	return contracts.GateInput{
		Provider:   cred.Provider,
		Credential: cred.ID,
		Model:      req.Model,
		Headers:    headerNamesOnly(req.Headers),
		Meta:       meta,
	}
}

// Do implements contracts.Executor: PreRequest, delegate, PostResponse.
func (g *GatedExecutor) Do(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.WireResponse, error) {
	in := g.gateInput(req, cred)
	decision, err := g.chain.PreRequest(ctx, in)
	if err != nil {
		return contracts.WireResponse{}, err
	}
	// Reuse the request-scoped Derived computed once (ADR-0014 §6).
	if decision.Derived != nil {
		in.Derived = decision.Derived
	}
	if decision.Kind == contracts.DecisionReroute {
		return contracts.WireResponse{}, rerouteUnsupported()
	}
	if synth, blocked := syntheticFromDecision(decision); blocked {
		return synth, nil
	}

	resp, err := g.inner.Do(ctx, req, cred)
	if err != nil {
		// PostResponse still runs (best-effort) so a gate can observe the
		// failure; the original error is preserved.
		_ = g.chain.PostResponse(ctx, in)
		return contracts.WireResponse{}, err
	}
	_ = g.chain.PostResponse(ctx, in)
	return resp, nil
}

// DoStream implements contracts.Executor: PreRequest before opening the stream
// and PostResponse after Close. A pre-commit Block returns a single-chunk stream
// carrying the synthetic body, so the caller sees a normal successful stream.
func (g *GatedExecutor) DoStream(ctx context.Context, req contracts.WireRequest, cred contracts.Credential) (contracts.Stream, error) {
	in := g.gateInput(req, cred)
	decision, err := g.chain.PreRequest(ctx, in)
	if err != nil {
		return nil, err
	}
	// Reuse the request-scoped Derived computed once (ADR-0014 §6) in the
	// per-chunk stage via the closing stream's base input.
	if decision.Derived != nil {
		in.Derived = decision.Derived
	}
	if decision.Kind == contracts.DecisionReroute {
		return nil, rerouteUnsupported()
	}
	if synth, blocked := syntheticFromDecision(decision); blocked {
		return &syntheticStream{
			headers: synth.Headers,
			body:    synth.Body,
			onClose: func() { _ = g.chain.PostResponse(ctx, in) },
		}, nil
	}

	stream, err := g.inner.DoStream(ctx, req, cred)
	if err != nil {
		_ = g.chain.PostResponse(ctx, in)
		return nil, err
	}
	return &closingStream{
		Stream:  stream,
		chain:   g.chain,
		ctx:     ctx,
		base:    in,
		onClose: func() { _ = g.chain.PostResponse(ctx, in) },
	}, nil
}

// rerouteUnsupported refuses a pre-commit DecisionReroute with a typed error.
// The reroute vocabulary is frozen in the contracts, but the F3 Dispatcher that
// validates a target against the allowlist does not exist yet; running the inner
// executor with the ORIGINAL request would silently ignore the gate's intent
// (SEC-10). Until the Dispatcher lands, a reroute is an explicit refusal rather
// than a silent no-op.
func rerouteUnsupported() error {
	return domain.New(domain.CodeProviderRerouteUnsupported,
		domain.WithHTTPStatus(http.StatusNotImplemented),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"reason": "requires the F3 dispatcher"}),
	)
}

// CountTokens implements contracts.Executor: no gate stages (counting is not a
// request/response exchange).
func (g *GatedExecutor) CountTokens(ctx context.Context, req contracts.WireRequest, model domain.ModelID) (int, error) {
	return g.inner.CountTokens(ctx, req, model)
}

// syntheticFromDecision reports whether a pre-commit decision terminates the call
// with a synthetic response, and returns that response as a WireResponse.
func syntheticFromDecision(d contracts.Decision) (contracts.WireResponse, bool) {
	if d.Kind != contracts.DecisionBlock || d.Synthetic == nil {
		return contracts.WireResponse{}, false
	}
	status := d.Synthetic.Status
	if status == 0 {
		status = http.StatusOK
	}
	return contracts.WireResponse{
		Status:  status,
		Headers: d.Synthetic.Headers,
		Body:    d.Synthetic.Body,
	}, true
}
