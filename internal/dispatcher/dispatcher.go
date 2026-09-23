package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dandgabr/heimdall-core/internal/breaker"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Config carries the dispatcher's injected seams. Clock and IDs are required;
// the zero Waiter is replaced by the production TimerWaiter.
type Config struct {
	// Clock is the injectable time source (cooldowns, timestamps).
	Clock contracts.Clock
	// IDs supplies the request id that forms the idempotency key.
	IDs contracts.IDGen
	// Waiter honours a RetryAfter between attempts. Nil uses TimerWaiter.
	Waiter Waiter
	// MaxCooldown caps a single inter-attempt wait, so a hostile Retry-After
	// cannot stall a request for hours. Zero means the default (30s).
	MaxCooldown time.Duration
}

// DefaultMaxCooldown bounds an inter-attempt wait.
const DefaultMaxCooldown = 30 * time.Second

// Dispatcher is the concrete contracts.Dispatcher (ADR-0010).
type Dispatcher struct {
	factory  ExecutorFactory
	creds    CredentialSource
	br       Breaker
	quota    QuotaFilter
	recorder contracts.UsageRecorder
	cfg      Config
}

var _ contracts.Dispatcher = (*Dispatcher)(nil)

// New builds a dispatcher. factory, creds and br are required (a dispatcher
// without them cannot attempt anything); quota and recorder may be nil.
func New(factory ExecutorFactory, creds CredentialSource, br Breaker, quota QuotaFilter, recorder contracts.UsageRecorder, cfg Config) *Dispatcher {
	if cfg.Clock == nil {
		panic("dispatcher: nil clock")
	}
	if cfg.IDs == nil {
		cfg.IDs = domainIDGen{}
	}
	if cfg.Waiter == nil {
		cfg.Waiter = TimerWaiter{}
	}
	if cfg.MaxCooldown <= 0 {
		cfg.MaxCooldown = DefaultMaxCooldown
	}
	return &Dispatcher{factory: factory, creds: creds, br: br, quota: quota, recorder: recorder, cfg: cfg}
}

// domainIDGen adapts domain.NewRequestID to contracts.IDGen.
type domainIDGen struct{}

func (domainIDGen) NewRequestID() domain.RequestID { return domain.NewRequestID() }

// TimerWaiter is the production Waiter: a context-aware timer.
type TimerWaiter struct{}

// Wait blocks for d or until ctx is done.
func (TimerWaiter) Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Do implements contracts.Dispatcher for a non-streaming plan.
func (d *Dispatcher) Do(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan) (*contracts.Response, error) {
	res, err := d.run(ctx, req, plan, false)
	if err != nil {
		return nil, err
	}
	return &contracts.Response{
		Candidate: res.candidate,
		Wire:      res.wire,
		Attempts:  res.attempts,
	}, nil
}

// DoStream implements contracts.Dispatcher for a streaming plan. The returned
// Stream is bound to ctx; the winning candidate is fixed (committed on the first
// byte), so no failover happens after this returns.
func (d *Dispatcher) DoStream(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan) (contracts.Stream, error) {
	resp, err := d.run(ctx, req, plan, true)
	if err != nil {
		return nil, err
	}
	return resp.stream, nil
}

// run is the shared attempt loop. stream selects Do vs DoStream on the executor.
//
// A STRUCTURAL plan is dispatched first: fusion fans out its panels and runs the
// judge (ADR-0009 §3), pipeline chains its steps N→N+1 (§6). Both delegate back
// to this linear loop for each sub-call, so accounting/breaker/retry are
// unchanged per attempt. A linear plan falls straight through.
func (d *Dispatcher) run(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan, stream bool) (*outcome, error) {
	if len(plan.Panels) > 0 {
		return d.runFusion(ctx, req, plan, stream)
	}
	if len(plan.Chain) > 0 {
		return d.runPipeline(ctx, req, plan, stream)
	}

	requestID := string(d.cfg.IDs.NewRequestID())
	maxRounds := plan.MaxRounds
	if maxRounds <= 0 {
		maxRounds = len(plan.Attempts)
	}

	var (
		attempts     int
		lastErr      *domain.DomainError
		sawBreaker   bool
		sawQuota     bool
		maxRoundsHit bool
	)

	for _, c := range plan.Attempts {
		if attempts >= maxRounds {
			maxRoundsHit = true
			break
		}

		cred, cc, ok, reason := d.resolve(ctx, c)
		if !ok {
			switch reason {
			case skipBreaker:
				sawBreaker = true
			case skipQuota:
				sawQuota = true
			}
			continue
		}

		if err := ctx.Err(); err != nil {
			return nil, ctxError(err)
		}

		exec, err := d.factory.Build(ctx, cc, cred)
		if err != nil {
			de := asDomain(err)
			lastErr = de
			d.record(ctx, cc, attemptOutcome(de), breakerFrom(de))
			continue
		}

		attempts++
		key := fmt.Sprintf("%s:%s/%s:%s:%d", requestID, cc.Provider, cc.Model, cc.Credential, attempts)

		wireReq := rewriteModel(req, cc.Model)

		if stream {
			s, err := exec.DoStream(ctx, wireReq, cred)
			if err != nil {
				de := asDomain(err)
				lastErr = de
				d.record(ctx, cc, attemptOutcome(de), breakerFrom(de))
				if de.Scope == domain.ScopeRequest {
					return nil, de
				}
				if cerr := ctx.Err(); cerr != nil {
					return nil, ctxError(cerr)
				}
				if waitErr := d.cooldown(ctx, de.RetryAfter); waitErr != nil {
					return nil, waitErr
				}
				continue
			}
			return &outcome{candidate: cc, attempts: attempts, stream: d.wrapStream(s, cc, key)}, nil
		}

		resp, err := exec.Do(ctx, wireReq, cred)
		if err != nil {
			de := asDomain(err)
			lastErr = de
			d.record(ctx, cc, attemptOutcome(de), breakerFrom(de))
			// A ScopeRequest failure is terminal: return immediately, without
			// retrying and WITHOUT cooldowning (ADR-0010 §2.1).
			if de.Scope == domain.ScopeRequest {
				return nil, de
			}
			if cerr := ctx.Err(); cerr != nil {
				return nil, ctxError(cerr)
			}
			if waitErr := d.cooldown(ctx, de.RetryAfter); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		// Success: close the circuit and account the usage, then return.
		d.br.Record(cc, breaker.Outcome{Success: true})
		d.account(ctx, cc, key, resp.Body)
		return &outcome{candidate: cc, wire: resp, attempts: attempts}, nil
	}

	// No winner. Aggregate the reasons (ADR-0010 §6).
	if attempts == 0 {
		return nil, noAttemptsError(sawBreaker, sawQuota, len(plan.Attempts))
	}
	if maxRoundsHit {
		return nil, maxRoundsError(maxRounds)
	}
	return nil, exhaustedError(attempts, lastErr)
}

// skipReason explains why a candidate was not executable.
type skipReason uint8

const (
	skipNone skipReason = iota
	skipBreaker
	skipQuota
	skipCredential
)

// resolve selects the concrete credential for a candidate and checks the
// preflight (breaker + quota). It returns ok=false with the class of the skip
// when the candidate cannot be attempted.
func (d *Dispatcher) resolve(ctx context.Context, c contracts.Candidate) (contracts.Credential, contracts.Candidate, bool, skipReason) {
	if c.Credential != "" {
		cc := c
		if !d.allow(ctx, cc) {
			return contracts.Credential{}, c, false, d.denyReason(cc)
		}
		cred, err := d.creds.Get(ctx, c.Credential)
		if err != nil {
			return contracts.Credential{}, c, false, skipCredential
		}
		return cred, cc, true, skipNone
	}

	// Zero credential: pick the first healthy account of the family.
	ids, err := d.creds.Credentials(ctx, c.Provider)
	if err != nil {
		return contracts.Credential{}, c, false, skipCredential
	}
	for _, id := range ids {
		cc := c
		cc.Credential = id
		if !d.allow(ctx, cc) {
			continue
		}
		cred, getErr := d.creds.Get(ctx, id)
		if getErr != nil {
			continue
		}
		return cred, cc, true, skipNone
	}
	// No concrete account was eligible. Distinguish an open circuit from an
	// absent/all-exhausted credential set for the aggregate reason.
	if len(ids) == 0 {
		return contracts.Credential{}, c, false, skipCredential
	}
	return contracts.Credential{}, c, false, skipBreaker
}

// rewriteModel sets the canonical request body's "model" field to the candidate's
// model, so the plan's chosen model is what the upstream sees. A body that is not
// a JSON object (or has no model field) is left untouched: rewriting is
// best-effort and must never fail an attempt.
func rewriteModel(req contracts.WireRequest, model domain.ModelID) contracts.WireRequest {
	if model == "" || req.Model == model {
		return req
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(req.Body, &obj); err != nil || obj == nil {
		req.Model = model
		return req
	}
	encoded, err := jsonMarshal(string(model))
	if err != nil {
		req.Model = model
		return req
	}
	obj["model"] = encoded
	body, err := jsonMarshal(obj)
	if err != nil {
		req.Model = model
		return req
	}
	req.Body = body
	req.Model = model
	return req
}

// jsonMarshal is a seam over json.Marshal. The two marshals in rewriteModel can
// only fail for values the JSON package cannot serialise, which a real canonical
// request never contains; routing them through a variable lets a test inject a
// failure and prove the best-effort path leaves the body untouched rather than
// dropping the attempt. Production uses the standard library.
var jsonMarshal = json.Marshal

// allow is the preflight: breaker closed AND quota permits.
func (d *Dispatcher) allow(ctx context.Context, c contracts.Candidate) bool {
	if !d.br.Allow(c) {
		return false
	}
	if d.quota == nil {
		return true
	}
	plan := contracts.RoutePlan{Attempts: []contracts.Candidate{c}, MaxRounds: 1}
	filtered, _ := d.quota.Filter(ctx, plan)
	return len(filtered.Attempts) == 1
}

// denyReason classifies why a specific candidate was denied, for the aggregate.
func (d *Dispatcher) denyReason(c contracts.Candidate) skipReason {
	if !d.br.Allow(c) {
		return skipBreaker
	}
	return skipQuota
}

// cooldown honours a RetryAfter between attempts, capped by MaxCooldown and
// always cancellable by ctx.
func (d *Dispatcher) cooldown(ctx context.Context, d2 time.Duration) error {
	if d2 <= 0 {
		return nil
	}
	if d2 > d.cfg.MaxCooldown {
		d2 = d.cfg.MaxCooldown
	}
	if err := d.cfg.Waiter.Wait(ctx, d2); err != nil {
		return ctxError(err)
	}
	return nil
}

// record reports one FAILED attempt to the breaker and the usage recorder.
func (d *Dispatcher) record(ctx context.Context, c contracts.Candidate, outcome contracts.AttemptOutcome, bo breaker.Outcome) {
	d.br.Record(c, bo)
	if d.recorder == nil {
		return
	}
	_ = d.recorder.Record(ctx, outcome, contracts.Usage{
		Provider:   c.Provider,
		Credential: c.Credential,
		Model:      c.Model,
		Requests:   1,
	})
}

// account reports a successful non-streaming attempt's usage.
func (d *Dispatcher) account(ctx context.Context, c contracts.Candidate, key string, body []byte) {
	if d.recorder == nil {
		return
	}
	_ = d.recorder.Record(ctx, contracts.OutcomeSuccess, usageFromBody(c, key, body))
}

// usageFromBody parses the canonical response body for token accounting. A body
// without a usage block yields zero tokens (unknown), never an error: parsing is
// best-effort and must not fail the attempt.
func usageFromBody(c contracts.Candidate, key string, body []byte) contracts.Usage {
	u := contracts.Usage{AttemptKey: key, Provider: c.Provider, Credential: c.Credential, Model: c.Model, Requests: 1}
	var payload struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
			InputTokens      int `json:"input_tokens"`
			OutputTokens     int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return u
	}
	in := payload.Usage.PromptTokens
	out := payload.Usage.CompletionTokens
	if in == 0 && payload.Usage.InputTokens > 0 {
		in = payload.Usage.InputTokens
	}
	if out == 0 && payload.Usage.OutputTokens > 0 {
		out = payload.Usage.OutputTokens
	}
	u.InputTokens = in
	u.OutputTokens = out
	switch {
	case payload.Usage.TotalTokens > 0:
		u.Tokens = payload.Usage.TotalTokens
	default:
		u.Tokens = in + out
	}
	return u
}

// attemptOutcome maps a DomainError's typed Scope to the coarse AttemptOutcome.
// The three ErrScope values are exhaustive; the default (ProviderError) is the
// fail-safe for an out-of-range scope, which a future Scope would land in.
func attemptOutcome(de *domain.DomainError) contracts.AttemptOutcome {
	switch de.Scope {
	case domain.ScopeRequest:
		return contracts.OutcomeClientError
	case domain.ScopeCredential:
		return contracts.OutcomeCredentialError
	default:
		return contracts.OutcomeProviderError
	}
}

// breakerFrom maps a DomainError onto the breaker's typed Outcome. Only the
// typed fields are read: never the Code or the HTTPStatus (ADR-0002).
func breakerFrom(de *domain.DomainError) breaker.Outcome {
	return breaker.Outcome{Scope: de.Scope, Retryable: de.Retryable, RetryAfter: de.RetryAfter}
}

// asDomain normalises an arbitrary error to a DomainError without leaking the
// cause. A non-domain error is a bug in the core: error.internal, ScopeRequest,
// non-retryable (ADR-0002 §5), so it never cooldowns a credential.
func asDomain(err error) *domain.DomainError {
	var de *domain.DomainError
	if errors.As(err, &de) && de != nil {
		return de
	}
	return domain.New(domain.CodeInternal,
		domain.WithHTTPStatus(http.StatusInternalServerError),
		domain.WithScope(domain.ScopeRequest),
		domain.WithCause(err),
	)
}

// ctxError maps a cancelled/expired context to a typed provider-scoped timeout,
// never to "candidates exhausted" (ADR-0010 §2.3).
func ctxError(err error) *domain.DomainError {
	return domain.New(domain.CodeUpstreamTimeout,
		domain.WithHTTPStatus(http.StatusGatewayTimeout),
		domain.WithScope(domain.ScopeProvider),
		domain.WithCause(err),
	)
}

// noAttemptsError is returned when every candidate was filtered before an
// attempt. It preserves the filter class: a transient breaker rejection is
// retryable, a quota rejection is credential-scoped and retryable, and an empty
// plan is the request's own problem (ADR-0010 §6).
func noAttemptsError(sawBreaker, sawQuota bool, candidates int) *domain.DomainError {
	switch {
	case sawBreaker:
		return domain.New(domain.CodeDispatchNoAttempts,
			domain.WithHTTPStatus(http.StatusServiceUnavailable),
			domain.Retry(),
			domain.WithScope(domain.ScopeProvider),
			domain.WithParams(map[string]string{"candidates": itoa(candidates)}),
		)
	case sawQuota:
		return domain.New(domain.CodeDispatchNoAttempts,
			domain.WithHTTPStatus(http.StatusServiceUnavailable),
			domain.Retry(),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"candidates": itoa(candidates)}),
		)
	default:
		return domain.New(domain.CodeDispatchNoAttempts,
			domain.WithHTTPStatus(http.StatusServiceUnavailable),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"candidates": itoa(candidates)}),
		)
	}
}

// maxRoundsError is returned when the attempt cap was reached with candidates
// still untried.
func maxRoundsError(maxRounds int) *domain.DomainError {
	return domain.New(domain.CodeDispatchMaxRounds,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.Retry(),
		domain.WithScope(domain.ScopeProvider),
		domain.WithParams(map[string]string{"max_rounds": itoa(maxRounds)}),
	)
}

// exhaustedError is the aggregate when attempts happened and all failed. It
// inherits the LAST attempt's Scope/Retryable and preserves its cause, never
// inventing a new Scope (ADR-0010 §6).
func exhaustedError(attempts int, last *domain.DomainError) *domain.DomainError {
	e := domain.New(domain.CodeDispatchExhausted,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.WithParams(map[string]string{
			"attempts":  itoa(attempts),
			"last_code": last.Code,
		}),
		domain.WithScope(last.Scope),
		domain.WithCause(last),
	)
	if last.Retryable {
		e.Retryable = true
	}
	return e
}

// itoa is a tiny local integer formatter.
func itoa(n int) string { return fmt.Sprintf("%d", n) }
