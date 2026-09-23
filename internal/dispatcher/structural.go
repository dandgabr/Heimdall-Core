package dispatcher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file executes the two STRUCTURAL strategies (ADR-0009 §3/§6, F3
// correction D-02). A linear plan is Attempts-in-order; a structural plan also
// carries a SHAPE — fusion's Panels+Judge or pipeline's Chain — and the
// Dispatcher is what runs it.
//
// The Dispatcher does NOT resolve routes: the Router has already built and
// validated the shape (fan-out cap, judge non-self/non-fusion). Here it only
// executes one sub-plan at a time through the SAME linear loop, so accounting,
// breaker and retry apply per sub-call exactly as for a linear plan.

// maxFanout mirrors router's runtime cap (combos.MaxFanout). The Router already
// refuses an over-cap plan; this is the Dispatcher's own defensive bound so a
// hand-built plan cannot fan out without limit.
const maxFanout = 8

// panelOutput is the result of one fusion panel: its anonymised label and the
// textual content the judge will see. ok=false means the panel failed; a fusion
// with SOME failures still proceeds with the panel outputs that succeeded.
type panelOutput struct {
	label   string
	content string
	ok      bool
}

// runFusion executes a fusion plan (ADR-0009 §3): fan out every panel in
// parallel, collect their anonymised outputs, then run the judge — a NORMAL
// request that re-enters the Dispatcher. Success is PARTIAL: a failed panel is
// dropped and the judge still runs on the survivors; only when EVERY panel fails
// is the result a typed error (route.fusion_all_failed). stream selects whether
// the JUDGE runs streaming (the panels are always non-streaming: the judge needs
// their text, not their bytes).
func (d *Dispatcher) runFusion(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan, stream bool) (*outcome, error) {
	if len(plan.Panels) > maxFanout {
		return nil, fanoutExceeded(len(plan.Panels))
	}
	if len(plan.Panels) == 0 {
		return nil, noAttemptsError(false, false, 0)
	}

	outputs := d.runPanels(ctx, req, plan.Panels)
	successes := 0
	for _, o := range outputs {
		if o.ok {
			successes++
		}
	}
	if successes == 0 {
		return nil, fusionAllFailed(len(plan.Panels))
	}

	// No judge route (degenerate fallback, documented): return the first
	// successful panel's response. In streaming mode, synthesise a one-chunk
	// stream so the caller still receives a Stream.
	if plan.Judge == nil {
		return firstSuccessfulPanel(outputs, stream), nil
	}

	judgeReq := judgeRequest(req, outputs)
	res, err := d.run(ctx, judgeReq, *plan.Judge, stream)
	if err != nil {
		return nil, err
	}
	res.attempts += successes // observability: panels + judge attempts
	return res, nil
}

// firstSuccessfulPanel returns the first successful panel as an outcome. It is
// only called when at least one panel succeeded (successes > 0).
func firstSuccessfulPanel(outputs []panelResult, stream bool) *outcome {
	for _, o := range outputs {
		if !o.ok {
			continue
		}
		if stream {
			return &outcome{
				candidate: o.candidate,
				stream:    &singleChunkStream{body: o.body},
				attempts:  len(outputs),
			}
		}
		return &outcome{
			candidate: o.candidate,
			wire:      contracts.WireResponse{Status: http.StatusOK, Body: o.body},
			attempts:  len(outputs),
		}
	}
	// Unreachable by the caller's guard; kept total so a future caller cannot
	// dereference nil.
	return &outcome{}
}

// panelResult augments panelOutput with the winning candidate and raw body, kept
// private to the fusion path.
type panelResult struct {
	panelOutput
	candidate contracts.Candidate
	body      []byte
}

// runPanels runs every panel concurrently and returns the outputs in panel
// order, so the judge prompt is deterministic. The goroutine count is already
// bounded: runFusion refuses a plan with more than maxFanout panels, so there is
// no separate semaphore to fill. Cancelling ctx aborts each panel's own attempt
// loop (which checks ctx), so a cancelled request does not spawn unbounded work.
func (d *Dispatcher) runPanels(ctx context.Context, req contracts.WireRequest, panels []contracts.Panel) []panelResult {
	results := make([]panelResult, len(panels))
	var wg sync.WaitGroup

	for i := range panels {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := d.run(ctx, req, panels[i].Plan, false)
			if err != nil {
				results[i] = panelResult{panelOutput: panelOutput{label: panels[i].Label, ok: false}}
				return
			}
			results[i] = panelResult{
				panelOutput: panelOutput{
					label:   panels[i].Label,
					content: extractContent(res.wire.Body),
					ok:      true,
				},
				candidate: res.candidate,
				body:      res.wire.Body,
			}
		}(i)
	}
	wg.Wait()
	return results
}

// judgeRequest builds the judge's request: the original request with the
// ANONYMISED panel outputs appended as a user message. The judge sees content
// labelled "panel-1", "panel-2", … and never the provider/model provenance
// (ADR-0009 §3). A body that is not a JSON object is left untouched (best-effort,
// the judge still runs).
func judgeRequest(base contracts.WireRequest, panels []panelResult) contracts.WireRequest {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base.Body, &obj); err != nil || obj == nil {
		return base
	}
	var messages []json.RawMessage
	if raw, ok := obj["messages"]; ok {
		_ = json.Unmarshal(raw, &messages)
	}
	message := struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "user", Content: panelsDigest(panels)}
	encodedMsg, err := jsonMarshal(message)
	if err != nil {
		return base
	}
	messages = append(messages, encodedMsg)
	encodedMsgs, err := jsonMarshal(messages)
	if err != nil {
		return base
	}
	obj["messages"] = encodedMsgs
	body, err := jsonMarshal(obj)
	if err != nil {
		return base
	}
	synth := base
	synth.Body = body
	return synth
}

// panelsDigest renders the anonymised panel outputs for the judge. A failed
// panel is omitted; labels are positional and carry no provider/model identity.
func panelsDigest(panels []panelResult) string {
	digest := ""
	for _, p := range panels {
		if !p.ok {
			continue
		}
		digest += "[" + p.label + "]\n" + p.content + "\n\n"
	}
	return digest
}

// runPipeline executes a pipeline plan (ADR-0009 §6): the steps run
// SEQUENTIALLY, step N's response text becoming step N+1's input, and ONLY the
// last step's response is returned to the caller. Intermediate steps never
// commit to the client. stream selects whether the LAST step runs streaming;
// every earlier step is non-streaming because its text feeds the next request.
func (d *Dispatcher) runPipeline(ctx context.Context, req contracts.WireRequest, plan contracts.RoutePlan, stream bool) (*outcome, error) {
	if len(plan.Chain) == 0 {
		return nil, noAttemptsError(false, false, 0)
	}
	// Run every step EXCEPT the last non-streaming, feeding each output into the
	// next request. The last step is run once — streaming when the caller asked
	// for a stream — and its response is the only one returned.
	cur := req
	total := 0
	lastIndex := len(plan.Chain) - 1
	for i := 0; i < lastIndex; i++ {
		res, err := d.run(ctx, cur, plan.Chain[i], false)
		if err != nil {
			return nil, err
		}
		total += res.attempts
		if res.wire.Body != nil {
			cur = chainRequest(cur, res.wire.Body)
		}
	}

	res, err := d.run(ctx, cur, plan.Chain[lastIndex], stream)
	if err != nil {
		return nil, err
	}
	res.attempts += total
	return res, nil
}

// chainRequest folds a pipeline step's response into the next step's request: the
// step's assistant text is appended as a user message so step N+1 sees step N's
// output (ADR-0009 §6). A non-JSON body is left untouched (best-effort).
func chainRequest(base contracts.WireRequest, responseBody []byte) contracts.WireRequest {
	content := extractContent(responseBody)
	if content == "" {
		return base
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base.Body, &obj); err != nil || obj == nil {
		return base
	}
	var messages []json.RawMessage
	if raw, ok := obj["messages"]; ok {
		_ = json.Unmarshal(raw, &messages)
	}
	message := struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "user", Content: content}
	encodedMsg, err := jsonMarshal(message)
	if err != nil {
		return base
	}
	messages = append(messages, encodedMsg)
	encodedMsgs, err := jsonMarshal(messages)
	if err != nil {
		return base
	}
	obj["messages"] = encodedMsgs
	body, err := jsonMarshal(obj)
	if err != nil {
		return base
	}
	next := base
	next.Body = body
	return next
}

// extractContent reads the first assistant message's content from a canonical
// response body. An absent or non-string content yields "" (the caller then
// leaves the request unchanged).
func extractContent(body []byte) string {
	var payload struct {
		Choices []struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Choices) == 0 {
		return ""
	}
	var content string
	if err := json.Unmarshal(payload.Choices[0].Message.Content, &content); err != nil {
		return ""
	}
	return content
}

// fusionAllFailed is the typed error when every panel failed: there is no winner
// to judge (ADR-0009 §3).
func fusionAllFailed(panels int) *domain.DomainError {
	return domain.New(domain.CodeRouteFusionAllFailed,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.WithScope(domain.ScopeProvider),
		domain.WithParams(map[string]string{"panels": itoa(panels)}),
	)
}

// fanoutExceeded is the Dispatcher's defensive fan-out refusal (the Router
// already enforces the same cap).
func fanoutExceeded(n int) *domain.DomainError {
	return domain.New(domain.CodeRouteFanoutExceeded,
		domain.WithHTTPStatus(http.StatusBadRequest),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": "", "max": itoa(maxFanout)}),
	)
}

// singleChunkStream is a one-chunk contracts.Stream, used for the degenerate
// fusion-without-judge streaming fallback. It is the same shape the pipeline's
// synthetic stream has and never carries a `[DONE]` sentinel as data.
type singleChunkStream struct {
	body    []byte
	emitted bool
	closed  bool
}

var _ contracts.Stream = (*singleChunkStream)(nil)

// Headers implements contracts.Stream.
func (s *singleChunkStream) Headers() http.Header { return http.Header{} }

// Recv implements contracts.Stream: one chunk, then io.EOF.
func (s *singleChunkStream) Recv() (contracts.Chunk, error) {
	if s.emitted {
		return contracts.Chunk{}, io.EOF
	}
	s.emitted = true
	return contracts.Chunk{Data: s.body}, nil
}

// Close implements contracts.Stream.
func (s *singleChunkStream) Close() error { s.closed = true; return nil }
