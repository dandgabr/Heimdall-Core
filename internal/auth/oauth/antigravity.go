package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// AntigravityConfig is the non-endpoint DATA the Antigravity post-exchange needs:
// where to fetch the user profile, where to discover the project/tier, where to
// onboard, and the client metadata Google fingerprints. It is a value, not code,
// so a test can point it at an httptest.Server.
//
// The endpoints here are the PRODUCTION hosts from the reference connector
// (registry/antigravity.js): project discovery and onboarding live on
// cloudcode-pa.googleapis.com, NOT the daily chat host.
type AntigravityConfig struct {
	// UserInfoEndpoint returns the account profile (email/subject).
	UserInfoEndpoint string
	// LoadCodeAssistEndpoint discovers the cloudaicompanionProject and tiers.
	LoadCodeAssistEndpoint string
	// OnboardUserEndpoint provisions the account once a project is known.
	OnboardUserEndpoint string
	// UserAgent is the official CLI UA presented on the discovery calls.
	UserAgent string
	// Metadata is the client metadata object sent to loadCodeAssist/onboardUser
	// ({ideType, platform, pluginType}).
	Metadata AntigravityClientMetadata
	// OnboardAttempts caps the fire-and-forget onboarding retries.
	OnboardAttempts int
	// OnboardRetryDelay is the wait between onboarding attempts.
	OnboardRetryDelay time.Duration
}

// AntigravityClientMetadata is the {ideType, platform, pluginType} triple Google
// fingerprints on loadCodeAssist/onboardUser.
type AntigravityClientMetadata struct {
	IDEType    int `json:"ideType"`
	Platform   int `json:"platform"`
	PluginType int `json:"pluginType"`
}

// DefaultAntigravityConfig returns the production Antigravity defaults.
func DefaultAntigravityConfig() AntigravityConfig {
	return AntigravityConfig{
		UserInfoEndpoint:       "https://www.googleapis.com/oauth2/v1/userinfo",
		LoadCodeAssistEndpoint: "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
		OnboardUserEndpoint:    "https://cloudcode-pa.googleapis.com/v1internal:onboardUser",
		UserAgent:              "antigravity/ide/2.11.0 darwin/arm64",
		// ideType ANTIGRAVITY=9, platform DARWIN_ARM64=2, pluginType GEMINI=2.
		Metadata:          AntigravityClientMetadata{IDEType: 9, Platform: 2, PluginType: 2},
		OnboardAttempts:   10,
		OnboardRetryDelay: 5 * time.Second,
	}
}

// defaultLegacyTier is the tier the reference connector falls back to when
// loadCodeAssist returns no allowedTiers with a default.
const defaultLegacyTier = "legacy-tier"

// AntigravityFlow wraps a PKCEFlow: it runs the standard authorization_code
// (with the public client_secret) exchange, then the Antigravity POST-EXCHANGE —
// userinfo, loadCodeAssist (project + tier) and a fire-and-forget onboardUser.
// The post-exchange never blocks the save: a failure to discover a project is
// tolerated, and onboarding runs in the background with a bounded retry.
type AntigravityFlow struct {
	*PKCEFlow
	cfg  AntigravityConfig
	deps ClientDeps
	// onboard launches the fire-and-forget onboarding. It is a seam so a test
	// can make it synchronous and assert the request without sleeping.
	onboard func(ctx context.Context, accessToken, tierID string)
	// marshal is the payload encoder used by the ASYNC onboarder. It is a
	// per-flow field (not a package seam) because the onboarder runs on its own
	// goroutine: a test that swapped a package-level seam would race the reader.
	marshal func(any) ([]byte, error)
}

// NewAntigravityFlow builds the Antigravity flow from a descriptor and its
// post-exchange config.
func NewAntigravityFlow(deps ClientDeps, desc contracts.ProviderDescriptor, cfg AntigravityConfig) *AntigravityFlow {
	f := &AntigravityFlow{PKCEFlow: NewPKCEFlow(deps, desc), cfg: cfg, deps: deps, marshal: json.Marshal}
	f.onboard = f.onboardUserAsync
	return f
}

// Kind implements contracts.AuthFlow.
func (f *AntigravityFlow) Kind() contracts.AuthMode { return contracts.AuthOAuth }

// AwaitCallback completes the browser callback and the token exchange via the
// embedded PKCE flow, then enriches the result with the Antigravity post-exchange.
func (f *AntigravityFlow) AwaitCallback(ctx context.Context, ch contracts.AuthChallenge, desc contracts.ProviderDescriptor) (contracts.AuthResult, error) {
	res, err := f.PKCEFlow.AwaitCallback(ctx, ch, desc)
	if err != nil {
		return contracts.AuthResult{}, err
	}
	return f.postExchange(ctx, res)
}

// postExchange runs the Antigravity-specific steps after the token grant:
//  1. userinfo  -> Account.Email / Account.Subject;
//  2. loadCodeAssist -> Account.Project (cloudaicompanionProject) and tier;
//  3. onboardUser -> fire-and-forget, never blocks the save.
//
// Every step is best-effort: a discovery failure leaves the project/tier at
// their defaults rather than failing the grant, matching the reference connector
// (a transient discovery error must not cost the user their login).
func (f *AntigravityFlow) postExchange(ctx context.Context, res contracts.AuthResult) (contracts.AuthResult, error) {
	token := res.Access.Reveal()
	if token == "" {
		return res, nil
	}

	// 1. userinfo (best-effort).
	if f.cfg.UserInfoEndpoint != "" {
		if info, err := f.fetchUserInfo(ctx, token); err == nil {
			res.Account.Email = info.Email
			res.Account.Subject = info.ID
		}
	}

	// 2. loadCodeAssist (best-effort): project + tier. The reference connector
	// defaults the tier to legacy-tier even when discovery fails, so the plan is
	// always populated.
	project, tierID := f.loadCodeAssist(ctx, token)
	if project != "" {
		res.Account.Project = project
	}
	if tierID == "" {
		tierID = defaultLegacyTier
	}
	res.Account.Plan = tierID

	// 3. onboardUser fire-and-forget. Only when a project exists, matching the
	// reference connector: onboarding without a project is meaningless.
	if project != "" && f.onboard != nil {
		f.onboard(ctx, token, tierID)
	}
	return res, nil
}

// antigravityUserInfo is the subset of the Google userinfo response we keep.
type antigravityUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// fetchUserInfo calls the userinfo endpoint. It never logs the token.
func (f *AntigravityFlow) fetchUserInfo(ctx context.Context, token string) (antigravityUserInfo, error) {
	endpoint := f.cfg.UserInfoEndpoint + "?alt=json"
	doer, err := f.deps.doerFor(endpoint)
	if err != nil {
		return antigravityUserInfo{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return antigravityUserInfo{}, flowError(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-request-source", "local")

	resp, err := doer.Do(req)
	if err != nil {
		return antigravityUserInfo{}, networkError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return antigravityUserInfo{}, networkError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return antigravityUserInfo{}, flowError(io.EOF)
	}
	var info antigravityUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return antigravityUserInfo{}, flowError(err)
	}
	return info, nil
}

// loadCodeAssist discovers the project and tier. It returns ("", "") on any
// failure; the caller treats it as best-effort.
func (f *AntigravityFlow) loadCodeAssist(ctx context.Context, token string) (project, tierID string) {
	if f.cfg.LoadCodeAssistEndpoint == "" {
		return "", ""
	}
	reqBody, err := jsonMarshal(map[string]any{"metadata": f.cfg.Metadata})
	if err != nil {
		return "", ""
	}
	body, ok := f.postJSON(ctx, f.cfg.LoadCodeAssistEndpoint, token, reqBody)
	if !ok {
		return "", ""
	}

	var data struct {
		CloudAIC     companionProject `json:"cloudaicompanionProject"`
		AllowedTiers []struct {
			ID        string `json:"id"`
			IsDefault bool   `json:"isDefault"`
		} `json:"allowedTiers"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", ""
	}

	project = data.CloudAIC.ID
	if project == "" {
		project = data.CloudAIC.Str
	}
	for _, tier := range data.AllowedTiers {
		if tier.IsDefault && tier.ID != "" {
			tierID = strings.TrimSpace(tier.ID)
			break
		}
	}
	if tierID == "" {
		tierID = defaultLegacyTier
	}
	return project, tierID
}

// companionProject decodes a field that may be either an object {"id":...} or a
// bare string, as the reference connector handles both shapes.
type companionProject struct {
	ID  string
	Str string
}

// UnmarshalJSON accepts either {"id":"x",...} or "x".
func (c *companionProject) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed == "null" {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		c.Str = s
		return nil
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	c.ID = obj.ID
	return nil
}

// onboardUserAsync launches the onboarding in the background. It NEVER blocks
// the caller (the grant save) and stops after OnboardAttempts or the first
// done=true. A failure is swallowed: onboarding is a one-time provisioning hint,
// not a credential.
func (f *AntigravityFlow) onboardUserAsync(_ context.Context, accessToken, tierID string) {
	cfg := f.cfg
	deps := f.deps
	attempts := cfg.OnboardAttempts
	if attempts <= 0 {
		attempts = 1
	}
	marshal := f.marshal
	if marshal == nil {
		marshal = json.Marshal
	}
	// Build the policy-bound doer BEFORE launching the goroutine. A wiring error
	// (no Egress policy and no test client) is a programming error; swallowing it
	// silently would be worse than skipping the best-effort onboarding, but the
	// onboarding itself must never block the grant save, so it is simply not
	// started.
	doer, doerErr := deps.doerFor(cfg.OnboardUserEndpoint)
	if doerErr != nil {
		return
	}
	go func() {
		payload, err := marshal(map[string]any{"tierId": tierID, "metadata": cfg.Metadata})
		if err != nil {
			return
		}
		for i := 0; i < attempts; i++ {
			// A fresh background context: the browser callback's ctx is already
			// cancelled by the time onboarding runs.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			body, ok := postJSONWith(ctx, doer, cfg.OnboardUserEndpoint, cfg.UserAgent, accessToken, payload)
			cancel()
			if ok {
				var result struct {
					Done bool `json:"done"`
				}
				if json.Unmarshal(body, &result) == nil && result.Done {
					return
				}
			}
			if i < attempts-1 {
				time.Sleep(cfg.OnboardRetryDelay)
			}
		}
	}()
}

// postJSON sends an authenticated JSON POST and returns the body. It returns
// ok=false on any failure; callers treat it as best-effort.
func (f *AntigravityFlow) postJSON(ctx context.Context, endpoint, token string, payload []byte) ([]byte, bool) {
	doer, err := f.deps.doerFor(endpoint)
	if err != nil {
		return nil, false
	}
	return postJSONWith(ctx, doer, endpoint, f.cfg.UserAgent, token, payload)
}

// postJSONWith is the transport body shared by the flow and the async onboarder.
// The doer is policy-bound (ADR-SEC-05): TLS verified, SSRF dial-time denylist,
// redirects refused.
func postJSONWith(ctx context.Context, doer contracts.HTTPDoer, endpoint, userAgent, token string, payload []byte) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("x-request-source", "local")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	return body, true
}

// compile-time assertion that the flow satisfies the frozen contract.
var _ contracts.AuthFlow = (*AntigravityFlow)(nil)

// ensure domain is used even if the file's error helpers change.
var _ = domain.CodeAuthFlowInsecure
