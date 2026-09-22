package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// defaultPollInterval is the RFC 8628 §3.5 fallback when the provider omits
// `interval`. defaultDeviceTTL bounds the grant when the provider omits
// `expires_in`.
const (
	defaultPollInterval = 5 * time.Second
	defaultDeviceTTL    = 10 * time.Minute
	// defaultSlowDownIncrement is the RFC 8628 §3.5 recommendation: increase
	// the poll interval by 5 seconds on slow_down.
	defaultSlowDownIncrement = 5 * time.Second
	// maxSlowDownInterval caps the backoff so a misbehaving server cannot push
	// the interval to hours.
	maxSlowDownInterval = 60 * time.Second
)

// DeviceCodeFlow is the generic RFC 8628 device authorization flow.
//
// The token endpoint and public client id are bound at construction (from the
// same ProviderDescriptor the composition root passes to Begin), because Poll
// receives only the challenge and the challenge does not carry endpoints.
type DeviceCodeFlow struct {
	deps               ClientDeps
	deviceAuthEndpoint string
	tokenEndpoint      string
	clientID           string
	// clientSecret/requiresClientSecret mirror PKCEFlow: a confidential CLI
	// client authenticates the token exchange and refresh with its public
	// client secret (ADR-0003). Pure public clients leave both zero.
	clientSecret         string
	requiresClientSecret bool
	// SlowDownIncrement overrides the 5s add on slow_down (tests use a tiny
	// value; production keeps the RFC recommendation).
	SlowDownIncrement time.Duration
}

// slowDownIncrement returns the configured increment or the RFC default.
func (f *DeviceCodeFlow) slowDownIncrement() time.Duration {
	if f.SlowDownIncrement > 0 {
		return f.SlowDownIncrement
	}
	return defaultSlowDownIncrement
}

// NewDeviceCodeFlow builds the flow for one descriptor. The descriptor's
// endpoints and client id are captured here so Poll (which receives only the
// challenge) is self-contained.
func NewDeviceCodeFlow(deps ClientDeps, desc contracts.ProviderDescriptor) *DeviceCodeFlow {
	return &DeviceCodeFlow{
		deps:                 deps,
		deviceAuthEndpoint:   desc.DeviceAuthEndpoint,
		tokenEndpoint:        desc.TokenEndpoint,
		clientID:             desc.ClientID,
		clientSecret:         desc.ClientSecret,
		requiresClientSecret: desc.RequiresClientSecret,
	}
}

// Kind implements contracts.AuthFlow.
func (f *DeviceCodeFlow) Kind() contracts.AuthMode { return contracts.AuthOAuth }

// deviceAuthResponse is the RFC 8628 §3.2 response.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// Begin calls the device authorization endpoint and returns the challenge.
func (f *DeviceCodeFlow) Begin(ctx context.Context, desc contracts.ProviderDescriptor) (contracts.AuthChallenge, error) {
	endpoint := desc.DeviceAuthEndpoint
	if endpoint == "" {
		endpoint = f.deviceAuthEndpoint
	}
	if endpoint == "" {
		return contracts.AuthChallenge{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "device authorization endpoint is not configured"}),
		)
	}

	clientID := desc.ClientID
	if clientID == "" {
		clientID = f.clientID
	}

	form := url.Values{}
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if len(desc.DefaultScopes) > 0 {
		form.Set("scope", strings.Join(desc.DefaultScopes, " "))
	}

	doer, err := f.deps.doerFor(endpoint)
	if err != nil {
		return contracts.AuthChallenge{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return contracts.AuthChallenge{}, flowError(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return contracts.AuthChallenge{}, networkError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return contracts.AuthChallenge{}, networkError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var oe errorResponse
		if json.Unmarshal(body, &oe) == nil && oe.Error != "" {
			return contracts.AuthChallenge{}, mapOAuthError(oe.Error, oe.ErrorDescription)
		}
		return contracts.AuthChallenge{}, networkError(errors.New("device authorization endpoint failed"))
	}

	var da deviceAuthResponse
	if err := json.Unmarshal(body, &da); err != nil {
		return contracts.AuthChallenge{}, flowError(err)
	}
	if da.DeviceCode == "" || da.UserCode == "" {
		return contracts.AuthChallenge{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(502),
			domain.WithParams(map[string]string{"reason": "device authorization response is missing codes"}),
		)
	}

	interval := time.Duration(da.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPollInterval
	}
	ttl := time.Duration(da.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultDeviceTTL
	}

	verification := da.VerificationURI
	// Prefer the pre-filled URI when the provider offers one: fewer user typos.
	if da.VerificationURIComplete != "" {
		verification = da.VerificationURIComplete
	}

	return contracts.AuthChallenge{
		Mode:            contracts.AuthOAuth,
		DeviceCode:      da.DeviceCode,
		UserCode:        da.UserCode,
		VerificationURI: verification,
		Interval:        interval,
		ExpiresAt:       f.deps.now().Add(ttl),
	}, nil
}

// Poll advances the grant until it completes, expires or is denied.
//
// It respects the provider's interval, applies slow_down by increasing it
// (RFC 8628 §3.5), enforces the ticket TTL, and returns auth.oauth_flow_expired
// when the TTL passes. The device_code is never logged.
func (f *DeviceCodeFlow) Poll(ctx context.Context, ch contracts.AuthChallenge) (contracts.AuthResult, error) {
	if ch.DeviceCode == "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(400),
			domain.WithParams(map[string]string{"reason": "challenge has no device code"}),
		)
	}
	if f.tokenEndpoint == "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "token endpoint is not configured"}),
		)
	}

	interval := ch.Interval
	if interval <= 0 {
		interval = defaultPollInterval
	}

	for {
		if !ch.ExpiresAt.IsZero() && !f.deps.now().Before(ch.ExpiresAt) {
			return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowExpired,
				domain.WithHTTPStatus(408),
				domain.WithScope(domain.ScopeRequest),
			)
		}

		// Wait one interval before each poll (RFC 8628 §3.4), bounded by ctx and
		// the ticket TTL.
		if err := f.sleep(ctx, interval, ch.ExpiresAt); err != nil {
			return contracts.AuthResult{}, err
		}

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", ch.DeviceCode)
		if f.clientID != "" {
			form.Set("client_id", f.clientID)
		}

		tr, err := f.deps.postForm(ctx, f.tokenEndpoint, form)
		switch {
		case err == nil:
			res := resultFromToken(f.deps, tr, contracts.AuthOAuth, contracts.RefreshToken{})
			if res.Access.IsEmpty() {
				return contracts.AuthResult{}, domain.New(domain.CodeAuthRefreshFailed,
					domain.WithHTTPStatus(502),
					domain.Retry(),
					domain.WithScope(domain.ScopeCredential),
					domain.WithParams(map[string]string{"reason": "token response had no access token"}),
				)
			}
			return res, nil

		case errors.Is(err, errAuthorizationPending):
			continue // not an error; keep polling

		case errors.Is(err, errSlowDown):
			interval += f.slowDownIncrement()
			if interval > maxSlowDownInterval {
				interval = maxSlowDownInterval
			}
			continue

		default:
			return contracts.AuthResult{}, err
		}
	}
}

// Refresh exchanges a refresh token for fresh access material.
//
// INVARIANT — single-flight: the caller MUST hold
// CredentialStore.RefreshLock(cred.ID) for the whole call, so N concurrent
// callers produce exactly one upstream exchange. Refresh itself is a pure
// function of its inputs and is idempotent from the flow's perspective: given
// the same refresh token it performs the same exchange, and the lock is what
// collapses the duplicates.
func (f *DeviceCodeFlow) Refresh(ctx context.Context, cred contracts.Credential, token contracts.RefreshToken) (contracts.AuthResult, error) {
	return f.refresh(ctx, cred, token)
}

// refresh is shared by the device and PKCE flows: only Begin differs.
func (f *DeviceCodeFlow) refresh(ctx context.Context, cred contracts.Credential, token contracts.RefreshToken) (contracts.AuthResult, error) {
	if f.tokenEndpoint == "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "token endpoint is not configured"}),
		)
	}
	if token.Token.IsEmpty() {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthCredentialInvalid,
			domain.WithHTTPStatus(401),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"reason": "no refresh token available"}),
		)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token.Token.Reveal())
	if f.clientID != "" {
		form.Set("client_id", f.clientID)
	}
	if f.requiresClientSecret && f.clientSecret != "" {
		form.Set("client_secret", f.clientSecret)
	}

	tr, err := f.deps.postForm(ctx, f.tokenEndpoint, form)
	if err != nil {
		return contracts.AuthResult{}, err
	}

	res := resultFromToken(f.deps, tr, contracts.AuthOAuth, token)
	if res.Access.IsEmpty() {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthRefreshFailed,
			domain.WithHTTPStatus(502),
			domain.Retry(),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"reason": "refresh response had no access token"}),
		)
	}
	res.Account = cred.Meta
	return res, nil
}

// sleep waits d, returning early on ctx cancellation or ticket expiry.
func (f *DeviceCodeFlow) sleep(ctx context.Context, d time.Duration, expiresAt time.Time) error {
	if !expiresAt.IsZero() {
		if until := expiresAt.Sub(f.deps.now()); until < d {
			d = until
		}
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return flowError(ctx.Err())
	case <-timer.C:
		if !expiresAt.IsZero() && !f.deps.now().Before(expiresAt) {
			return domain.New(domain.CodeAuthFlowExpired,
				domain.WithHTTPStatus(408),
				domain.WithScope(domain.ScopeRequest),
			)
		}
		return nil
	}
}
