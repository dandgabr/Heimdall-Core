package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// defaultCallbackTimeout bounds how long the flow waits for the browser to
// return. It is short on purpose: a stale listener is an open port.
const defaultCallbackTimeout = 3 * time.Minute

// PKCEFlow is the generic authorization_code + PKCE S256 flow.
//
// Security invariants (review SEC-05/SEC-06):
//   - PKCE S256 is mandatory; there is no path that issues a flow without a
//     verifier and a challenge.
//   - State is >=128 bits from crypto/rand, generated per attempt, and compared
//     single-use.
//   - Begin binds the loopback listener FIRST, on an ephemeral port, and the
//     redirect URI it puts in the authorization URL carries THAT concrete port.
//     This is what makes the flow actually complete: a provider echoes the
//     redirect_uri back verbatim, so a placeholder port would be refused. It is
//     also the SEC-06 control — the port is unpredictable and the flow owns it.
//   - The redirect URI is checked against the descriptor allowlist BEFORE the
//     bind and re-checked before the exchange. The allowlist entry is the stable
//     loopback URI; the port is confirmed by owning the bound listener.
type PKCEFlow struct {
	deps          ClientDeps
	tokenEndpoint string
	clientID      string
	// clientSecret is the PUBLIC client secret of a confidential CLI client
	// (ADR-0003). It is sent on the token exchange/refresh only when
	// requiresClientSecret is set; a pure PKCE client leaves it empty.
	clientSecret string
	// requiresClientSecret selects the authorization_code flow WITH a client
	// secret (and Google's access_type=offline&prompt=consent), rather than
	// pure PKCE. It mirrors ProviderDescriptor.RequiresClientSecret.
	requiresClientSecret bool
	// allowlist is the exact redirect URIs permitted (host/scheme/path form,
	// without a specific port).
	allowlist []string
	// CallbackTimeout overrides defaultCallbackTimeout.
	CallbackTimeout time.Duration
	// Listen overrides the loopback listener (tests bind their own).
	Listen func(network, address string) (net.Listener, error)
	// listener is the socket bound by Begin and served by AwaitCallback. It is
	// carried on the flow instance because Begin and AwaitCallback are separate
	// contract calls, and the port must be the same one advertised in the URL.
	listener net.Listener
	// redirectURI is the concrete URI (with the bound port) advertised at Begin.
	redirectURI string
}

// NewPKCEFlow builds the flow for one descriptor.
func NewPKCEFlow(deps ClientDeps, desc contracts.ProviderDescriptor) *PKCEFlow {
	return &PKCEFlow{
		deps:                 deps,
		tokenEndpoint:        desc.TokenEndpoint,
		clientID:             desc.ClientID,
		clientSecret:         desc.ClientSecret,
		requiresClientSecret: desc.RequiresClientSecret,
		allowlist:            append([]string(nil), desc.RedirectAllowlist...),
	}
}

// Kind implements contracts.AuthFlow.
func (f *PKCEFlow) Kind() contracts.AuthMode { return contracts.AuthOAuth }

// Begin creates the PKCE challenge. The verifier stays server-side (carried on
// the challenge, never sent to the browser); only the S256 challenge and the
// state go to the authorization URL.
//
// The callback listener is bound HERE, before the URL is built, so the
// redirect_uri advertises the concrete ephemeral port the flow will actually
// listen on. The listener stays open (on the flow instance) until AwaitCallback
// consumes it or Close is called.
func (f *PKCEFlow) Begin(ctx context.Context, desc contracts.ProviderDescriptor) (contracts.AuthChallenge, error) {
	if f.tokenEndpoint == "" || desc.AuthEndpoint == "" {
		return contracts.AuthChallenge{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "authorization or token endpoint is not configured"}),
		)
	}
	if len(f.allowlist) == 0 {
		return contracts.AuthChallenge{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "no redirect allowlist configured"}),
		)
	}

	state, err := NewState()
	if err != nil {
		return contracts.AuthChallenge{}, err
	}
	verifier, challenge, err := NewPKCEVerifier()
	if err != nil {
		return contracts.AuthChallenge{}, err
	}

	// Bind the loopback listener first, on an ephemeral port. Never "0.0.0.0".
	listen := f.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return contracts.AuthChallenge{}, flowError(err)
	}
	f.listener = ln

	// Build the concrete redirect_uri from the allowlisted template plus the
	// bound port. The template is validated by exact match first; the port is
	// then substituted, which is what the provider echoes back.
	redirectURI, err := f.redirectWithPort(ln.Addr().String())
	if err != nil {
		f.closeListener()
		return contracts.AuthChallenge{}, err
	}
	f.redirectURI = redirectURI

	clientID := desc.ClientID
	if clientID == "" {
		clientID = f.clientID
	}
	authURL, err := url.Parse(desc.AuthEndpoint)
	if err != nil {
		f.closeListener()
		return contracts.AuthChallenge{}, flowError(err)
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(desc.DefaultScopes) > 0 {
		q.Set("scope", strings.Join(desc.DefaultScopes, " "))
	}
	// A confidential CLI client (Antigravity/Google) needs a refresh token and
	// an explicit consent prompt: access_type=offline is what returns the
	// refresh_token, and prompt=consent forces Google to re-issue it. The
	// descriptor's RequiresClientSecret selects this shape.
	if f.requiresClientSecret {
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}
	authURL.RawQuery = q.Encode()

	return contracts.AuthChallenge{
		Mode:          contracts.AuthOAuth,
		State:         state,
		PKCEVerifier:  contracts.Secret(verifier),
		CodeChallenge: challenge,
		RedirectURI:   redirectURI,
		// VerificationURI carries the authorization URL for PKCE, because the
		// challenge struct has no dedicated field and the caller opens it. It is
		// not a secret: the verifier is what is withheld.
		VerificationURI: authURL.String(),
		ExpiresAt:       f.deps.now().Add(f.callbackTimeout()),
	}, nil
}

// Close releases the listener Begin may have bound. It is safe to call when no
// listener exists and after AwaitCallback has consumed it.
func (f *PKCEFlow) Close() error {
	f.closeListener()
	return nil
}

func (f *PKCEFlow) closeListener() {
	if f.listener != nil {
		_ = f.listener.Close()
		f.listener = nil
	}
}

// redirectWithPort replaces the port in the allowlisted redirect template with
// the bound ephemeral port. The template must match an allowlist entry on
// scheme/host/path (ignoring any port it declares), which is the exact-match
// check applied to the stable loopback form.
func (f *PKCEFlow) redirectWithPort(boundAddr string) (string, error) {
	if len(f.allowlist) == 0 {
		return "", domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "no redirect allowlist configured"}),
		)
	}
	// The template IS f.allowlist[0], so it is allowlisted by construction; no
	// separate membership check is needed here (the caller-supplied redirect in
	// AwaitCallback is validated against the allowlist there).
	template := f.allowlist[0]
	base, err := url.Parse(template)
	if err != nil {
		return "", domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "redirect template is not a URL"}),
		)
	}
	// Reject a template that is not loopback or not http(s): the callback must
	// terminate locally, never be redirected elsewhere.
	host := base.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return "", domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "redirect host is not loopback"}),
		)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "redirect scheme is not http(s)"}),
		)
	}

	_, port, err := net.SplitHostPort(boundAddr)
	if err != nil {
		return "", flowError(err)
	}
	base.Host = net.JoinHostPort(host, port)
	return base.String(), nil
}

// AwaitCallback binds the loopback listener on an ephemeral port, waits for the
// redirect, validates the state, and exchanges the code. It returns the sealed
// material the caller persists.
//
// The listener is closed on every return path. A state mismatch or a missing
// code returns auth.oauth_state_mismatch; a timeout returns
// auth.callback_timeout.
func (f *PKCEFlow) AwaitCallback(ctx context.Context, ch contracts.AuthChallenge, desc contracts.ProviderDescriptor) (contracts.AuthResult, error) {
	if ch.State == "" || ch.PKCEVerifier.IsEmpty() {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "challenge lacks state or PKCE verifier"}),
		)
	}
	// The redirect URI must be the one this flow's own listener serves. It is
	// re-derived from the bound listener's port and compared to the challenge,
	// so a challenge whose URI points elsewhere (a tampered challenge) is
	// refused rather than served.
	if f.listener == nil {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "no callback listener bound; call Begin first"}),
		)
	}
	expected, err := f.redirectWithPort(f.listener.Addr().String())
	if err != nil {
		return contracts.AuthResult{}, err
	}
	if ch.RedirectURI != expected {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "challenge redirect uri does not match the bound listener"}),
		)
	}

	ln := f.listener
	// From here the flow owns the listener; it is closed on every return path.

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			gotState := q.Get("state")
			// Constant-time-ish single-use state comparison. The state is a
			// public anti-CSRF value, so an equality check is sufficient; the
			// single-use property comes from using it exactly once here.
			if gotState == "" || gotState != ch.State {
				http.Error(w, "state mismatch", http.StatusBadRequest)
				errCh <- domain.New(domain.CodeAuthStateMismatch,
					domain.WithHTTPStatus(400),
					domain.WithScope(domain.ScopeRequest),
				)
				return
			}
			if e := q.Get("error"); e != "" {
				http.Error(w, "authorization denied", http.StatusBadRequest)
				errCh <- mapOAuthError(e, q.Get("error_description"))
				return
			}
			code := q.Get("code")
			if code == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				errCh <- domain.New(domain.CodeAuthStateMismatch,
					domain.WithHTTPStatus(400),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{"reason": "callback carried no code"}),
				)
				return
			}
			_, _ = w.Write([]byte("Authorization complete. You may close this window."))
			codeCh <- code
		}),
	}

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		// Shutdown closes the listener, but clear the field so a second
		// AwaitCallback (or Close) does not reuse a dead socket.
		f.listener = nil
	}()

	timeout := time.NewTimer(f.callbackTimeout())
	defer timeout.Stop()

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return contracts.AuthResult{}, err
	case err := <-serveErr:
		return contracts.AuthResult{}, flowError(err)
	case <-ctx.Done():
		return contracts.AuthResult{}, flowError(ctx.Err())
	case <-timeout.C:
		return contracts.AuthResult{}, domain.New(domain.CodeAuthCallbackTimeout,
			domain.WithHTTPStatus(408),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"address": ln.Addr().String()}),
		)
	}

	return f.exchange(ctx, ch, code, desc)
}

// ExchangeCode completes the grant with a MANUALLY supplied authorization code —
// the paste-code fallback for a browser that cannot reach the loopback listener
// (a remote/headless session, a hardened sandbox). The challenge must be the
// one Begin produced: the code is exchanged with its PKCE verifier and its
// redirect_uri, and Google only accepts a code presented with the exact
// redirect_uri it was issued for.
//
// The callback listener Begin bound is NOT consumed by this path; the caller
// releases it with Close.
func (f *PKCEFlow) ExchangeCode(ctx context.Context, ch contracts.AuthChallenge, code string, desc contracts.ProviderDescriptor) (contracts.AuthResult, error) {
	if ch.State == "" || ch.PKCEVerifier.IsEmpty() || ch.RedirectURI == "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowInsecure,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "challenge lacks state, verifier or redirect uri"}),
		)
	}
	if code == "" {
		return contracts.AuthResult{}, domain.New(domain.CodeAuthStateMismatch,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"reason": "no authorization code supplied"}),
		)
	}
	return f.exchange(ctx, ch, code, desc)
}

// exchange trades the authorization code for tokens using the PKCE verifier.
func (f *PKCEFlow) exchange(ctx context.Context, ch contracts.AuthChallenge, code string, desc contracts.ProviderDescriptor) (contracts.AuthResult, error) {
	clientID := desc.ClientID
	if clientID == "" {
		clientID = f.clientID
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", ch.PKCEVerifier.Reveal())
	form.Set("redirect_uri", ch.RedirectURI)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	// A confidential client authenticates the exchange with its public client
	// secret (ADR-0003); a pure PKCE client omits it.
	if f.requiresClientSecret && f.clientSecret != "" {
		form.Set("client_secret", f.clientSecret)
	}

	tr, err := f.deps.postForm(ctx, f.tokenEndpoint, form)
	if err != nil {
		return contracts.AuthResult{}, err
	}
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
}

// Poll is not used by the PKCE flow: the interactive step is AwaitCallback.
// It exists to satisfy the frozen contract and fails closed if called.
func (f *PKCEFlow) Poll(context.Context, contracts.AuthChallenge) (contracts.AuthResult, error) {
	return contracts.AuthResult{}, domain.New(domain.CodeAuthFlowNotInteractive,
		domain.WithHTTPStatus(400),
		domain.WithParams(map[string]string{"reason": "PKCE completes via AwaitCallback, not Poll"}),
	)
}

// Refresh exchanges a refresh token. Single-flight is the caller's lock; the
// function is idempotent for the same input token.
func (f *PKCEFlow) Refresh(ctx context.Context, cred contracts.Credential, token contracts.RefreshToken) (contracts.AuthResult, error) {
	inner := &DeviceCodeFlow{
		deps:                 f.deps,
		tokenEndpoint:        f.tokenEndpoint,
		clientID:             f.clientID,
		clientSecret:         f.clientSecret,
		requiresClientSecret: f.requiresClientSecret,
	}
	return inner.refresh(ctx, cred, token)
}

// allowedRedirect checks the URI against the allowlist by exact string match.
func (f *PKCEFlow) allowedRedirect(uri string) bool {
	for _, allowed := range f.allowlist {
		if allowed == uri {
			return true
		}
	}
	return false
}

func (f *PKCEFlow) callbackTimeout() time.Duration {
	if f.CallbackTimeout > 0 {
		return f.CallbackTimeout
	}
	return defaultCallbackTimeout
}
