// OAuth login surface (BD-02): the composition-root orchestration of an
// interactive provider grant — `heimdall login <provider-id>`.
//
// The flow factory builds the concrete OAuth flow (fail-closed on a missing
// operator client secret, ADR-0003); this layer owns everything AROUND the
// grant: the readiness preconditions, the seal-and-persist of the resulting
// credential, the non-secret status view and the single-flight refresh.
//
// Security invariants (ADR-SEC-01, ADR-0002):
//   - the access and refresh tokens exist in plaintext only inside this call
//     chain; they are sealed into ONE enc:v1 blob and never logged, printed or
//     returned. Meta carries only non-secret identity (email, project, tier).
//   - a credential blob is a contracts.CredentialBlob document: the refresh
//     token never lives outside the ciphertext, and a malformed blob fails
//     closed instead of sending an empty bearer upstream.
//   - Refresh holds CredentialStore.RefreshLock for the whole exchange and
//     RE-READS the credential under the lock, so N concurrent refreshes
//     collapse into exactly one upstream exchange and the losers observe its
//     persisted result.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// callbackAwaiter is implemented by the interactive flows that complete by
// serving their own loopback callback (PKCE / Antigravity). It mirrors the
// concrete signature; a device-code flow would fail the assertion in Complete
// instead of blocking forever.
type callbackAwaiter interface {
	AwaitCallback(context.Context, contracts.AuthChallenge, contracts.ProviderDescriptor) (contracts.AuthResult, error)
}

// codeExchanger is implemented by flows that can complete from a manually
// pasted authorization code — the fallback for a browser that cannot reach the
// loopback listener.
type codeExchanger interface {
	ExchangeCode(context.Context, contracts.AuthChallenge, string, contracts.ProviderDescriptor) (contracts.AuthResult, error)
}

// loginFlowCloser releases the loopback listener a PKCE-style Begin bound.
type loginFlowCloser interface {
	Close() error
}

// loginFlowBuilder is a seam over the flow factory's Build for the login
// surface. Production routes to a.Flows.Build (fail-closed on a missing client
// secret); a test injects a stub flow to reach the capability-refusal branches
// a real flow never provokes (same pattern as the newRouter seam).
var loginFlowBuilder = func(a *App, id domain.ProviderID) (contracts.AuthFlow, error) {
	return a.Flows.Build(id)
}

// encodeCredentialBlob is a seam over the blob encoder, so the marshal-error
// branch of the persist path is reachable in a test (a plain-string document
// cannot fail in production).
var encodeCredentialBlob = contracts.EncodeCredentialBlob

// LoginSession is one in-flight OAuth login, between BeginLogin and Complete.
// It carries the flow (which owns the bound callback listener and the PKCE
// verifier) and the challenge; the verification URL is exposed through
// accessors so the caller can never print the verifier by accident.
type LoginSession struct {
	app       *App
	provider  domain.ProviderID
	desc      contracts.ProviderDescriptor
	flow      contracts.AuthFlow
	challenge contracts.AuthChallenge
}

// AuthURL is the provider authorization URL the operator opens in a browser.
// It carries the state and the S256 challenge — both public — never the
// verifier.
func (s *LoginSession) AuthURL() string { return s.challenge.VerificationURI }

// CallbackURI is the loopback redirect URI with the concrete ephemeral port
// the flow is listening on.
func (s *LoginSession) CallbackURI() string { return s.challenge.RedirectURI }

// RiskNotice is the provider's ToS warning i18n code (ADR-0003 §4), shown at
// login because that is the moment the subscription session is connected.
func (s *LoginSession) RiskNotice() string { return s.desc.RiskNotice }

// close releases the callback listener. Safe on every path: AwaitCallback
// shuts the server down itself, and Close on a consumed listener is a no-op.
func (s *LoginSession) close() {
	if c, ok := s.flow.(loginFlowCloser); ok {
		_ = c.Close()
	}
}

// BeginLogin starts an OAuth login for provider id. It is fail-closed and
// typed:
//   - unknown provider                              -> provider.not_found;
//   - a provider that does not support OAuth        -> provider.login_not_supported
//     (the CLI points API-key providers at `provider add-key`);
//   - no KEK configured                             -> config.secret_missing
//     (the resulting credential could not be sealed);
//   - the flow not buildable (missing client secret, pending endpoints)
//     -> the factory's typed error, e.g. auth.provider_client_secret_missing.
//
// On success the authorization URL is live and the loopback callback is bound.
func (a *App) BeginLogin(ctx context.Context, id domain.ProviderID) (*LoginSession, error) {
	family, err := a.Providers.Get(id)
	if err != nil {
		return nil, err
	}
	if !supportsAuthMode(family.AuthModes(), contracts.AuthOAuth) {
		return nil, domain.New(domain.CodeProviderLoginNotSupported,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	if a.Secrets == nil {
		// The grant would succeed and then be unpersistable: refuse first.
		return nil, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	// The factory refuses pending endpoints and a missing client secret with
	// typed codes; nothing here ever substitutes a placeholder secret.
	flow, err := loginFlowBuilder(a, id)
	if err != nil {
		return nil, err
	}
	desc, err := a.descriptorOf(id)
	if err != nil {
		return nil, err
	}
	// A flow that can neither serve the loopback callback nor exchange a
	// pasted code cannot complete a login at all: refuse rather than start a
	// grant that can only hang until its expiry.
	if _, isAwaiter := flow.(callbackAwaiter); !isAwaiter {
		if _, isExchanger := flow.(codeExchanger); !isExchanger {
			if c, ok := flow.(loginFlowCloser); ok {
				_ = c.Close()
			}
			return nil, domain.New(domain.CodeAuthFlowInsecure,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": "flow supports neither the loopback callback nor a pasted code"}),
			)
		}
	}
	ch, err := flow.Begin(ctx, desc)
	if err != nil {
		if c, ok := flow.(loginFlowCloser); ok {
			_ = c.Close()
		}
		return nil, err
	}
	return &LoginSession{app: a, provider: id, desc: desc, flow: flow, challenge: ch}, nil
}

// Complete finishes a login started by BeginLogin. With pastedCode empty it
// waits for the browser on the loopback callback (bounded by the challenge
// expiry); with a code supplied it exchanges the pasted authorization code
// instead and never waits. Either path runs the provider's post-exchange
// (project/tier discovery) and seals the credential into the vault.
//
// The callback listener is released on every return path.
func (s *LoginSession) Complete(ctx context.Context, pastedCode string) (LoginResult, error) {
	defer s.close()
	var (
		res contracts.AuthResult
		err error
	)
	if pastedCode != "" {
		ex, ok := s.flow.(codeExchanger)
		if !ok {
			return LoginResult{}, domain.New(domain.CodeAuthFlowInsecure,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": "flow cannot exchange a pasted code"}),
			)
		}
		res, err = ex.ExchangeCode(ctx, s.challenge, pastedCode, s.desc)
	} else {
		aw, ok := s.flow.(callbackAwaiter)
		if !ok {
			return LoginResult{}, domain.New(domain.CodeAuthFlowInsecure,
				domain.WithHTTPStatus(500),
				domain.WithParams(map[string]string{"reason": "flow does not serve a loopback callback"}),
			)
		}
		res, err = aw.AwaitCallback(ctx, s.challenge, s.desc)
	}
	if err != nil {
		return LoginResult{}, err
	}
	return s.app.persistLogin(ctx, s.provider, res)
}

// LoginResult reports a completed login. It carries NO token: only the
// non-secret identity the operator needs to confirm the right account landed.
type LoginResult struct {
	Provider     domain.ProviderID
	CredentialID domain.CredentialID
	Label        string
	Email        string
	Project      string
	Plan         string
	// Upserted is true when an existing credential for the same account was
	// replaced (idempotent re-login), false when a new row was created.
	Upserted bool
}

// persistLogin seals the grant result into the vault. The credential id is
// deterministic per provider+account, so re-logging the same account updates
// the same row instead of duplicating it.
func (a *App) persistLogin(ctx context.Context, provider domain.ProviderID, res contracts.AuthResult) (LoginResult, error) {
	label := res.Account.Email
	if label == "" {
		label = string(provider)
	}
	meta := res.Account
	meta.DisplayName = label
	credID := oauthCredentialID(provider, res.Account.Subject, res.Account.Email)
	_, getErr := a.Credentials.Get(ctx, credID)
	existed := getErr == nil

	if err := a.upsertOAuthBlob(ctx, provider, credID, label, meta, res, oauthBlobSource{
		refresh: res.Token.Token.Reveal(),
		rotated: res.Token.Rotated,
	}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		Provider:     provider,
		CredentialID: credID,
		Label:        label,
		Email:        res.Account.Email,
		Project:      res.Account.Project,
		Plan:         res.Account.Plan,
		Upserted:     existed,
	}, nil
}

// oauthCredentialID derives a deterministic, non-secret credential id from the
// provider and the account identity (subject, then email as fallback), the
// same pattern as apiKeyCredentialID: a re-login of the same account is an
// update, never a duplicate row.
func oauthCredentialID(provider domain.ProviderID, subject, email string) domain.CredentialID {
	sum := sha256.Sum256([]byte("login:" + string(provider) + ":" + subject + ":" + email))
	return domain.CredentialID(fmt.Sprintf("oauth-%s-%s", provider, hex.EncodeToString(sum[:8])))
}

// LoginStatus is the non-secret state of a provider's stored login (`heimdall
// login --status <id>`). It reads vault METADATA only: it never opens the
// sealed blob, so it works even without a KEK and can never surface a token.
type LoginStatus struct {
	Provider     domain.ProviderID
	LoggedIn     bool
	CredentialID domain.CredentialID
	Label        string
	Email        string
	Subject      string
	Project      string
	Plan         string
	// ExpiresAt is when the stored access token expires (zero = unknown).
	ExpiresAt time.Time
	// Expired is true when ExpiresAt is in the past; refresh renews it.
	Expired bool
	// ReasonCode is the i18n code explaining a logged-out provider.
	ReasonCode string
}

// LoginStatus reports whether the vault holds a usable OAuth credential for
// provider id, without ever touching the secret material.
func (a *App) LoginStatus(ctx context.Context, id domain.ProviderID) (LoginStatus, error) {
	family, err := a.Providers.Get(id)
	if err != nil {
		return LoginStatus{}, err
	}
	st := LoginStatus{Provider: id}
	cred, err := a.credentialFor(ctx, id)
	if err != nil {
		if de, ok := err.(*domain.DomainError); ok && de.Code == domain.CodeProviderNoCredential {
			if supportsAuthMode(family.AuthModes(), contracts.AuthOAuth) {
				st.ReasonCode = domain.CodeProviderLoginRequired
			} else {
				st.ReasonCode = domain.CodeProviderNoCredential
			}
			return st, nil
		}
		return LoginStatus{}, err
	}
	if cred.AuthMode != contracts.AuthOAuth {
		st.ReasonCode = domain.CodeCredentialInvalidAuthMode
		return st, nil
	}
	st.LoggedIn = true
	st.CredentialID = cred.ID
	st.Label = cred.Label
	st.Email = cred.Meta.Email
	st.Subject = cred.Meta.Subject
	st.Project = cred.Meta.Project
	st.Plan = cred.Meta.Plan
	st.ExpiresAt = cred.ExpiresAt
	st.Expired = !cred.ExpiresAt.IsZero() && !time.Now().UTC().Before(cred.ExpiresAt)
	return st, nil
}

// RefreshResult reports one refresh run. No token material.
type RefreshResult struct {
	Provider     domain.ProviderID
	CredentialID domain.CredentialID
	// ExpiresAt is the new access-token expiry.
	ExpiresAt time.Time
	// Collapsed is true when another concurrent refresher had already
	// completed the exchange while this caller waited on the single-flight
	// lock, so no second upstream call was made.
	Collapsed bool
}

// RefreshProvider exchanges the provider's stored refresh token for fresh
// access material and persists it (BD-02 §3).
//
// Single-flight contract (contracts.AuthFlow.Refresh): the per-credential
// RefreshLock is held across the re-read, the exchange and the persist, so N
// concurrent callers produce exactly ONE upstream exchange — the losers
// re-read the freshly persisted credential under the lock and observe its
// result (Collapsed). The provider's projectId/tier survive in Meta: the flow
// copies the stored account metadata onto the refreshed result.
//
// Failures are typed and fail-closed:
//   - missing client secret (config/env) -> auth.provider_client_secret_missing;
//   - no stored credential               -> provider.no_credential;
//   - a malformed/undecryptable blob or a missing refresh token
//     -> auth.credential_invalid (re-login);
//   - a revoked refresh token            -> auth.credential_invalid (the flow's
//     mapping of invalid_grant); transient failures are auth.refresh_failed.
func (a *App) RefreshProvider(ctx context.Context, id domain.ProviderID) (RefreshResult, error) {
	family, err := a.Providers.Get(id)
	if err != nil {
		return RefreshResult{}, err
	}
	if !supportsAuthMode(family.AuthModes(), contracts.AuthOAuth) {
		return RefreshResult{}, domain.New(domain.CodeProviderLoginNotSupported,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	if a.Secrets == nil {
		return RefreshResult{}, domain.New(domain.CodeConfigSecretMissing,
			domain.WithHTTPStatus(500),
		)
	}
	// Fail closed before any network I/O when the operator secret is absent.
	flow, err := a.Flows.Build(id)
	if err != nil {
		return RefreshResult{}, err
	}
	cred, err := a.credentialFor(ctx, id)
	if err != nil {
		return RefreshResult{}, err
	}
	if cred.AuthMode != contracts.AuthOAuth {
		return RefreshResult{}, domain.New(domain.CodeCredentialInvalidAuthMode,
			domain.WithHTTPStatus(500),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"id": string(cred.ID), "mode": cred.AuthMode.String()}),
		)
	}
	before, err := a.openOAuthBlob(cred)
	if err != nil {
		return RefreshResult{}, err
	}
	if before.RefreshToken == "" {
		return RefreshResult{}, domain.New(domain.CodeAuthCredentialInvalid,
			domain.WithHTTPStatus(401),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"reason": "stored credential has no refresh token; log in again"}),
		)
	}

	unlock, err := a.Credentials.RefreshLock(ctx, cred.ID)
	if err != nil {
		return RefreshResult{}, err
	}
	defer unlock()

	// Re-read under the lock: a concurrent refresher may have rotated the row
	// between our snapshot and the lock acquisition.
	fresh, err := a.Credentials.Get(ctx, cred.ID)
	if err != nil {
		return RefreshResult{}, err
	}
	after, err := a.openOAuthBlob(fresh)
	if err != nil {
		return RefreshResult{}, err
	}
	if after.AccessToken != before.AccessToken {
		// The row changed while we waited: the exchange already happened.
		return RefreshResult{Provider: id, CredentialID: cred.ID, ExpiresAt: fresh.ExpiresAt, Collapsed: true}, nil
	}

	res, err := flow.Refresh(ctx, fresh, contracts.RefreshToken{Token: contracts.Secret(after.RefreshToken)})
	if err != nil {
		return RefreshResult{}, err
	}
	if err := a.upsertOAuthBlob(ctx, id, fresh.ID, fresh.Label, res.Account, res, oauthBlobSource{
		refresh: after.RefreshToken,
		rotated: res.Token.Rotated,
	}); err != nil {
		return RefreshResult{}, err
	}
	return RefreshResult{Provider: id, CredentialID: fresh.ID, ExpiresAt: res.ExpiresAt}, nil
}

// oauthBlobSource carries the refresh-token inputs of a persist: the token to
// store and whether the grant ROTATED it (a provider that reuses the previous
// refresh token keeps the stored one, RFC 6749 §6).
type oauthBlobSource struct {
	refresh string
	rotated bool
}

// upsertOAuthBlob seals access+refresh into one blob and upserts the
// credential row. The plaintext exists only inside this call; on any failure
// nothing partially-written escapes.
func (a *App) upsertOAuthBlob(ctx context.Context, provider domain.ProviderID, credID domain.CredentialID, label string, meta contracts.AccountMeta, res contracts.AuthResult, src oauthBlobSource) error {
	refresh := src.refresh
	if src.rotated && !res.Token.Token.IsEmpty() {
		refresh = res.Token.Token.Reveal()
	}
	raw, err := encodeCredentialBlob(contracts.CredentialBlob{
		AccessToken:  res.Access.Reveal(),
		RefreshToken: refresh,
	})
	if err != nil {
		return domain.New(domain.CodeCredentialStoreFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "encode oauth credential blob"}),
		)
	}
	// sealer is the app's SecretStore in production; the injected seam covers
	// the seal-failure branch in tests (same pattern as AddAPIKey).
	var sealer apiKeySealer = a.Secrets
	if a.sealer != nil {
		sealer = a.sealer
	}
	sealed, err := sealer.Seal(raw)
	if err != nil {
		return domain.New(domain.CodeCredentialStoreFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "seal failed"}),
		)
	}
	cred := contracts.Credential{
		ID:        credID,
		Provider:  provider,
		AuthMode:  contracts.AuthOAuth,
		Label:     label,
		Meta:      meta,
		Sealed:    []byte(sealed),
		ExpiresAt: res.ExpiresAt,
	}
	return a.Credentials.Upsert(ctx, cred)
}

// credentialRefresher adapts the App to the executors' optional
// contracts.CredentialRefresher port (BD02-1): it runs the single-flight
// refresh through RefreshProvider and re-reads the persisted row, so the
// executor presents the renewed bearer and concurrent requests observe the
// same renewed credential. On refresh failure it returns the ORIGINAL
// credential alongside the error (the executor fails open with it).
type credentialRefresher struct {
	app *App
}

// RefreshCredential implements contracts.CredentialRefresher.
func (r credentialRefresher) RefreshCredential(ctx context.Context, cred contracts.Credential) (contracts.Credential, error) {
	if _, err := r.app.RefreshProvider(ctx, cred.Provider); err != nil {
		return cred, err
	}
	return r.app.Credentials.Get(ctx, cred.ID)
}

// openOAuthBlob decrypts and parses a stored OAuth credential. A decrypt
// failure is auth.secret_missing (the KEK cannot open the row); a malformed
// document is auth.credential_invalid — the row is readable but unusable and
// the actionable fix is a fresh login, never a silent empty token.
func (a *App) openOAuthBlob(cred contracts.Credential) (contracts.CredentialBlob, error) {
	plaintext, err := a.Secrets.Open(string(cred.Sealed))
	if err != nil {
		return contracts.CredentialBlob{}, domain.New(domain.CodeAuthSecretMissing,
			domain.WithHTTPStatus(500),
			domain.WithScope(domain.ScopeCredential),
		)
	}
	blob, err := contracts.ParseCredentialBlob(plaintext)
	if err != nil {
		return contracts.CredentialBlob{}, domain.New(domain.CodeAuthCredentialInvalid,
			domain.WithHTTPStatus(401),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"reason": "stored oauth credential is malformed; log in again"}),
		)
	}
	return blob, nil
}
