package domain

// Error codes are i18n keys, not prose. The core returns a code plus named
// params; each client (CLI, GUI, API) localises from the embedded catalogs.
// Keeping them as named constants prevents typo drift between the error sites
// and the catalog files.
const (
	CodeInternal                  = "error.internal"
	CodeInvalidRequest            = "error.invalid_request"
	CodeNotFound                  = "error.not_found"
	CodeUnauthorized              = "error.unauthorized"
	CodeForbiddenLocalOnly        = "error.forbidden_local_only"
	CodeMethodNotAllowed          = "error.method_not_allowed"
	CodeUpstreamUnavailable       = "error.upstream_unavailable"
	CodeUpstreamTimeout           = "error.upstream_timeout"
	CodeBadUpstreamResponse       = "error.bad_upstream_response"
	CodeUpstreamResponseTooLarge  = "error.upstream_response_too_large"
	CodeUpstreamInsecureURL       = "error.upstream_insecure_url"
	CodeUpstreamDestinationDenied = "error.upstream_destination_denied"

	CodeConfigLoadFailed      = "config.load_failed"
	CodeConfigInvalidVersion  = "config.invalid_version"
	CodeConfigBindNotLoopback = "config.bind_not_loopback"
	CodeConfigInvalidPort     = "config.invalid_port"
	CodeConfigSecretMissing   = "config.secret_missing"

	CodeStoreOpenFailed    = "store.open_failed"
	CodeStoreMigrateFailed = "store.migrate_failed"
	CodeStoreTokenFailed   = "store.token_failed"
	// CodeStoreVaultPermissions is returned when the vault file or its
	// directory is more permissive than 0600/0700. It carries {path} and {mode}
	// and renders with the corrective action, so the operator knows what to fix.
	CodeStoreVaultPermissions = "store.vault_permissions"

	// Secret/vault codes (ADR-SEC-01). The prefix is deliberately separate from
	// config.* so a failure inside the crypto layer is distinguishable from a
	// missing configuration value.
	CodeSecretInvalidFormat  = "secret.invalid_format"
	CodeSecretUnknownVersion = "secret.unknown_version"
	CodeSecretDecryptFailed  = "secret.decrypt_failed"
	CodeSecretKDFFailed      = "secret.kdf_failed"
	CodeSecretKEKMismatch    = "secret.kek_mismatch"
	CodeSecretEnvDeprecated  = "secret.env_override_deprecated"
	CodeSecretRecoveryFailed = "secret.recovery_failed"
	CodeSecretKeyfileFailed  = "secret.keyfile_failed"
	CodeSecretKeyNotFound    = "secret.key_not_found"

	CodeCredentialStoreFailed     = "credential.store_failed"
	CodeCredentialRefreshWait     = "credential.refresh_wait_cancelled"
	CodeCredentialInvalidAuthMode = "credential.invalid_auth_mode"

	// auth.* — credential and OAuth (ADR-0002 taxonomy). Each site sets these
	// with the exact HTTPStatus/Retryable/Scope from the ADR table.
	CodeAuthTokenExpired      = "auth.token_expired"
	CodeAuthRefreshFailed     = "auth.refresh_failed"
	CodeAuthCredentialInvalid = "auth.credential_invalid"
	CodeAuthScopeInsufficient = "auth.scope_insufficient"
	CodeAuthOAuthDenied       = "auth.oauth_denied"
	CodeAuthStateMismatch     = "auth.oauth_state_mismatch"
	CodeAuthFlowExpired       = "auth.oauth_flow_expired"
	CodeAuthSecretMissing     = "auth.secret_missing"

	// auth.* extras for the flow mechanics that ADR-0002 does not enumerate:
	// a static-key credential driven through the interactive AuthFlow surface,
	// a malformed/insecure flow request, and a callback that never arrived.
	CodeAuthFlowNotInteractive = "auth.flow_not_interactive"
	CodeAuthFlowInsecure       = "auth.flow_insecure"
	CodeAuthCallbackTimeout    = "auth.callback_timeout"
	CodeAuthKeyMissing         = "auth.api_key_missing"
	CodeAuthKeyInvalidFormat   = "auth.api_key_invalid_format"
	// CodeAuthProviderPending is returned when a provider's endpoints or client
	// id are still placeholders, so the family must not be activated against the
	// live service. It is an explicit refusal, not a crash.
	CodeAuthProviderPending = "auth.provider_pending_endpoints"
	// CodeAuthProviderClientSecretMissing is returned when a provider's OAuth
	// flow requires a client secret (e.g. Antigravity's public CLI client) but
	// none was supplied by config/env. The secret is NEVER hardcoded, so the
	// flow fails closed with this code instead of running with a placeholder.
	// Carries {provider}.
	CodeAuthProviderClientSecretMissing = "auth.provider_client_secret_missing"

	// provider.* — the family registry.
	CodeProviderNotFound   = "provider.not_found"
	CodeProviderDuplicate  = "provider.duplicate"
	CodeProviderInvalid    = "provider.invalid"
	CodeProviderNoExecutor = "provider.executor_unavailable"
	// CodeProviderLoginRequired is returned by `provider test` for an OAuth
	// credential: the probe exercises a static API key, so an interactive grant
	// must complete first. It is an explicit refusal, not a crash.
	CodeProviderLoginRequired = "provider.login_required"
	// CodeProviderNoCredential is returned when `provider test` finds no
	// credential for the provider in the vault.
	CodeProviderNoCredential = "provider.no_credential"
	// CodeProviderFuture labels a PLANNED provider whose integration is not
	// shipped yet. It is distinct from a user-fixable block: the provider is
	// listed but not usable in this build.
	CodeProviderFuture = "provider.future"
	// CodeProviderAPIKeyNotSupported is returned when an API key is added to a
	// provider that does not accept AuthAPIKey (e.g. an OAuth provider). It is
	// about the PROVIDER's supported modes, distinct from
	// credential.invalid_auth_mode (a stored credential with an unknown mode).
	CodeProviderAPIKeyNotSupported = "provider.api_key_not_supported"
	// CodeProviderAuthModeUnsupported is returned when a credential's mode is
	// not one the provider supports (e.g. an OAuth credential on an API-key-only
	// family). It names the provider and the offending mode.
	CodeProviderAuthModeUnsupported = "provider.auth_mode_unsupported"
	// CodeProviderRerouteUnsupported is returned when a gate requests a reroute
	// but the dispatcher that validates the target does not exist yet.
	CodeProviderRerouteUnsupported = "provider.reroute_unsupported"
	// CodeProviderAPIKeyReadFailed is returned when `provider add-key` cannot
	// read the key from stdin/the terminal.
	CodeProviderAPIKeyReadFailed = "provider.api_key_read_failed"
	// CodeProviderLoginNotSupported is returned when an interactive OAuth
	// login is requested for a provider whose auth mode is a static API key
	// (the mirror of provider.api_key_not_supported): the actionable fix is
	// `provider add-key`, not a browser grant. Carries {provider}.
	CodeProviderLoginNotSupported = "provider.login_not_supported"

	// translate.* — the pure translator layer (F2.3). A malformed payload or an
	// unmappable shape fails with translate.failed; a lookup for a (from,to)
	// pair with no registered translator fails with translate.unsupported.
	CodeTranslateFailed      = "translate.failed"
	CodeTranslateUnsupported = "translate.unsupported"

	// route.* — combos and routing (F3, ADR-0009/ADR-0013). A combo is a named,
	// validated DAG; every validation failure is typed at SAVE time, so a bad
	// combo never reaches the request path.
	CodeRouteInvalidCombo    = "route.invalid_combo"
	CodeRouteCyclicCombo     = "route.cyclic_combo"
	CodeRouteDepthExceeded   = "route.depth_exceeded"
	CodeRouteFanoutExceeded  = "route.fanout_exceeded"
	CodeRouteUnknownProvider = "route.unknown_provider"
	CodeRouteNoCandidate     = "route.no_candidate"
	// CodeRouteUnknownModel is returned when a combo's `model` step names a
	// model that no registered provider declares. It is DELIBERATELY distinct
	// from route.unknown_provider: a typo in a model id is not an unknown
	// provider, and conflating the two produced a misleading operator message.
	CodeRouteUnknownModel = "route.unknown_model"
	// CodeRouteFusionSelfJudge is returned when a fusion combo's judge resolves
	// to the fusion combo itself: that is infinite recursion and is refused
	// (ADR-0009 §3).
	CodeRouteFusionSelfJudge = "route.fusion_self_judge"
	// CodeRouteFusionAllFailed is returned when every panel of a fusion fan-out
	// failed: there is no winner to judge (ADR-0009 §3).
	CodeRouteFusionAllFailed = "route.fusion_all_failed"

	// quota.* — per-credential quota (F3, ADR-0011). Quota is a FILTER, not a
	// gate: these codes are produced by the QuotaFilter (Skip.Code) and by the
	// Dispatcher's aggregate when a candidate is filtered by quota. Every one is
	// ScopeCredential (cooldown the account until the reset), never ScopeProvider:
	// one account hitting its plan must not open the whole family's circuit.
	CodeQuotaExhausted         = "quota.exhausted"
	CodeQuotaRateLimited       = "quota.rate_limited"
	CodeQuotaCostCap           = "quota.cost_cap"
	CodeQuotaInvalidCredential = "quota.invalid_credential"

	// breaker.* — circuit observability (F3, ADR-0012). `breaker.open`
	// accompanies a preflight Skip (it is not itself an error returned to the
	// client); `breaker.terminal` marks a credential invalid until human action.
	CodeBreakerOpen     = "breaker.open"
	CodeBreakerTerminal = "breaker.terminal"

	// security.* — the F4 security gates. A gate denial is delivered as a
	// DecisionBlock with a SyntheticResponse (never via the dispatcher), so
	// these codes travel in the synthetic {error:{code,params}} envelope.
	// Classification (ADR-0002 rule 1): a client-supplied payload that trips a
	// policy is the REQUEST's fault — ScopeRequest, non-retryable, never
	// cooldowns a credential or a provider — except rate_limited (429,
	// retryable after Retry-After).
	CodeSecurityRateLimited       = "security.rate_limited"
	CodeSecurityDestinationDenied = "security.destination_denied"
	CodeSecurityInjectionDetected = "security.injection_detected"
	CodeSecurityPIIBlocked        = "security.pii_blocked"

	// dispatch.* — the Dispatcher's aggregate outcomes (F3, ADR-0010 §7).
	// These are produced when the attempt loop ends without a winner; they
	// inherit the last attempt's classification so the caller/breaker acts on
	// the most recent cause.
	CodeDispatchNoAttempts = "dispatch.no_attempts"
	CodeDispatchExhausted  = "dispatch.exhausted"
	CodeDispatchMaxRounds  = "dispatch.max_rounds"

	// import.* — read-only harness credential import (F1.6).
	CodeImportFailed        = "import.failed"
	CodeImportSourceMissing = "import.source_missing"
	CodeImportMalformed     = "import.malformed"

	CodeHealthOK = "api.health_ok"
	CodePingOK   = "api.ping_ok"
	CodeModelsOK = "api.models_ok"

	CodeStartupListening     = "startup.listening"
	CodeStartupTokenReady    = "startup.management_token_written"
	CodeStartupShutdown      = "startup.shutdown"
	CodeTokenRotationOK      = "api.mgmt.token_rotated"
	CodeManagementAuthFailed = "api.mgmt.token_invalid"
	// CodeTokenRotateThrottled refuses a management-token rotation inside the
	// ADR-SEC-06 §4.2 window (at most one rotation per 5s). It carries
	// {retry_after} and is emitted with a Retry-After header, 429.
	CodeTokenRotateThrottled = "token.rotate_throttled"

	// clientkey.* — the F5 client-key authentication of the inference gateway
	// (/v1/*, ADR-SEC-06 §2). The code is deliberately named "clientkey" so a
	// rejected client key is never confused with the management token
	// (api.mgmt.token_invalid) on either side of the separation of privilege.
	//
	//   - CodeClientKeyInvalid: absent, malformed, unknown or revoked client
	//     key. ScopeRequest, 401: the request must never cool down a credential
	//     and never leaks whether the key existed. This is the code the F5.1
	//     task specifies for the gateway's 401.
	CodeClientKeyInvalid = "clientkey.invalid"
	// CodeClientKeyStoreFailed: a client-key persistence failure (DB error).
	CodeClientKeyStoreFailed = "clientkey.store_failed"
	// CodeClientKeyNotFound: the id passed to `client-key revoke` does not
	// exist. It carries {id} so the operator sees which id was wrong.
	CodeClientKeyNotFound = "clientkey.not_found"
	// CodeClientKeyCreated is the success line of `client-key create`; it
	// carries {id} and {label} only — the key itself is printed on its own line
	// by the CLI, never through the catalog or the logger.
	CodeClientKeyCreated = "api.clientkey.created"
	// CodeClientKeyRevoked is the success line of `client-key revoke` ({id}).
	CodeClientKeyRevoked = "api.clientkey.revoked"

	// server.* — anti-DNS-rebinding and anti-CSRF (ADR-SEC-06 §3). Both are
	// ScopeRequest and 403: the caller is a browser-driven or rebinding request
	// whose Host/Origin is not a local origin, refused before routing.
	//
	//   - CodeServerHostInvalid: the Host header is not on the loopback/local
	//     allowlist (a public name or a rebinding domain such as
	//     127.0.0.1.nip.io).
	//   - CodeServerOriginInvalid: a mutating request's Origin/Referer is not a
	//     local origin (anti-CSRF).
	CodeServerHostInvalid   = "server.host_invalid"
	CodeServerOriginInvalid = "server.origin_invalid"

	// CodeStartupWarningRemoteAccess is the WARN log emitted when the operator
	// deliberately binds a non-loopback address (ADR-SEC-06 §6.2). It is a log
	// message, not an HTTP error: the process keeps running.
	CodeStartupWarningRemoteAccess = "startup.remote_access_warning"

	// cli.* — operator-facing messages emitted by the F5.3 CLI commands (quota,
	// gate, config). They are ordinary i18n codes localised from the same
	// embedded catalogs as every other message (ADR-002): the CLI never prints
	// server prose, it renders a code through the negotiated language.
	//
	//   - CodeCLIQuotaNoState: a stored credential has no recorded quota window
	//     yet (the filter fail-opens); the honest answer is "nothing recorded".
	//   - CodeCLIQuotaUnknown: `quota show` was given a credential id that is
	//     not in the vault. Carries {id}.
	//   - CodeCLIGateNotEnabled: `gate show` named a gate that is not in the
	//     effective chain. Carries {name}; the message notes it may be disabled
	//     by config.
	//   - CodeCLIGateConfigOnly: gates are switched in the config file, so there
	//     is no runtime enable/disable (the chain is built once at boot).
	//   - CodeCLIConfigNoFile: `config show`/`config path` found no config file;
	//     built-in defaults are in effect.
	CodeCLIQuotaNoState   = "cli.quota.no_state"
	CodeCLIQuotaUnknown   = "cli.quota.unknown"
	CodeCLIGateNotEnabled = "cli.gate.not_enabled"
	CodeCLIGateConfigOnly = "cli.gate.config_only"
	CodeCLIConfigNoFile   = "cli.config.no_file"
	// cli.login.* — the `heimdall login` messages (BD-02). The authorization
	// URL is {url} data interpolated into the template. None of them ever
	// carries a token or the client secret.
	CodeCLILoginOpenURL  = "cli.login.open_url"
	CodeCLILoginCodeHint = "cli.login.code_hint"
)
