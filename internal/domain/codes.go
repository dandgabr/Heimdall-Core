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

	// provider.* — the family registry.
	CodeProviderNotFound   = "provider.not_found"
	CodeProviderDuplicate  = "provider.duplicate"
	CodeProviderInvalid    = "provider.invalid"
	CodeProviderNoExecutor = "provider.executor_unavailable"

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
)
