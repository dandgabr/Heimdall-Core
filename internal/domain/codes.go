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

	CodeHealthOK = "api.health_ok"
	CodePingOK   = "api.ping_ok"
	CodeModelsOK = "api.models_ok"

	CodeStartupListening     = "startup.listening"
	CodeStartupTokenReady    = "startup.management_token_written"
	CodeStartupShutdown      = "startup.shutdown"
	CodeTokenRotationOK      = "api.mgmt.token_rotated"
	CodeManagementAuthFailed = "api.mgmt.token_invalid"
)
