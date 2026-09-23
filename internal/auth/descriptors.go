package auth

import (
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Provider identifiers for the four F1 providers. They are the ProviderID
// values the registry is keyed by.
const (
	ProviderAntigravity domain.ProviderID = "antigravity"
	ProviderZAI         domain.ProviderID = "z.ai"
	ProviderOllamaCloud domain.ProviderID = "ollama-cloud"
	ProviderCommandCode domain.ProviderID = "command-code"
)

// Descriptors returns the static description of every F1 provider, keyed by ID.
//
// ENDPOINT PROVENANCE — read before trusting a value:
//
// The API-key providers (z.ai, Ollama Cloud, Command Code) need no OAuth
// endpoints, so their descriptors are complete: only the family identity and
// auth mode matter.
//
// Antigravity is the only OAuth provider. Its authorization/token endpoints
// and the public CLI client were confirmed against the reference connector
// (registry/antigravity.js) and the installed `agy` binary (ADR-0003 context),
// so PendingEndpoints is empty and the provider participates in readiness like
// any other: credential present -> ready, absent -> blocked(login_required).
func Descriptors() map[domain.ProviderID]contracts.ProviderDescriptor {
	return map[domain.ProviderID]contracts.ProviderDescriptor{
		ProviderAntigravity: {
			ID:          ProviderAntigravity,
			Protocol:    contracts.WireCloudCode,
			DisplayName: "Antigravity",
			// Endpoints and the public CLI client are confirmed against the
			// reference connector (registry/antigravity.js) and the installed
			// `agy` binary (ADR-0003 context).
			AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenEndpoint: "https://oauth2.googleapis.com/token",
			DefaultScopes: []string{
				"https://www.googleapis.com/auth/cloud-platform",
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/cclog",
				"https://www.googleapis.com/auth/experimentsandconfigs",
			},
			// The loopback callback allowlist is the stable URI; the ephemeral
			// port is validated by the bind.
			RedirectAllowlist: []string{"http://127.0.0.1/callback"},
			// The PUBLIC client id embedded in the vendor CLI (ADR-0003). The
			// matching client SECRET is deliberately NOT hardcoded here: a
			// secret literal in the source is a secret-scanning hazard and must
			// never ship in the repo. The operator supplies it via the
			// provider's `client_secret` / `client_secret_env` config, and the
			// composition root injects it (see NewFlowFactoryWithSecrets). With
			// no secret the Antigravity flow fails closed.
			ClientID:             "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
			RequiresClientSecret: true,
			Obfuscation:          antigravityObfuscation(),
			RiskNotice:           "provider.risk_notice.antigravity",
			// BD-02: the interactive login surface (`heimdall login`) and the
			// vault persistence ship with this descriptor, so it is no longer
			// Future. Readiness is credential-driven: without a stored
			// credential the provider is blocked(provider.login_required)
			// (fixable by the user); with one it is ready. The client SECRET
			// stays operator-supplied (see RequiresClientSecret above) and a
			// login without it fails closed.
		},
		ProviderZAI: {
			ID:          ProviderZAI,
			Protocol:    contracts.WireOpenAI,
			DisplayName: "Z.ai",
		},
		ProviderOllamaCloud: {
			ID:          ProviderOllamaCloud,
			Protocol:    contracts.WireOpenAI,
			DisplayName: "Ollama Cloud",
		},
		ProviderCommandCode: {
			ID:          ProviderCommandCode,
			Protocol:    contracts.WireOpenAI,
			DisplayName: "Command Code",
		},
	}
}

// Descriptor returns one provider's descriptor, or provider.not_found.
func Descriptor(id domain.ProviderID) (contracts.ProviderDescriptor, error) {
	desc, ok := Descriptors()[id]
	if !ok {
		return contracts.ProviderDescriptor{}, domain.New(domain.CodeProviderNotFound,
			domain.WithHTTPStatus(404),
			domain.WithParams(map[string]string{"provider": string(id)}),
		)
	}
	return desc, nil
}

// PendingEndpoints lists the provider IDs whose endpoints are placeholders
// awaiting confirmation. The composition root must not enable these against the
// live service until this list is empty for them. It is EMPTY as of Wave 2:
// Antigravity's endpoints and public CLI client were confirmed (ADR-0003), so
// no provider has an unconfirmed endpoint.
func PendingEndpoints() map[domain.ProviderID][]string {
	return map[domain.ProviderID][]string{}
}

// antigravityObfuscation is the per-provider harness-fingerprint layer for
// Antigravity (ADR-0003 §1). It is DATA, so it is testable and versioned: the
// executor applies it, the obfuscate package implements it, and a golden file
// pins the effect of each technique.
func antigravityObfuscation() contracts.Obfuscation {
	return contracts.Obfuscation{
		// The official IDE UA, pinned even off macOS (ADR-0003 §2).
		UserAgent:         "antigravity/ide/2.11.0 darwin/arm64",
		RequiresUserAgent: true,
		PromptRewrites: []contracts.PromptRewrite{
			// Competing-client branding that makes the backend flag the request
			// with a fake 429 (ADR-0003 §2). The regex forms carry inline RE2
			// flags (?i)/(?im) because Go has no /gim suffix.
			{From: "You are a Claude agent, built on Anthropic's Claude Agent SDK.", To: ""},
			{From: `(?im)^x-anthropic-billing-header:[^\n]*(?:\r?\n)*`, To: "", IsRegex: true},
			{From: "opencode", To: "antigravity"},
		},
		ToolCloaking: &contracts.ToolCloaking{
			NameSuffix: "_ide",
			DecoyTools: antigravityDecoyTools(),
		},
		SyntheticProject: true,
	}
}

// antigravityDecoyTools are the native IDE tool names injected as neutral
// decoys; the description matches the reference connector's "currently
// unavailable" text.
func antigravityDecoyTools() []contracts.ToolDecoy {
	names := []string{
		"browser_subagent", "command_status", "find_by_name", "generate_image",
		"grep_search", "list_dir", "list_resources", "mcp_sequential-thinking_sequentialthinking",
		"multi_replace_file_content", "notify_user", "read_resource", "read_terminal",
		"read_url_content", "replace_file_content", "run_command", "search_web",
		"send_command_input", "task_boundary", "view_content_chunk", "view_file",
		"write_to_file",
	}
	out := make([]contracts.ToolDecoy, 0, len(names))
	for _, n := range names {
		out = append(out, contracts.ToolDecoy{Name: n, Description: "This tool is currently unavailable."})
	}
	return out
}
