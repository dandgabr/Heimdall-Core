// Package importers reads credentials already present on the machine (from
// other harnesses) and writes them into the CredentialStore.
//
// Contract (F1.6):
//   - READ-ONLY over the source files: the importer never creates, edits or
//     moves them.
//   - The value is sealed by the SecretStore BEFORE it reaches the store, so no
//     plaintext is ever persisted (the store never sees it either).
//   - Only the credential ID/label is logged; the value never is.
//   - Import is idempotent: running it twice upserts the same CredentialID
//     instead of creating a duplicate.
package importers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// EnvOpenCodePath overrides the opencode auth file location.
const EnvOpenCodePath = "HEIMDALL_IMPORT_OPENCODE"

// Result reports one imported (or skipped) credential without its value.
type Result struct {
	// Provider is the target provider family.
	Provider domain.ProviderID
	// CredentialID is the deterministic ID written to the store.
	CredentialID domain.CredentialID
	// Label is the human label ("opencode:ollama-cloud").
	Label string
	// Skipped is true when the source had no entry for this provider.
	Skipped bool
}

// Store is the persistence surface the importer needs. It is the frozen
// contracts.CredentialStore, so the importer depends on no concrete type.
type Store interface {
	Upsert(ctx context.Context, cred contracts.Credential) error
	Get(ctx context.Context, id domain.CredentialID) (contracts.Credential, error)
}

// Sealer seals plaintext before persistence. It is satisfied by *secret.Store.
type Sealer interface {
	Seal(plaintext []byte) (string, error)
}

// Importer imports every source it knows about into the store.
type Importer struct {
	Store  Store
	Sealer Sealer
	// Env is the environment snapshot (nil means os.Getenv).
	Env map[string]string
	// Home overrides the home directory (tests).
	Home string
	// Now is the clock for CreatedAt/ExpiresAt (nil means the store's own).
	Now func() string
}

// ImportAll runs every source and returns the per-credential results. A missing
// source is not an error: a machine that never used opencode simply imports
// nothing from it.
func (im *Importer) ImportAll(ctx context.Context) ([]Result, error) {
	var results []Result

	oc, err := im.importOpenCode(ctx)
	if err != nil {
		return results, err
	}
	results = append(results, oc...)

	cc, err := im.importCommandCode(ctx)
	if err != nil {
		return results, err
	}
	results = append(results, cc...)

	// Antigravity: no readable token file is known, so nothing is imported.
	// See importAntigravity for the rationale.
	ag, err := antigravityImport(im, ctx)
	if err != nil {
		return results, err
	}
	results = append(results, ag...)

	return results, nil
}

// --- opencode ---

// opencodeAuth is the schema of ~/.local/share/opencode/auth.json:
//
//	{ "<id>": { "type": "api", "key": "..." }, ... }
type opencodeAuth map[string]struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// providerMap maps a source provider name to (target provider, label).
//
// The brief fixes two renames: zai-coding-plan -> z.ai and
// ollama-cloud -> Ollama Cloud. opencode-go is mapped to the command-code
// family because it is the same harness account.
var opencodeProviderMap = map[string]struct {
	Provider domain.ProviderID
	Label    string
}{
	"zai-coding-plan": {Provider: "z.ai", Label: "Z.ai"},
	"ollama-cloud":    {Provider: "ollama-cloud", Label: "Ollama Cloud"},
	"opencode-go":     {Provider: "command-code", Label: "Command Code"},
}

func (im *Importer) importOpenCode(ctx context.Context) ([]Result, error) {
	path := im.env(EnvOpenCodePath)
	if path == "" {
		path = filepath.Join(im.home(), ".local", "share", "opencode", "auth.json")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // source absent: nothing to import
		}
		return nil, importError("opencode", err)
	}

	var auth opencodeAuth
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, domain.New(domain.CodeImportMalformed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"path": path, "reason": "invalid JSON"}),
		)
	}

	var results []Result
	for sourceID, entry := range auth {
		mapping, ok := opencodeProviderMap[sourceID]
		if !ok || entry.Key == "" {
			continue
		}
		res, err := im.storeSealed(ctx, mapping.Provider, mapping.Label, sourceID, entry.Key)
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// --- command code ---

// commandCodeAuth is the schema of ~/.commandcode/auth.json.
type commandCodeAuth struct {
	APIKey          string `json:"apiKey"`
	UserID          string `json:"userId"`
	UserName        string `json:"userName"`
	KeyName         string `json:"keyName"`
	AuthenticatedAt string `json:"authenticatedAt"`
}

func (im *Importer) importCommandCode(ctx context.Context) ([]Result, error) {
	path := filepath.Join(im.home(), ".commandcode", "auth.json")

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, importError("command-code", err)
	}

	var cc commandCodeAuth
	if err := json.Unmarshal(raw, &cc); err != nil {
		return nil, domain.New(domain.CodeImportMalformed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"path": path, "reason": "invalid JSON"}),
		)
	}
	if cc.APIKey == "" {
		return nil, nil
	}

	label := cc.KeyName
	if label == "" {
		label = "Command Code"
	}
	res, err := im.storeSealed(ctx, "command-code", label, "command-code", cc.APIKey)
	if err != nil {
		return nil, err
	}
	return []Result{res}, nil
}

// --- antigravity ---

// importAntigravity deliberately imports nothing.
//
// The `agy` binary owns the Antigravity OAuth session and there is no
// documented, readable token file this importer can rely on: the tokens are
// managed by the harness (possibly in an OS keyring or an encrypted store we
// have no contract for). Reading an undocumented file would be guessing at a
// format, and the brief explicitly prefers not to depend on `agy`.
//
// The supported path is to run the OAuth flow through internal/auth (the
// Antigravity descriptor) and let the flow write the sealed credential. This
// function exists so ImportAll reports the decision rather than silently
// omitting it.
//
// TODO(F1): if Antigravity documents a readable token file, add a source here
// following the opencode pattern (read-only, sealed, idempotent). Until then
// this is a no-op by design.
func (im *Importer) importAntigravity(context.Context) ([]Result, error) {
	return nil, nil
}

// antigravityImport is the seam ImportAll calls for the Antigravity source. It
// defaults to importAntigravity (the documented no-op); a test swaps it to cover
// ImportAll's propagation of an Antigravity error.
var antigravityImport = func(im *Importer, ctx context.Context) ([]Result, error) {
	return im.importAntigravity(ctx)
}

// --- shared ---

// storeSealed seals the value and upserts it under a deterministic ID.
//
// The ID is derived from provider+source so a second import updates the same
// row instead of creating a duplicate: idempotence comes from the stable key,
// not from a pre-read (which would race).
func (im *Importer) storeSealed(ctx context.Context, provider domain.ProviderID, label, sourceID, value string) (Result, error) {
	id := deterministicID(provider, sourceID)

	sealed, err := im.Sealer.Seal([]byte(value))
	if err != nil {
		return Result{}, domain.New(domain.CodeImportFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "seal failed"}),
		)
	}

	cred := contracts.Credential{
		ID:       id,
		Provider: provider,
		AuthMode: contracts.AuthAPIKey,
		Label:    label,
		Meta:     contracts.AccountMeta{DisplayName: label},
		Sealed:   []byte(sealed),
	}
	if err := im.Store.Upsert(ctx, cred); err != nil {
		return Result{}, err
	}

	return Result{
		Provider:     provider,
		CredentialID: id,
		Label:        label,
	}, nil
}

// deterministicID builds a stable CredentialID from provider+source. The hash
// is over non-secret inputs only, so the ID never leaks key material.
func deterministicID(provider domain.ProviderID, sourceID string) domain.CredentialID {
	sum := sha256.Sum256([]byte("import:" + string(provider) + ":" + sourceID))
	return domain.CredentialID(fmt.Sprintf("imp-%s-%s", provider, hex.EncodeToString(sum[:8])))
}

func (im *Importer) env(name string) string {
	if im.Env != nil {
		return im.Env[name]
	}
	return os.Getenv(name)
}

// home resolves the home directory. Explicit Home wins; then HOME from the
// injected environment (a systemd --user service may run with a different HOME
// than the interactive shell, and tests need it isolated); then the process
// user's home. Never guessing means the read-only source path is deterministic.
//
// Hermeticity (F5-1): when an environment snapshot was INJECTED (Env != nil),
// it is the complete picture — an absent HOME means "unknown", never a silent
// fall back to the host operator's real home. Only a nil Env (no snapshot) uses
// os.UserHomeDir. This stops a test that runs with an empty env from reading the
// host's real harness files.
func (im *Importer) home() string {
	if im.Home != "" {
		return im.Home
	}
	if im.Env != nil {
		if h := im.Env["HOME"]; h != "" {
			return h
		}
		return "."
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}

func importError(source string, err error) error {
	return domain.New(domain.CodeImportFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": source}),
	)
}
