// Package i18n owns the message catalogs and the two cross-cutting string
// concerns that must never diverge: localisation of error codes and redaction
// of secrets.
//
// It is a leaf package: besides the standard library it imports only
// golang.org/x/text and domain, so logger, API and formatter can all share one
// implementation without an import cycle.
package i18n

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/language"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// DefaultLanguage is the fallback every unresolved negotiation lands on.
const DefaultLanguage = "en"

//go:embed catalogs/*.json
var catalogsFS embed.FS

// Catalog maps a message code to a template with {named} placeholders.
type Catalog map[string]string

// Bundle is the immutable, concurrency-safe set of loaded catalogs.
type Bundle struct {
	mu       sync.RWMutex
	catalogs map[string]Catalog
	tags     []language.Tag
	keys     []string
	matcher  language.Matcher
}

// defaultCatalogFS is the catalog source New reads. It is a package variable so
// a test can inject a broken source and exercise New's (and MustNew's) failure
// path; production always uses the embedded FS.
var defaultCatalogFS fs.FS = catalogsFS

// New loads every catalog under catalogs/ and builds the language matcher.
func New() (*Bundle, error) {
	return loadFrom(defaultCatalogFS)
}

// loadFrom is New with an injectable catalog source. Production passes the
// embedded FS; a test passes an fs.FS so the read/parse/missing-default branches
// are reachable without shipping a broken catalog.
func loadFrom(fsys fs.FS) (*Bundle, error) {
	entries, err := fs.ReadDir(fsys, "catalogs")
	if err != nil {
		return nil, fmt.Errorf("i18n: read embedded catalogs: %w", err)
	}

	b := &Bundle{catalogs: make(map[string]Catalog, len(entries))}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join("catalogs", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("i18n: read %s: %w", e.Name(), err)
		}
		var catalog Catalog
		if err := json.Unmarshal(raw, &catalog); err != nil {
			return nil, fmt.Errorf("i18n: parse %s: %w", e.Name(), err)
		}
		tag := strings.TrimSuffix(e.Name(), ".json")
		b.catalogs[tag] = catalog
		b.keys = append(b.keys, tag)
	}

	if len(b.catalogs) == 0 {
		return nil, fmt.Errorf("i18n: no catalogs embedded")
	}
	sort.Strings(b.keys)

	b.tags = make([]language.Tag, 0, len(b.keys))
	for _, k := range b.keys {
		b.tags = append(b.tags, language.MustParse(k))
	}
	b.matcher = language.NewMatcher(b.tags)

	if _, ok := b.catalogs[DefaultLanguage]; !ok {
		return nil, fmt.Errorf("i18n: default catalog %q is missing", DefaultLanguage)
	}
	return b, nil
}

// MustNew is New for package-level initialisation where a failure is fatal.
func MustNew() *Bundle {
	b, err := New()
	if err != nil {
		panic(err)
	}
	return b
}

// Languages returns the available catalog tags, sorted.
func (b *Bundle) Languages() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, len(b.keys))
	copy(out, b.keys)
	return out
}

var placeholderRe = regexp.MustCompile(`\{([A-Za-z0-9_.]+)\}`)

// Format resolves code in tag and substitutes named placeholders. An unknown
// code falls back to DefaultLanguage and then to the code itself, so a caller
// always receives a non-empty string; an absent placeholder is left literal so
// the gap is visible rather than silently blank.
func (b *Bundle) Format(tag, code string, params map[string]string) string {
	b.mu.RLock()
	template, ok := b.catalogs[tag][code]
	if !ok {
		template, ok = b.catalogs[DefaultLanguage][code]
	}
	b.mu.RUnlock()
	if !ok {
		return code
	}
	if len(params) == 0 {
		return template
	}
	return placeholderRe.ReplaceAllStringFunc(template, func(match string) string {
		name := match[1 : len(match)-1]
		if v, ok := params[name]; ok {
			return v
		}
		return match
	})
}

// FormatError localises a DomainError. When lang is empty the default is used.
func (b *Bundle) FormatError(lang string, e *domain.DomainError) string {
	if e == nil {
		return ""
	}
	return b.FormatDomainError(e, lang)
}

// FormatDomainError turns an arbitrary error into an operator-facing message:
// the i18n code is resolved in the negotiated language and its named params are
// interpolated. It is the single rendering path for every user-facing boundary
// (CLI stderr, and later the GUI), so the raw code never reaches a human without
// its corrective detail (e.g. the failing path and mode).
//
// Security and robustness:
//   - params are passed through the central redactor BEFORE interpolation, and
//     the rendered message is redacted again, so a credential embedded in a
//     param or template cannot leak;
//   - a non-DomainError is rendered from its (redacted) text rather than
//     dropped;
//   - an unknown code, or a known code with no params for a template that
//     needs them, falls back to the code itself instead of an empty or
//     half-rendered string.
func (b *Bundle) FormatDomainError(err error, lang string) string {
	if err == nil {
		return ""
	}
	if lang == "" {
		lang = DefaultLanguage
	}

	var de *domain.DomainError
	if !errors.As(err, &de) || de == nil {
		return RedactString(err.Error())
	}

	// Redact param values first: they can carry a path or a stray credential.
	params := make(map[string]string, len(de.Params))
	for k, v := range de.Params {
		params[k] = RedactString(v)
	}

	message := b.Format(lang, de.Code, params)
	if message == "" {
		// Unknown code and no default entry: surface the code, never blank.
		return de.Code
	}
	// If the TEMPLATE needs a placeholder the caller did not supply, fall back
	// to the stable code rather than emit a sentence with a literal "{name}"
	// (the bug class this guards against). The check is on the template's own
	// placeholders, not the rendered text, so a param VALUE that legitimately
	// contains braces (e.g. a JSON reason) does not trigger a false fallback.
	if missingPlaceholder(b.template(de.Code, lang), params) {
		return de.Code
	}
	return RedactString(message)
}

// template returns the catalog entry for code in tag, falling back to the
// default language; it returns "" when the code is unknown.
func (b *Bundle) template(code, tag string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if t, ok := b.catalogs[tag][code]; ok {
		return t
	}
	return b.catalogs[DefaultLanguage][code]
}

// missingPlaceholder reports whether template contains a {name} placeholder that
// params does not supply.
func missingPlaceholder(template string, params map[string]string) bool {
	for _, m := range placeholderRe.FindAllStringSubmatch(template, -1) {
		if _, ok := params[m[1]]; !ok {
			return true
		}
	}
	return false
}
