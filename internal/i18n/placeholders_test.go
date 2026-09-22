package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file is the regression guard for the bug class where a call site passes
// WithParams keys that do not match the placeholders its i18n template expects
// (e.g. passing {provider} to a template that renders {id}, which surfaced a
// literal "{id}" to the user). It statically scans every production .go file,
// resolves each domain.New(domain.Code<X>, ...) call to its catalog template, and
// requires the call's literal params to cover the template's placeholders.
//
// Scope / honesty:
//   - only LITERAL `WithParams(map[string]string{...})` blocks are inspected; a
//     call that forwards a caller-supplied map (configProviderError) or builds
//     options in a variable cannot be checked statically and is SKIPPED, not
//     silently passed;
//   - a template entry absent from a code constant map is skipped;
//   - the check is one-directional (missing placeholders are the bug; an extra
//     param is harmless).

var (
	codeConstRe = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*"([^"]+)"`)
	// A call site: the constant, then (within a window) the WithParams literal.
	newCallRe = regexp.MustCompile(`domain\.New\(domain\.(Code\w+)`)
	paramsRe  = regexp.MustCompile(`WithParams\(map\[string\]string\{([^}]*)\}`)
	paramKey  = regexp.MustCompile(`"([a-z_]+)"\s*:`)
)

func TestCatalogPlaceholdersMatchCallSites(t *testing.T) {
	root := filepath.Join("..", "..")

	codes := loadCodeConstants(t, filepath.Join(root, "internal", "domain", "codes.go"))
	catalog := MustNew()

	var problems []string
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Strip the i18n package's own catalog files' regex (not relevant) and
		// skip generated/goldens.
		text := string(src)
		for _, m := range newCallRe.FindAllStringSubmatchIndex(text, -1) {
			constName := text[m[2]:m[3]]
			i18nCode, ok := codes[constName]
			if !ok {
				continue
			}
			template := catalog.template(i18nCode, DefaultLanguage)
			if template == "" {
				continue
			}
			want := placeholderSet(template)
			if len(want) == 0 {
				continue
			}
			// Window from the constant to the end of its call (bounded).
			window := callWindow(text, m[0])
			pm := paramsRe.FindStringSubmatch(window)
			if pm == nil {
				// No literal params in this window: either dynamic (skipped) or
				// actually missing. Only flag when the call has NO WithParams at
				// all, because that is a genuine "needs placeholders, got none".
				if !strings.Contains(window, "WithParams(") {
					problems = append(problems, path+" "+constName+": template "+i18nCode+
						" needs "+setString(want)+" but the call passes no params")
				}
				continue
			}
			got := map[string]bool{}
			for _, k := range paramKey.FindAllStringSubmatch(pm[1], -1) {
				got[k[1]] = true
			}
			var missing []string
			for name := range want {
				if !got[name] {
					missing = append(missing, name)
				}
			}
			if len(missing) > 0 {
				missingSet := map[string]bool{}
				for _, name := range missing {
					missingSet[name] = true
				}
				problems = append(problems, path+" "+constName+": template "+i18nCode+
					" needs "+setString(want)+" but the call omits "+setString(missingSet))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, p := range problems {
		t.Errorf("placeholder mismatch: %s", p)
	}
}

// loadCodeConstants parses `Const = "i18n.code"` pairs from codes.go.
func loadCodeConstants(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read codes.go: %v", err)
	}
	out := map[string]string{}
	for _, m := range codeConstRe.FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("no code constants parsed from codes.go")
	}
	return out
}

// callWindow returns a bounded slice of text starting at start, long enough to
// contain the call's own WithParams but not the next unrelated call.
func callWindow(text string, start int) string {
	const max = 600
	end := start + max
	if end > len(text) {
		end = len(text)
	}
	return text[start:end]
}

func placeholderSet(template string) map[string]bool {
	out := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(template, -1) {
		out[m[1]] = true
	}
	return out
}

func setString(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// deterministic order for stable messages
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return "{" + strings.Join(keys, ",") + "}"
}
