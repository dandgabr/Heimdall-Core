package i18n

import "golang.org/x/text/language"

// Negotiate picks a catalog tag following the ADR-002 precedence:
// Accept-Language header, then the user's stored preference, then the default.
//
// The header wins because it reflects the request in flight; the stored
// preference is the tie-break for clients that send no header. Matching is done
// by golang.org/x/text/language, so "pt" resolves to the "pt-BR" catalog and
// "en-US" to "en" instead of failing on an exact string compare.
func (b *Bundle) Negotiate(acceptLanguage, preference string) string {
	if acceptLanguage != "" {
		if tag, ok := b.match(acceptLanguage, true); ok {
			return tag
		}
	}
	if preference != "" {
		if tag, ok := b.match(preference, false); ok {
			return tag
		}
	}
	return DefaultLanguage
}

// match resolves a raw language string against the loaded catalogs. accept=true
// parses a full Accept-Language list (with q-values); otherwise a single tag.
func (b *Bundle) match(raw string, accept bool) (string, bool) {
	b.mu.RLock()
	matcher := b.matcher
	keys := b.keys
	b.mu.RUnlock()

	var langs []language.Tag
	if accept {
		parsed, _, err := language.ParseAcceptLanguage(raw)
		if err != nil {
			return "", false
		}
		langs = parsed
	} else {
		tag, err := language.Parse(raw)
		if err != nil {
			return "", false
		}
		langs = []language.Tag{tag}
	}
	if len(langs) == 0 {
		return "", false
	}

	_, index, confidence := matcher.Match(langs...)
	if confidence == language.No || index < 0 || index >= len(keys) {
		return "", false
	}
	return keys[index], true
}
