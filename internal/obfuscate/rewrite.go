package obfuscate

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file holds the deterministic text primitives: rewriteText, copyBytes,
// trimSpace and the typed error. They are split from apply.go so the pure
// helpers are easy to unit-test in isolation.

// marshalJSON is a seam over json.Marshal. The values this package marshals
// (maps of json.RawMessage, strings, structs of strings) cannot actually fail to
// marshal, so the error branches would be unreachable without the seam. Routing
// every error-checked marshal through it lets a test inject a failure and prove
// the error path returns a typed error instead of a partial body — the same
// pattern the store uses for its marshal seam.
var marshalJSON = json.Marshal

// rewriteText applies the rules in order and reports whether anything changed.
// A literal rule replaces every occurrence (strings.ReplaceAll). A regex rule
// uses RE2; a pattern that does not compile is a programming error in the
// descriptor and is returned as an error rather than silently skipped, because a
// silently skipped rewrite would send client branding to a provider that flags
// it.
//
// RE2 flags: the reference connector's patterns carry /gim (case-insensitive,
// multiline). In Go RE2 there is no /flag suffix; the equivalent is an INLINE
// flag group at the start of the pattern, e.g. "(?im)^x-anthropic-billing-header:"
// — (?i) case-insensitive, (?m) ^/$ match at line boundaries. rewriteText does
// NOT add flags implicitly: the descriptor author encodes them, so the pattern's
// behaviour is visible in the data and a golden file is unambiguous. Global
// replacement is the default (ReplaceAllString); there is no non-global mode.
func rewriteText(text string, rules []contracts.PromptRewrite) (string, bool, error) {
	changed := false
	for _, rule := range rules {
		if rule.From == "" {
			continue
		}
		if rule.IsRegex {
			re, err := regexp.Compile(rule.From)
			if err != nil {
				return text, changed, obfuscationError("invalid prompt rewrite regex", err)
			}
			if re.MatchString(text) {
				next := re.ReplaceAllString(text, rule.To)
				if next != text {
					text = next
					changed = true
				}
			}
			continue
		}
		if strings.Contains(text, rule.From) {
			next := strings.ReplaceAll(text, rule.From, rule.To)
			if next != text {
				text = next
				changed = true
			}
		}
	}
	return text, changed, nil
}

// copyBytes returns a defensive copy so the caller cannot mutate this package's
// input through the returned slice, and the output never aliases caller memory.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// trimSpace trims ASCII whitespace from a raw JSON message.
func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isJSONNull reports whether raw is absent or the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	trimmed := trimSpace(raw)
	return len(trimmed) == 4 && string(trimmed) == "null"
}
