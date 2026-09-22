package i18n

import (
	"regexp"
	"strconv"
	"unicode"
)

// Redacted is the literal substituted for a secret. It carries no length hint,
// so the replacement cannot leak how long the key was.
const Redacted = "[REDACTED]"

// redactionRule is one ordered substitution. The capture group $1, when
// present, is preserved so the surrounding context (the header name, the query
// parameter name) survives while only the value is masked.
type redactionRule struct {
	name string
	re   *regexp.Regexp
	repl string
	// guard, when non-nil, decides whether a match is really a secret. It
	// receives the rule's last capture group (the value). This exists for the
	// space-separated form, where a field name followed by an ordinary word
	// ("token expirado") must NOT be masked.
	guard func(value string) bool
}

// secretFieldNames is the alternation of key/field names whose VALUE is a
// secret. It is shared by the query, JSON and assignment rules so a new field
// name only has to be added once.
const secretFieldNames = `api[_-]?key|key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|session|token|bearer|secret|client[_-]?secret|password|passwd|pwd|authorization|auth`

// tokenChars is the set of characters that can appear inside a credential
// (JWT/hex/base64url): dots, dashes, underscores, slashes, plus signs and
// trailing '=' padding.
const tokenChars = `[A-Za-z0-9._~+/=-]`

// minSecretRun is the shortest value the space-separated rule will consider.
// Short values ("ok", "yes") cannot be a credential and are too ambiguous to
// mask safely.
const minSecretRun = 6

// looksLikeCredential is the guard for the space-separated rule. Without it,
// ordinary prose ("token expirado", "session iniciada") matches the regex
// exactly as a credential does, and masking it would corrupt legitimate logs.
//
// A value is treated as a credential when it is long enough to be a secret AND
// carries at least one entropy signal a natural language word does not: a
// digit, a symbol from the token set, or mixed case. A pure lower-case word is
// only accepted when it is long enough (>= 16) that a dictionary word is
// unlikely and a random/lowercase-hex token is probable.
func looksLikeCredential(value string) bool {
	if len(value) < minSecretRun {
		return false
	}
	var hasDigit, hasSymbol, hasUpper, hasLower bool
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r > unicode.MaxASCII:
			// A non-ASCII letter (e.g. "inválido") is a word character, not a
			// credential symbol. Counting it as entropy would flag prose.
			hasLower = true
		default:
			hasSymbol = true
		}
	}
	if hasDigit || hasSymbol || (hasUpper && hasLower) {
		return true
	}
	// Pure lower-case (or pure upper-case) run: only credible at length.
	return len(value) >= 16
}

// redactionRules is the single source of truth for secret masking. Both the
// structured logger and the API error formatter call RedactString, so a pattern
// added here protects every sink at once (ADR-003: redator central único).
//
// Order matters:
//  1. Whole-value rules first (Cookie, Authorization) so a header value is
//     consumed as one unit regardless of its internal separators.
//  2. The "Bearer <token>" rule, which must run before the generic assignment
//     rule so the scheme word is not mistaken for a field name.
//  3. Key=value / "key":"value" structural rules.
//  4. Bare high-entropy token rules last.
//
// The earlier implementation failed on `Authorization: Bearer <long token>` and
// on `refresh_token=...` because the header rule used a class that stopped at
// separators inside long tokens, and no rule matched an assignment whose value
// contained no separator. Both are fixed below.
var redactionRules = []redactionRule{
	{
		// Cookie / Set-Cookie headers are entirely sensitive; consume the rest
		// of the line.
		name: "cookie-header",
		re:   regexp.MustCompile(`(?i)((?:set-)?cookie\s*:\s*)[^\r\n]*`),
		repl: "$1" + Redacted,
	},
	{
		// Authorization header: mask everything after the header name,
		// including the scheme and a long token with any separators. Runs
		// before the bearer rule so the whole value is treated as one secret.
		name: "authorization-header",
		re:   regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)[^\r\n]+`),
		repl: "$1" + Redacted,
	},
	{
		// "Bearer <token>" anywhere, e.g. inside a proxied request line. Allows
		// dots/dashes/slashes/plus/equals and is reasonably long.
		name: "bearer-scheme",
		re:   regexp.MustCompile(`(?i)\bbearer\s+` + tokenChars + `{6,}`),
		repl: "Bearer " + Redacted,
	},
	{
		// JSON field: "refresh_token":"abc" (value may be empty).
		name: "json-field",
		re:   regexp.MustCompile(`(?i)("(?:` + secretFieldNames + `)"\s*:\s*")[^"]*(")`),
		repl: "$1" + Redacted + "$2",
	},
	{
		// Query parameter: ?token=abc / &refresh_token=abc.
		name: "query-param",
		re:   regexp.MustCompile(`(?i)([?&](?:` + secretFieldNames + `)=)[^&\s"'#]*`),
		repl: "$1" + Redacted,
	},
	{
		// Assignment / header line without a scheme: refresh_token=abc,
		// session=abc, token: abc. Covers both the YAML/TOML line form (leading
		// whitespace) and inline forms with a single rule.
		name: "assignment-field",
		re:   regexp.MustCompile(`(?i)(\b(?:` + secretFieldNames + `)\s*[:=]\s*)` + tokenChars + `{1,}`),
		repl: "$1" + Redacted,
	},
	{
		// Space-separated field: "refresh_token abc123", "session xyz789".
		// The earlier rules only covered the '=' / ':' / quoted forms, so a
		// log line that prints the pair with a space leaked the value.
		//
		// The guard is what keeps this from masking prose: a field name
		// followed by an ordinary word ("token expirado", "session iniciada")
		// looks identical to the regex, so looksLikeCredential decides.
		name:  "space-separated-field",
		re:    regexp.MustCompile(`(?i)\b(` + secretFieldNames + `)\s+(` + tokenChars + `{` + strconv.Itoa(minSecretRun) + `,})\b`),
		repl:  "$1 " + Redacted,
		guard: looksLikeCredential,
	},
	{
		// OpenAI-style keys by prefix.
		name: "openai-key",
		re:   regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`),
		repl: Redacted,
	},
	{
		// A standalone long hex token (e.g. a 64-hex management token pasted
		// into a log line). Conservative by design: a security control should
		// over-redact rather than miss.
		name: "bare-hex-token",
		re:   regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`),
		repl: Redacted,
	},
}

// RedactString masks every known secret pattern in s. When nothing matches it
// returns s as-is; otherwise every rule runs in order.
func RedactString(s string) string {
	matched := false
	for _, rule := range redactionRules {
		if rule.re.MatchString(s) {
			matched = true
			break
		}
	}
	if !matched {
		return s
	}
	for _, rule := range redactionRules {
		s = applyRule(s, rule)
	}
	return s
}

// applyRule substitutes one rule. A unguarded rule uses ReplaceAllString with
// its template. A guarded rule (currently only space-separated-field) rebuilds
// the match from its capture groups, so the guard can veto a match; such a rule
// must use the "$1 <marker>" shape.
func applyRule(s string, rule redactionRule) string {
	if rule.guard == nil {
		return rule.re.ReplaceAllString(s, rule.repl)
	}
	return rule.re.ReplaceAllStringFunc(s, func(match string) string {
		sub := rule.re.FindStringSubmatch(match)
		if len(sub) < 3 || !rule.guard(sub[2]) {
			return match
		}
		return sub[1] + " " + Redacted
	})
}

// Redacter is the contracts.Redactor implementation backed by RedactString.
type Redacter struct{}

// Redact satisfies contracts.Redactor.
func (Redacter) Redact(s string) string { return RedactString(s) }

// Compile-time assertion that Redacter is usable as a contract.
var _ interface{ Redact(string) string } = Redacter{}
