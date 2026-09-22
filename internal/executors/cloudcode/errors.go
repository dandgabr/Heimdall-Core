package cloudcode

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// retryResetPattern matches the Antigravity quota message form
// "... reset after 2h7m23s" (also "1h30m", "45m", "30s"). The reference
// connector derives the RetryAfter from this when no header is present.
var retryResetPattern = regexp.MustCompile(`(?i)reset after (?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?`)

// transientPatterns are the provider messages that mark a retryable outage even
// when the status is not a 5xx (capacity/high-traffic/timeouts).
var transientPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)high\s+traffic`),
	regexp.MustCompile(`(?i)capacity`),
	regexp.MustCompile(`(?i)temporarily\s+unavailable`),
	regexp.MustCompile(`(?i)timeout`),
}

// mapHTTPError maps a CloudCode non-2xx response to the ADR-0002 taxonomy.
//   - 429: credential-scoped, retryable, with RetryAfter derived from the
//     headers or the "reset after ..." message.
//   - 5xx or a transient message: provider-scoped, retryable.
//   - any other 4xx: request-scoped, not retryable.
//
// The upstream body is never echoed: only the derived retry delay and status.
func mapHTTPError(status int, header http.Header, body []byte, now time.Time) *domain.DomainError {
	message := string(body)
	retryAfter := parseRetryAfter(header, message, now)

	switch {
	case status == http.StatusTooManyRequests:
		opts := []domain.Option{
			domain.WithHTTPStatus(http.StatusBadGateway),
			domain.Retry(),
			domain.WithScope(domain.ScopeCredential),
			domain.WithParams(map[string]string{"status": strconv.Itoa(status)}),
		}
		if retryAfter > 0 {
			opts = append(opts, domain.WithRetryAfter(retryAfter))
		}
		return domain.New(domain.CodeUpstreamUnavailable, opts...)

	case status >= 500 || isTransient(message):
		return domain.New(domain.CodeUpstreamUnavailable,
			domain.WithHTTPStatus(http.StatusBadGateway),
			domain.Retry(),
			domain.WithScope(domain.ScopeProvider),
			domain.WithParams(map[string]string{"status": strconv.Itoa(status)}),
		)

	default:
		return domain.New(domain.CodeBadUpstreamResponse,
			domain.WithHTTPStatus(http.StatusBadRequest),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"status": strconv.Itoa(status)}),
		)
	}
}

// isTransient reports whether the message names a retryable provider condition.
func isTransient(message string) bool {
	for _, p := range transientPatterns {
		if p.MatchString(message) {
			return true
		}
	}
	return false
}

// parseRetryAfter derives a retry delay from the headers (Retry-After,
// x-ratelimit-reset-after seconds, x-ratelimit-reset unix seconds) or, failing
// those, the Antigravity "reset after ..." message. It returns 0 when unknown.
func parseRetryAfter(header http.Header, message string, now time.Time) time.Duration {
	if header != nil {
		if d := parseRetryAfterHeader(header.Get("Retry-After"), now); d > 0 {
			return d
		}
		if d := parseSecondsHeader(header.Get("x-ratelimit-reset-after")); d > 0 {
			return d
		}
		if d := parseUnixResetHeader(header.Get("x-ratelimit-reset"), now); d > 0 {
			return d
		}
	}
	return parseResetFromMessage(message)
}

// parseRetryAfterHeader parses the RFC Retry-After header in either delta-seconds
// or HTTP-date form.
func parseRetryAfterHeader(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := when.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// parseSecondsHeader parses a positive integer-seconds header.
func parseSecondsHeader(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// parseUnixResetHeader parses an absolute unix-seconds reset timestamp.
func parseUnixResetHeader(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	if d := time.Unix(seconds, 0).Sub(now); d > 0 {
		return d
	}
	return 0
}

// parseResetFromMessage parses the "reset after <h>h<m>m<s>s" form.
func parseResetFromMessage(message string) time.Duration {
	m := retryResetPattern.FindStringSubmatch(message)
	if m == nil {
		return 0
	}
	var total time.Duration
	if m[1] != "" {
		if h, err := strconv.Atoi(m[1]); err == nil {
			total += time.Duration(h) * time.Hour
		}
	}
	if m[2] != "" {
		if mins, err := strconv.Atoi(m[2]); err == nil {
			total += time.Duration(mins) * time.Minute
		}
	}
	if m[3] != "" {
		if s, err := strconv.Atoi(m[3]); err == nil {
			total += time.Duration(s) * time.Second
		}
	}
	return total
}
