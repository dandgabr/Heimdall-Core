package executors

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// jsonUnmarshal is a thin indirection so the executor does not import encoding
// json at more than one site.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// errIdleTimeout marks an SSE idle expiry. It is a plain sentinel (not a
// net.Error) because a net.Error would drag in the deprecated Temporary method;
// transportError classifies it explicitly as a retryable provider stall
// (upstream_timeout, provider scope), distinct from a caller-imposed context
// deadline, which is deliberately non-retryable.
var errIdleTimeout = errors.New("sse stream idle timeout")

func isCanceledOrDeadline(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// egressPolicyError extracts a typed egress-policy refusal from an arbitrary
// transport error and returns it unchanged when the code is one of the
// fail-closed destination/scheme decisions. net/http wraps a dial-time Control
// error in *url.Error, so the scan is done with errors.As rather than a direct
// type assertion. It returns nil when the failure is not a policy refusal.
func egressPolicyError(err error) *domain.DomainError {
	var de *domain.DomainError
	if !errors.As(err, &de) {
		return nil
	}
	switch de.Code {
	case domain.CodeUpstreamDestinationDenied, domain.CodeUpstreamInsecureURL:
		return de
	default:
		return nil
	}
}

// parseRetryAfter reads an HTTP Retry-After header (delta seconds or HTTP date)
// and returns the delay relative to now. It returns 0 when absent or invalid.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = stringsTrim(value)
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

func stringsTrim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
