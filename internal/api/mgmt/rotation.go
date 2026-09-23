package mgmt

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// DefaultRotationWindow is the minimum interval between two management-token
// rotations, per ADR-SEC-06 §4.2 ("no máximo 1 rotação a cada 5 segundos"). It
// bounds a compromised or buggy operator surface from churning the token,
// invalidating every client between rotations.
const DefaultRotationWindow = 5 * time.Second

// RotationThrottle enforces at most ONE management-token rotation per window.
// It is deliberately separate from the LoginThrottle (which throttles FAILED
// authentication per IP): this limits the SUCCESS path's frequency, per the ADR.
//
// It is concurrency-safe and clock-injectable so a test proves the window
// without waiting 5 seconds. A nil *RotationThrottle allows every rotation, so a
// caller can attach it conditionally without a second check.
type RotationThrottle struct {
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	last time.Time
	// started is false until the first rotation records a timestamp, so the
	// first call is always allowed regardless of the zero time.
	started bool
}

// NewRotationThrottle builds a throttle. A window <= 0 falls back to
// DefaultRotationWindow; a nil clock falls back to time.Now.
func NewRotationThrottle(window time.Duration, now func() time.Time) *RotationThrottle {
	if window <= 0 {
		window = DefaultRotationWindow
	}
	if now == nil {
		now = time.Now
	}
	return &RotationThrottle{window: window, now: now}
}

// allow reports whether a rotation may proceed now, and if not, how long until
// the next one is permitted. On success it records the instant.
func (t *RotationThrottle) allow() (bool, time.Duration) {
	if t == nil {
		return true, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if t.started {
		if elapsed := now.Sub(t.last); elapsed < t.window {
			return false, t.window - elapsed
		}
	}
	t.last = now
	t.started = true
	return true, 0
}

// rotateToken handles POST /api/mgmt/token/rotate, refusing a rotation inside
// the throttle window with a typed 429 (token.rotate_throttled + Retry-After).
func (h *Handler) rotateToken(w http.ResponseWriter, r *http.Request) {
	if ok, retryAfter := h.rotation.allow(); !ok {
		secs := int(retryAfter.Seconds() + 0.999)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, r, domain.New(domain.CodeTokenRotateThrottled,
			domain.WithHTTPStatus(http.StatusTooManyRequests),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"retry_after": strconv.Itoa(secs)})))
		return
	}
	v, err := h.svc.RotateToken(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	// A rotated token is a one-time secret: never cached, never reused.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}
