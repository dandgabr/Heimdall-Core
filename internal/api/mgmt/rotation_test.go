package mgmt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dandgabr/heimdall-core/internal/api/middleware"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestRotationThrottleAllowsOncePerWindow is the F5-3 acceptance test: the first
// rotation succeeds, the second within the window is a typed 429 with
// Retry-After, and after the window elapses a rotation succeeds again.
func TestRotationThrottleAllowsOncePerWindow(t *testing.T) {
	now := time.Unix(0, 0)
	svc := &fakeService{rotate: TokenRotateView{Token: "tok-1", Path: "/tmp/t"}}
	h := New(middleware.ManagementAuth{Verify: func(p string) bool { return p == testToken }}, svc)
	h.rotation = NewRotationThrottle(5*time.Second, func() time.Time { return now })
	mux := http.NewServeMux()
	h.Register(mux)

	rotate := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/mgmt/token/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	first := rotate()
	if first.Code != http.StatusOK {
		t.Fatalf("first rotation = %d, want 200 (body %s)", first.Code, first.Body.String())
	}
	// Immediate second rotation is refused.
	second := rotate()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second rotation = %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
	if !strings.Contains(second.Body.String(), domain.CodeTokenRotateThrottled) {
		t.Fatalf("body = %q, want token.rotate_throttled", second.Body.String())
	}
	// Still refused one second before the window elapses.
	now = now.Add(4 * time.Second)
	if third := rotate(); third.Code != http.StatusTooManyRequests {
		t.Fatalf("pre-window rotation = %d, want 429", third.Code)
	}
	// Allowed once the window has fully elapsed.
	now = now.Add(2 * time.Second)
	if fourth := rotate(); fourth.Code != http.StatusOK {
		t.Fatalf("post-window rotation = %d, want 200 (body %s)", fourth.Code, fourth.Body.String())
	}
}

// TestRotationThrottleDefaultsToFiveSeconds proves the shipped window is the
// ADR's 5s.
func TestRotationThrottleDefaultsToFiveSeconds(t *testing.T) {
	th := NewRotationThrottle(0, nil)
	if th.window != DefaultRotationWindow {
		t.Fatalf("default window = %v, want %v", th.window, DefaultRotationWindow)
	}
	if DefaultRotationWindow != 5*time.Second {
		t.Fatalf("DefaultRotationWindow = %v, want 5s (ADR-SEC-06 §4.2)", DefaultRotationWindow)
	}
}

// TestRotationThrottleNilAllows proves a nil throttle is a no-op (the caller can
// disable rotation limiting without a branch).
func TestRotationThrottleNilAllows(t *testing.T) {
	var th *RotationThrottle
	if ok, _ := th.allow(); !ok {
		t.Fatal("nil throttle refused a rotation")
	}
}

// TestRotateThrottledDoesNotCallService proves the throttle refuses BEFORE the
// service is invoked, so a throttled request never rotates the token.
func TestRotateThrottledDoesNotCallService(t *testing.T) {
	calls := 0
	svc := &recordingRotateService{onRotate: func() { calls++ }}
	now := time.Unix(0, 0)
	h := New(middleware.ManagementAuth{Verify: func(p string) bool { return p == testToken }}, svc)
	h.rotation = NewRotationThrottle(time.Minute, func() time.Time { return now })
	mux := http.NewServeMux()
	h.Register(mux)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/mgmt/token/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}
	if calls != 1 {
		t.Fatalf("service invoked %d times, want 1 (throttle must short-circuit)", calls)
	}
}

// recordingRotateService counts RotateToken calls; every other method is inert.
type recordingRotateService struct {
	fakeService
	onRotate func()
}

func (r *recordingRotateService) RotateToken(context.Context) (TokenRotateView, error) {
	if r.onRotate != nil {
		r.onRotate()
	}
	return TokenRotateView{Token: "t", Path: "/p"}, nil
}

// TestWithRotationThrottleReplacesThrottle covers the composition-root setter:
// the handler uses the injected throttle (shared across Handler() instances).
func TestWithRotationThrottleReplacesThrottle(t *testing.T) {
	now := time.Unix(0, 0)
	th := NewRotationThrottle(time.Minute, func() time.Time { return now })
	h := New(middleware.ManagementAuth{Verify: func(p string) bool { return p == testToken }}, &fakeService{}).
		WithRotationThrottle(th)
	if h.rotation != th {
		t.Fatal("WithRotationThrottle did not replace the throttle")
	}
}

// TestRotateThrottleRetryAfterClampsSubSecond covers the secs<1 clamp: a
// cooldown under one second still emits Retry-After: 1.
func TestRotateThrottleRetryAfterClampsSubSecond(t *testing.T) {
	now := time.Unix(0, 0)
	svc := &fakeService{rotate: TokenRotateView{Token: "t", Path: "/p"}}
	h := New(middleware.ManagementAuth{Verify: func(p string) bool { return p == testToken }}, svc)
	h.rotation = NewRotationThrottle(time.Second, func() time.Time { return now })
	mux := http.NewServeMux()
	h.Register(mux)

	rotate := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/mgmt/token/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := rotate(); rec.Code != http.StatusOK {
		t.Fatalf("first = %d", rec.Code)
	}
	// Advance almost the whole window, leaving a sub-millisecond cooldown so the
	// secs<1 clamp (int(x.Seconds()+0.999) == 0) runs.
	now = now.Add(999999500 * time.Nanosecond)
	rec := rotate()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1 (clamped)", got)
	}
}
