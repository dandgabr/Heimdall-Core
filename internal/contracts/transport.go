package contracts

import (
	"net/http"
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file freezes the outbound-transport port of F2 (ADR-SEC-05). The
// Executor never builds an http.Client directly: ADR-SEC-05 makes creating a
// client without the egress policy an explicit violation, because SSRF, TLS,
// redirect and timeout controls must be applied in exactly one place and be
// injectable for tests. The concrete policy (denylist, dial-time hook,
// redirect revalidation) is F2.5 and is deliberately not implemented here.

// HTTPDoer is the minimal HTTP port the Executor depends on. *http.Client
// satisfies it, and so does a test double, which is the point: the Executor must
// be testable without a network.
type HTTPDoer interface {
	// Do sends req and returns the response. The caller closes the body.
	Do(req *http.Request) (*http.Response, error)
}

// EgressSpec describes one outbound destination and the per-phase budgets that
// apply to it. It is DATA, so the policy decides how to build the transport
// (dialer, TLS, redirect policy) without the caller ever touching those knobs.
type EgressSpec struct {
	// BaseURL is the upstream root, e.g. https://api.openai.com/v1. The policy
	// validates scheme and destination; it MUST reject a non-HTTPS URL unless
	// AllowLoopback is set for an explicit loopback IP literal.
	BaseURL string
	// AllowLoopback unlocks the loopback exception for a local runtime (e.g.
	// Ollama). It is only honoured for an explicit IP literal, never a
	// hostname. Default false.
	AllowLoopback bool
	// ResponseHeaderTimeout bounds time-to-first-token. This is the correct
	// place to bound a streaming call; http.Client.Timeout is forbidden because
	// it would abort long, legitimate generations.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds the gap between chunks on a live stream. Zero disables
	// the idle guard.
	IdleTimeout time.Duration
	// MaxResponseBytes bounds a buffered (non-stream) response. Zero means the
	// policy's default.
	MaxResponseBytes int64
	// FollowRedirects is false by default (ADR-SEC-05 §4). The inference and
	// auth clients must not follow a 30x, which would leak the Authorization
	// header to another host.
	FollowRedirects bool
	// MaxRedirects caps the hop count when FollowRedirects is true. Each hop is
	// revalidated against the full egress policy.
	MaxRedirects int
}

// Validate enforces the shape of the spec. It does NOT resolve or dial the
// destination: that is the policy's job at Client() time (and again at
// connect time, to defeat DNS rebinding). It exists so a misconfigured spec
// fails fast with a typed error instead of producing a client that surprises at
// request time.
func (s EgressSpec) Validate() error {
	if s.BaseURL == "" {
		return egressInvalid("base url is empty")
	}
	if s.ResponseHeaderTimeout < 0 {
		return egressInvalid("response header timeout is negative")
	}
	if s.IdleTimeout < 0 {
		return egressInvalid("idle timeout is negative")
	}
	if s.MaxResponseBytes < 0 {
		return egressInvalid("max response bytes is negative")
	}
	if s.FollowRedirects && s.MaxRedirects <= 0 {
		return egressInvalid("follow redirects requires a positive max redirects")
	}
	if !s.FollowRedirects && s.MaxRedirects != 0 {
		return egressInvalid("max redirects is set but follow redirects is off")
	}
	return nil
}

func egressInvalid(reason string) error {
	return domain.New(domain.CodeProviderInvalid,
		domain.WithHTTPStatus(http.StatusInternalServerError),
		domain.WithParams(map[string]string{"reason": "egress spec: " + reason}),
	)
}

// EgressPolicy is the ONLY sanctioned way an Executor obtains a transport. It
// applies the ADR-SEC-05 controls (HTTPS/TLS, SSRF denylist at dial time,
// redirect policy, timeout budgets) and returns a client bound to them.
//
// The concrete policy lives in internal/egress (F2.5). A family that needs a
// client MUST call this port; constructing http.Transport inline is forbidden by
// the ADR and is the exact bypass this interface exists to prevent.
type EgressPolicy interface {
	// Client validates spec and returns a policy-bound HTTP client.
	Client(spec EgressSpec) (HTTPDoer, error)
}
