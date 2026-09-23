package security

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/egress"
)

// SSRFGuard validates every URL carried in the request body against the
// ADR-SEC-05 denylist BEFORE the request is dispatched — a client-supplied
// media URL must never aim the router's egress at loopback, link-local, cloud
// metadata, private ranges or their IPv4-mapped IPv6 spellings. The decision
// reuses the single egress authority (egress.DeniedIP); it does not duplicate
// the ranges.
//
// This gate is the request-level containment of phase 1. It does NOT replace
// the dial-time hook: a hostname this gate cannot resolve is still subject to
// the Control hook when (and if) the executor connects — this gate only makes
// the body an explicit, early deny surface. Denials carry the refused HOST
// only; the path, query and anything else in the URL are never echoed into
// params, Meta or logs (query strings can embed signed credentials,
// ADR-SEC-05 §8).
//
// Scheme policy: body-supplied URLs must be https. Cleartext http is the
// operator's decision for CONFIGURED upstreams (the loopback exception of
// ADR-SEC-05 §2 belongs to the provider registry, never to client payload).
//
// FailurePolicy is FailClosed: an unparseable URL is a denial, not a pass.
type SSRFGuard struct{}

// Compile-time assertions.
var (
	_ contracts.Gate         = (*SSRFGuard)(nil)
	_ contracts.GateDeclarer = (*SSRFGuard)(nil)
	_ contracts.BodyConsumer = (*SSRFGuard)(nil)
)

// NewSSRFGuard builds the gate.
func NewSSRFGuard() *SSRFGuard { return &SSRFGuard{} }

// ID implements contracts.Gate.
func (g *SSRFGuard) ID() string { return IDSSRFGuard }

// Stages implements contracts.Gate: containment runs pre-request only, before
// any fetch the dispatch could trigger.
func (g *SSRFGuard) Stages() contracts.GateStageSet {
	return contracts.StageSet(contracts.StagePreRequest)
}

// RequiredCaps implements contracts.Gate.
func (g *SSRFGuard) RequiredCaps() contracts.GateCaps { return 0 }

// FailurePolicy implements contracts.Gate.
func (g *SSRFGuard) FailurePolicy() contracts.FailurePolicy { return contracts.FailClosed }

// NeedsBody implements contracts.BodyConsumer.
func (g *SSRFGuard) NeedsBody() bool { return true }

// Declare implements contracts.GateDeclarer. The guard neither reads a field
// another gate writes nor writes one — its verdict is terminal, not data — so
// the graph leaves it in the containment phase with the other zero-edge gates,
// ordered by ID (ADR-SEC-04 §1.1).
func (g *SSRFGuard) Declare() contracts.Declared {
	return contracts.Declared{Stages: g.Stages()}
}

// urlCandidateRe extracts http(s) URLs from a decoded string value. The scan
// is content-superset on purpose: a URL anywhere in a string value is a
// destination the model could be steered to fetch.
var urlCandidateRe = regexp.MustCompile(`https?://[^\s"'<>\\]+`)

// deniedReason labels WHY a URL was refused, for Meta diagnostics only.
type deniedReason string

const (
	deniedScheme   deniedReason = "scheme"
	deniedParse    deniedReason = "unparseable"
	deniedUserInfo deniedReason = "userinfo"
	deniedHost     deniedReason = "host"
)

// PreRequest implements contracts.Gate. The pass never rewrites the body: a
// clean request comes back byte-identical and continues; a refusal stops the
// chain with a 400 synthetic.
func (g *SSRFGuard) PreRequest(_ context.Context, in contracts.GateInput) (contracts.Decision, error) {
	if len(in.Body) == 0 {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	var host string
	var reason deniedReason
	denied := false
	_, _, err := mapJSONStrings(in.Body, func(s string) string {
		if denied {
			return s // first denial wins; keep the scan cheap
		}
		for _, raw := range urlCandidateRe.FindAllString(s, -1) {
			if h, r, d := urlDenied(trimURLPunctuation(raw)); d {
				host, reason, denied = h, r, true
				return s
			}
		}
		return s
	})
	if err != nil {
		return contracts.Decision{}, err
	}
	if !denied {
		return contracts.Decision{Kind: contracts.DecisionContinue}, nil
	}
	setMeta(in.Meta, IDSSRFGuard+".denied", host)
	setMeta(in.Meta, IDSSRFGuard+".reason", string(reason))
	return blockWith(domain.CodeSecurityDestinationDenied,
		map[string]string{"host": host},
		http.StatusBadRequest), nil
}

// trimURLPunctuation strips the trailing prose punctuation a sentence can
// leave on a URL. The closing bracket is NOT punctuation here: an IPv6 literal
// ends with ].
func trimURLPunctuation(raw string) string {
	return strings.TrimRight(raw, `.,;:!?"'`)
}

// urlDenied decides one URL candidate. host is reported only for denials and
// is the hostname/IP literal alone. A hostname the gate cannot classify is
// ALLOWED here on purpose: the dial-time Control hook is the authority on
// resolved addresses (DNS rebinding cannot be decided from the body).
func urlDenied(raw string) (host string, reason deniedReason, denied bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", deniedParse, true
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return sanitizeHost(u), deniedScheme, true
	}
	if u.User != nil {
		return sanitizeHost(u), deniedUserInfo, true
	}
	h := u.Hostname()
	if h == "" {
		return "", deniedHost, true
	}
	// Trim the FQDN trailing dot so "metadata.google.internal." cannot slip
	// past the exact-name rules.
	h = strings.TrimSuffix(h, ".")
	if strings.EqualFold(h, "localhost") || strings.EqualFold(h, "metadata.google.internal") {
		return h, deniedHost, true
	}
	if ip, perr := netip.ParseAddr(h); perr == nil {
		if egress.DeniedIP(ip, false) {
			// Report the CANONICAL (unmapped) form, so ::ffff:169.254.169.254
			// and 169.254.169.254 are the same diagnostic.
			return ip.Unmap().String(), deniedHost, true
		}
		return "", "", false
	}
	return "", "", false
}

// sanitizeHost returns the bare hostname for diagnostics. It strips path,
// query, port and any userinfo, so nothing client-controlled beyond the host
// label is echoed back. u comes from a successful url.Parse and is non-nil.
func sanitizeHost(u *url.URL) string {
	return u.Hostname()
}

// OnResponseChunk implements contracts.Gate: no post-commit action.
func (g *SSRFGuard) OnResponseChunk(context.Context, contracts.ChunkInput) (contracts.ChunkDecision, error) {
	return contracts.ChunkDecision{Kind: contracts.ChunkPassThrough}, nil
}

// PostResponse implements contracts.Gate: nothing to observe.
func (g *SSRFGuard) PostResponse(context.Context, contracts.GateInput) error { return nil }

// Close implements contracts.Gate.
func (g *SSRFGuard) Close() error { return nil }
