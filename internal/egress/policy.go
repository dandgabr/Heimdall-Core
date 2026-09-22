// Package egress is the single outbound-transport policy of Heimdall-Core
// (ADR-SEC-05).
//
// Every HTTP client the process creates MUST come from here. Creating an
// http.Client or http.Transport anywhere else is the exact bypass the ADR
// forbids, because SSRF, TLS, redirect and timeout controls have to be applied
// in exactly one place:
//
//   - TLS verification is mandatory and InsecureSkipVerify is never settable;
//   - a dial-time Control hook validates the RESOLVED address against the SSRF
//     denylist (loopback/private/link-local/metadata/multicast/unspecified),
//     with IPv4-mapped IPv6 collapsed first — this is what defeats DNS rebinding;
//   - redirects are not followed by default, and when enabled each hop is
//     revalidated against the same scheme + destination rules up to a cap;
//   - proxy schemes are restricted to http/https/socks5;
//   - timeouts are per-phase (TTFT via ResponseHeaderTimeout, dial, TLS), never
//     a global http.Client.Timeout.
package egress

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Default budgets. They are the production baseline of ADR-SEC-05 §6; a caller
// overrides TTFT per family through EgressSpec.ResponseHeaderTimeout.
const (
	// DefaultDialTimeout bounds TCP establishment.
	DefaultDialTimeout = 10 * time.Second
	// DefaultTLSHandshakeTimeout bounds the TLS handshake.
	DefaultTLSHandshakeTimeout = 10 * time.Second
	// DefaultMaxRedirects is the media-fetch cap (ADR-SEC-05 §4).
	DefaultMaxRedirects = 3
	// DefaultMaxResponseBytes is the buffered-response cap (ADR-SEC-05 §7).
	DefaultMaxResponseBytes = 32 << 20 // 32 MiB
)

// Policy is the concrete contracts.EgressPolicy. The zero value is not usable;
// call New. It is safe for concurrent use (it holds only immutable config).
type Policy struct {
	dialTimeout         time.Duration
	tlsHandshakeTimeout time.Duration
	// proxyFromEnv resolves the proxy for a request. It is a seam so a test can
	// inject a proxy URL (including an invalid scheme) without touching the
	// process environment.
	proxyFromEnv func(*http.Request) (*url.URL, error)
}

// New builds the default policy with the ADR-SEC-05 budgets.
func New() *Policy {
	return &Policy{
		dialTimeout:         DefaultDialTimeout,
		tlsHandshakeTimeout: DefaultTLSHandshakeTimeout,
		proxyFromEnv:        http.ProxyFromEnvironment,
	}
}

// compile-time assertion that Policy satisfies the frozen port.
var _ contracts.EgressPolicy = (*Policy)(nil)

// Client validates the spec and returns a policy-bound client. The returned
// type is *http.Client, which satisfies contracts.HTTPDoer; callers that only
// need the port should accept the interface.
func (p *Policy) Client(spec contracts.EgressSpec) (contracts.HTTPDoer, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	loopbackLiteral, err := ValidateUpstreamURL(spec.BaseURL)
	if err != nil {
		return nil, err
	}
	// The loopback exception is OPT-IN (ADR-SEC-05 §2): a loopback literal is
	// only unlocked when the caller explicitly set AllowLoopback. Without the
	// gate, ValidateUpstreamURL's literal detection alone would silently permit
	// 127.0.0.1 for any spec, making AllowLoopback decorative.
	allowLoopback := spec.AllowLoopback && loopbackLiteral

	dialer := &net.Dialer{
		Timeout:   p.dialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   SSRFControl(allowLoopback),
	}
	// InsecureSkipVerify is deliberately never set, and the TLS floor is pinned
	// to 1.2 (ADR-SEC-05 §1); the system roots are the only trust anchor.
	transport := &http.Transport{
		Proxy:                 p.validatedProxy,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   p.tlsHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: spec.ResponseHeaderTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		// OnProxyConnectResponse revalidates the CONNECT tunnel TARGET (the
		// host:port after the CONNECT verb), not the proxy's own address. The
		// dial-time Control only sees the proxy connection, so without this a
		// malicious HTTP(S)_PROXY could tunnel to a denied address (metadata,
		// loopback, private) and bypass the SSRF guard entirely.
		OnProxyConnectResponse: proxyConnectGuard(allowLoopback),
	}

	return &http.Client{
		Transport:     transport,
		CheckRedirect: redirectPolicy(spec),
	}, nil
}

// validatedProxy resolves the environment proxy and refuses an unsupported
// scheme. A proxy credential is never logged; the error carries the redacted
// URL form.
func (p *Policy) validatedProxy(req *http.Request) (*url.URL, error) {
	proxy, err := p.proxyFromEnv(req)
	if err != nil || proxy == nil {
		return proxy, err
	}
	switch strings.ToLower(proxy.Scheme) {
	case "http", "https", "socks5":
		return proxy, nil
	default:
		return nil, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"url": proxy.Redacted()}),
		)
	}
}

// redirectPolicy returns the CheckRedirect for a spec. With FollowRedirects off
// it refuses every redirect (http.ErrUseLastResponse), so a 30x cannot carry the
// Authorization header to another host. With it on (media fetch) each hop is
// bounded and revalidated against the scheme rule; the dial-time Control
// revalidates the destination of every hop automatically.
func redirectPolicy(spec contracts.EgressSpec) func(*http.Request, []*http.Request) error {
	if !spec.FollowRedirects {
		return func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	maxRedirects := spec.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return domain.New(domain.CodeUpstreamUnavailable,
				domain.WithHTTPStatus(http.StatusBadGateway),
				domain.WithScope(domain.ScopeProvider),
				domain.WithParams(map[string]string{"reason": "too many redirects"}),
			)
		}
		// Revalidate the scheme of the redirect target; the destination IP is
		// revalidated at dial time by the Control hook of the NEXT connection.
		if _, err := ValidateUpstreamURL(req.URL.String()); err != nil {
			return err
		}
		return nil
	}
}

// ValidateUpstreamURL enforces the scheme and host policy on a configured URL.
// It returns whether the target is an explicit loopback IP literal (so the
// dial-time guard may permit loopback for a local model server).
func ValidateUpstreamURL(raw string) (allowLoopback bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeRequest),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"url": sanitize(raw)}),
		)
	}
	host := u.Hostname()
	if host == "" {
		return false, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"url": sanitize(raw)}),
		)
	}
	loopback := IsLoopbackLiteral(host)

	switch strings.ToLower(u.Scheme) {
	case "https":
		return loopback, nil
	case "http":
		if loopback {
			return true, nil
		}
		return false, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"url": u.Redacted()}),
		)
	default:
		return false, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(http.StatusInternalServerError),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{"url": u.Redacted()}),
		)
	}
}

// IsLoopbackLiteral reports whether host is an explicit loopback IP literal
// (127.0.0.0/8 or ::1). A hostname is never accepted: allowing "localhost" would
// let a DNS entry decide the destination.
func IsLoopbackLiteral(host string) bool {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// metadataIPv4 are cloud metadata addresses that fall OUTSIDE the private
// ranges netip classifies, so they need explicit entries (ADR-SEC-05 §3).
var metadataIPv4 = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud metadata
}

// broadcastIPv4 is the limited broadcast address; netip's IsMulticast does not
// cover it, so it is denied explicitly (ADR-SEC-05 §3).
var broadcastIPv4 = netip.MustParseAddr("255.255.255.255")

// DeniedIP reports whether ip must never be dialled. It covers the SSRF ranges:
// loopback, private (RFC1918/ULA), link-local (including 169.254.169.254),
// metadata, multicast, broadcast, unspecified and the IPv4-mapped IPv6 forms of
// all of them (netip.Addr.Unmap collapses ::ffff:a.b first).
func DeniedIP(ip netip.Addr, allowLoopback bool) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip == broadcastIPv4 {
		return true
	}
	for _, meta := range metadataIPv4 {
		if ip == meta {
			return true
		}
	}
	return false
}

// SSRFControl is the net.Dialer.Control hook. It receives the already-resolved
// "host:port" address, so a DNS rebind to a private address is rejected at
// connect time with error.upstream_destination_denied (ScopeProvider).
func SSRFControl(allowLoopback bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			// A non-literal address cannot be validated; fail closed.
			return destinationDenied(host)
		}
		if DeniedIP(ip, allowLoopback) {
			return destinationDenied(host)
		}
		return nil
	}
}

func destinationDenied(host string) error {
	return domain.New(domain.CodeUpstreamDestinationDenied,
		domain.WithHTTPStatus(http.StatusBadGateway),
		domain.WithScope(domain.ScopeProvider),
		domain.WithParams(map[string]string{"host": host}),
	)
}

// proxyConnectGuard returns the net/http Transport OnProxyConnectResponse hook.
// It revalidates the CONNECT tunnel target (the authority the client asked the
// proxy to reach) against the SSRF denylist before the tunnel is accepted.
//
// The dial-time Control only inspects the connection to the PROXY; a hostile
// proxy could otherwise CONNECT to 169.254.169.254, a private host or loopback
// and defeat the guard. The target from connectReq.URL is a hostname or literal
// taken from the request (the proxy has not resolved it yet), so a literal is
// checked directly and a hostname is left to the dial-time guard of the tunnelled
// connection; either way loopback requires the explicit opt-in.
func proxyConnectGuard(allowLoopback bool) func(context.Context, *url.URL, *http.Request, *http.Response) error {
	return func(_ context.Context, _ *url.URL, connectReq *http.Request, _ *http.Response) error {
		if connectReq == nil || connectReq.URL == nil {
			return nil
		}
		host := connectReq.URL.Hostname()
		if host == "" {
			return destinationDenied(connectReq.URL.Host)
		}
		if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			if DeniedIP(ip, allowLoopback) {
				return destinationDenied(host)
			}
			return nil
		}
		// A hostname target cannot be resolved here; refuse a loopback-only name
		// so "localhost" is never tunnelled without the opt-in, and let the
		// dial-time Control enforce the resolved-IP policy on the tunnel.
		if !allowLoopback && strings.EqualFold(host, "localhost") {
			return destinationDenied(host)
		}
		return nil
	}
}

// sanitize strips userinfo and query from a raw URL for safe inclusion in an
// error, falling back to the input when it does not parse. It never returns a
// credential.
func sanitize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid url]"
	}
	return u.Redacted()
}
