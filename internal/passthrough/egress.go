package passthrough

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Egress policy for the passthrough upstream.
//
// ADR-003 (Egress) requires TLS verification, an SSRF guard and redirect
// revalidation. Three layers implement it:
//
//  1. URL validation at construction (validateUpstreamURL): HTTPS is mandatory;
//     plain HTTP is permitted only when the configured host is an explicit
//     loopback literal (a local Ollama-style upstream).
//  2. A dial-time Control hook (ssrfControl): every connection, including one
//     reached after DNS, is checked against the denied ranges. This is what
//     defeats DNS rebinding — the check runs on the RESOLVED address, not on the
//     hostname.
//  3. Redirect blocking (CheckRedirect): the client refuses to follow any
//     redirect, so a 30x cannot move the request to a different destination
//     after the initial validation.

// IsLoopbackLiteral reports whether host is an explicit loopback IP literal
// (127.0.0.0/8 or ::1). A hostname is never accepted here: allowing "localhost"
// would let a DNS entry decide the destination.
func IsLoopbackLiteral(host string) bool {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// validateUpstreamURL enforces the scheme and host policy on the configured
// base URL. It returns whether the target is an explicit loopback literal (so
// the dial-time guard may permit loopback for a local model server).
func validateUpstreamURL(raw string) (allowLoopback bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, domain.New(domain.CodeConfigLoadFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "invalid upstream URL"}),
		)
	}
	host := u.Hostname()
	if host == "" {
		return false, domain.New(domain.CodeConfigLoadFailed,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"reason": "upstream URL has no host"}),
		)
	}
	// Only an explicit loopback IP literal unlocks the loopback exception.
	loopback := IsLoopbackLiteral(host)

	switch strings.ToLower(u.Scheme) {
	case "https":
		return loopback, nil
	case "http":
		if loopback {
			return true, nil
		}
		return false, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"url": u.Redacted()}),
		)
	default:
		return false, domain.New(domain.CodeUpstreamInsecureURL,
			domain.WithHTTPStatus(500),
			domain.WithParams(map[string]string{"url": u.Redacted()}),
		)
	}
}

// deniedIP reports whether ip must never be dialled. It covers the SSRF ranges:
// loopback, private (RFC1918/U LA), link-local (including the cloud metadata
// address 169.254.169.254), unique-local IPv6, multicast, unspecified and the
// IPv4-mapped IPv6 forms of all of them (netip.Addr.Unmap collapses ::ffff:a.b).
func deniedIP(ip netip.Addr, allowLoopback bool) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return !allowLoopback
	}
	return ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast()
}

// ssrfControl is the net.Dialer.Control hook. It receives the already-resolved
// "host:port" address, so a DNS rebind to a private address is rejected at
// connect time.
func ssrfControl(allowLoopback bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			// A non-literal address cannot be validated; fail closed.
			return domain.New(domain.CodeUpstreamDestinationDenied,
				domain.WithHTTPStatus(502),
				domain.WithParams(map[string]string{"host": host}),
			)
		}
		if deniedIP(ip, allowLoopback) {
			return domain.New(domain.CodeUpstreamDestinationDenied,
				domain.WithHTTPStatus(502),
				domain.WithParams(map[string]string{"host": host}),
			)
		}
		return nil
	}
}
