// Package middleware holds the cross-cutting HTTP guards.
//
// Security model (ADR-003, achado SEC-04): LocalOnly is not applied route by
// route. The caller wraps the WHOLE mux with it, so a route added later is
// protected by construction and cannot be forgotten. It runs before any
// authentication: a non-loopback caller is rejected before it can even present
// a credential.
package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/observability"
)

// LocalOnly rejects any request whose peer is not a loopback address. It wraps
// the entire router (catch-all), never an allowlist of paths.
func LocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoopbackRemote(r.RemoteAddr) {
			domainErr := domain.New(domain.CodeForbiddenLocalOnly,
				domain.WithHTTPStatus(http.StatusForbidden),
				domain.WithParams(map[string]string{"remote": r.RemoteAddr}),
			)
			WriteError(w, r, domainErr)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IsLoopbackRemote reports whether a RemoteAddr ("host:port") is loopback.
// Anything unparseable fails closed.
func IsLoopbackRemote(remoteAddr string) bool {
	host := hostOf(remoteAddr)
	if host == "" {
		return false
	}
	// Accept a bare host too (some servers strip the port).
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsLoopback()
	}
	// "localhost" is not an IP but is unambiguously loopback.
	return strings.EqualFold(host, "localhost")
}

func hostOf(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	// No port present: strip IPv6 brackets and return as-is.
	return strings.Trim(remoteAddr, "[]")
}

// RequestID assigns a time-sortable request ID, stores it on the context and
// echoes it back in the X-Request-ID header.
type RequestIDFunc func() domain.RequestID

// RequestID wraps a handler with request-ID correlation.
func RequestID(gen RequestIDFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := gen()
			ctx := observability.WithRequestID(r.Context(), id)
			w.Header().Set("X-Request-ID", id.String())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Recoverer converts a panic into a redacted 500 and logs it with the request
// ID, so a stack-trace panic never reaches the client.
func Recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if logger != nil {
						logger.ErrorContext(r.Context(), "panic recovered",
							"panic", rec, "path", r.URL.Path)
					}
					domainErr := domain.New(domain.CodeInternal,
						domain.WithHTTPStatus(http.StatusInternalServerError),
					)
					WriteError(w, r, domainErr)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
