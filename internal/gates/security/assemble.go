package security

import (
	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// Config is the whole security-family configuration. Every gate is
// independently switchable; a disabled gate returns nil from its constructor
// and Assemble simply omits it, so it never enters the dependency graph and
// the order of the remaining gates is derived without it (ADR-0014 §4). The
// feature flags themselves live in the config layer (features.gates.<id>); a
// composition root maps them onto this struct.
//
// Safe defaults: the content gates are ON (credential masker, PII mask, block
// injection) and the rate limiter is OFF (its rate is an operator capacity
// decision with no safe guess).
type Config struct {
	// DisableCredentialMasker switches the credential masker off.
	DisableCredentialMasker bool
	// PIIMasker carries the PII policy; the zero value masks (safe default).
	PIIMasker PiiConfig
	// Injection carries the injection-guard policy; the zero value blocks.
	Injection InjectConfig
	// DisableSSRF switches the SSRF guard off.
	DisableSSRF bool
	// RateLimit carries the throttle; the zero value builds nothing.
	RateLimit RateLimitConfig
}

// Assemble builds every ENABLED gate, in ID order for a stable registration.
// The composition root registers each returned gate under g.ID().
func Assemble(cfg Config) []contracts.Gate {
	var out []contracts.Gate
	if !cfg.DisableCredentialMasker {
		out = append(out, NewCredentialMasker())
	}
	if p := NewPIIMasker(cfg.PIIMasker); p != nil {
		out = append(out, p)
	}
	if g := NewInjectionGuard(cfg.Injection); g != nil {
		out = append(out, g)
	}
	if !cfg.DisableSSRF {
		out = append(out, NewSSRFGuard())
	}
	if r := NewRateLimit(cfg.RateLimit); r != nil {
		out = append(out, r)
	}
	return out
}
