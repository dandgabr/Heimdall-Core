// Package contracts holds the leaf contracts shared across the core.
//
// It imports only domain (itself a leaf), so any package may depend on it
// without creating an import cycle. Interfaces are intentionally small and are
// satisfied structurally by their implementations, following the Go idiom that
// the consumer defines the interface it needs.
package contracts

import (
	"time"

	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Clock is the injectable time source. Cooldown, quota windows and TTL logic
// must be testable without sleeping, so nothing in the core calls time.Now
// directly once a Clock is available.
type Clock interface {
	Now() time.Time
}

// IDGen produces correlation identifiers. Injecting it keeps tests
// deterministic instead of parsing random UUIDs.
type IDGen interface {
	NewRequestID() domain.RequestID
}

// Redactor removes secrets from any string that may reach a log, an error body
// or an audit trail. There is exactly one implementation (internal/i18n) so the
// logger and the error formatter cannot drift apart.
type Redactor interface {
	Redact(s string) string
}
