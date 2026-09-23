package combos

import (
	"errors"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file exposes the small, stable surface the store needs: the not-found
// sentinel, an exported constructor for the invalid-combo error and the strategy
// parser. They exist so internal/store never re-implements the combo vocabulary
// (which could drift) and so a caller can errors.Is against NotFound.

// ErrNotFound is returned (wrapped) when a combo does not exist. It is a
// package-level sentinel; internal/store returns exactly it so a caller uses
// errors.Is rather than string matching.
var ErrNotFound = domain.New(domain.CodeNotFound,
	domain.WithHTTPStatus(404),
)

// NotFound returns the not-found sentinel.
func NotFound() error { return ErrNotFound }

// IsNotFound reports whether err is (or wraps) the not-found sentinel.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// InvalidError builds a route.invalid_combo error with the given name and
// reason. It is the exported form of the package's own `invalid` helper so the
// store can report a duplicate or a persisted-shape problem with the same code.
func InvalidError(name, reason string) error { return invalid(name, reason) }

// ParseStrategy reverses the shared strategy vocabulary.
func ParseStrategy(s string) (contracts.StrategyKind, bool) {
	return contracts.ParseStrategyKind(s)
}
