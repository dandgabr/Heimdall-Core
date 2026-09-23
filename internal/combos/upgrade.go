package combos

import (
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file holds the persisted-format upgrade, a PURE function (no I/O, no
// clock) testable with goldens, mirroring the config upgrader pattern.

// Upgrade brings a combo loaded from the store up to CurrentSchema.
//
// Rules (ADR-0013 §4):
//   - a combo at CurrentSchema is returned unchanged;
//   - a combo with a LOWER version is migrated (there is no shipped v1, so a
//     lower version is treated as corrupt rather than guessed — see below);
//   - a combo with a HIGHER version is REFUSED fail-closed: a newer build wrote
//     a format this binary does not understand, and guessing would corrupt it.
func Upgrade(c Combo) (Combo, error) {
	switch {
	case c.SchemaVer == CurrentSchema:
		return c, nil
	case c.SchemaVer > CurrentSchema:
		return Combo{}, domain.New(domain.CodeRouteInvalidCombo,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{
				"name":   c.Name,
				"reason": "combo schema version is newer than this build",
			}),
		)
	case c.SchemaVer <= 0:
		return Combo{}, domain.New(domain.CodeRouteInvalidCombo,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{
				"name":   c.Name,
				"reason": "combo has no schema version",
			}),
		)
	default:
		// A version below CurrentSchema (but > 0): no such format was ever
		// shipped, so there is no data to migrate. Refuse rather than invent a
		// mapping that would silently reinterpret fields.
		return Combo{}, domain.New(domain.CodeRouteInvalidCombo,
			domain.WithHTTPStatus(400),
			domain.WithScope(domain.ScopeRequest),
			domain.WithParams(map[string]string{
				"name":   c.Name,
				"reason": "combo schema version predates any shipped format",
			}),
		)
	}
}
