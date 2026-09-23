package combos

import (
	"strconv"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// itoa is a tiny local integer formatter.
func itoa(n int) string { return strconv.Itoa(n) }

// contractsParseStrategy is the shared strategy parser: the combo does not
// re-implement the closed set, so a strategy added to contracts is understood
// here without a second list.
func contractsParseStrategy(s string) (contracts.StrategyKind, bool) {
	return contracts.ParseStrategyKind(s)
}

// contractsStrategyFusion is the fusion strategy value, named once.
func contractsStrategyFusion() contracts.StrategyKind { return contracts.StrategyFusion }
