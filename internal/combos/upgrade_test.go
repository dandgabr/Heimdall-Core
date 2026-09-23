package combos

import (
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

func TestUpgradeCurrentSchema(t *testing.T) {
	c := NewCombo("x", contracts.StrategyAuto, []Step{{Kind: StepModel, Ref: "m"}})
	got, err := Upgrade(c)
	if err != nil {
		t.Fatalf("Upgrade(current): %v", err)
	}
	if got.SchemaVer != CurrentSchema {
		t.Fatalf("schema = %d", got.SchemaVer)
	}
}

func TestUpgradeNewerSchemaRefused(t *testing.T) {
	c := NewCombo("x", contracts.StrategyAuto, nil)
	c.SchemaVer = CurrentSchema + 1
	_, err := Upgrade(c)
	assertCode(t, err, domain.CodeRouteInvalidCombo)
}

func TestUpgradeZeroSchemaRefused(t *testing.T) {
	c := NewCombo("x", contracts.StrategyAuto, nil)
	c.SchemaVer = 0
	_, err := Upgrade(c)
	assertCode(t, err, domain.CodeRouteInvalidCombo)
}

func TestUpgradeOlderSchemaRefused(t *testing.T) {
	// A version below CurrentSchema but above zero predates any shipped format.
	c := NewCombo("x", contracts.StrategyAuto, nil)
	c.SchemaVer = 1
	_, err := Upgrade(c)
	assertCode(t, err, domain.CodeRouteInvalidCombo)
}

func TestNotFoundSentinel(t *testing.T) {
	err := NotFound()
	if !IsNotFound(err) {
		t.Fatal("IsNotFound(NotFound()) = false")
	}
	wrapped := errors.New("wrapped")
	if IsNotFound(wrapped) {
		t.Fatal("IsNotFound(unrelated) = true")
	}
	de, ok := err.(*domain.DomainError)
	if !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("not-found error = %v", err)
	}
}

func TestInvalidErrorExported(t *testing.T) {
	assertCode(t, InvalidError("n", "because"), domain.CodeRouteInvalidCombo)
}

func TestParseStrategyDelegates(t *testing.T) {
	got, ok := ParseStrategy("auto")
	if !ok || got != contracts.StrategyAuto {
		t.Fatalf("ParseStrategy(auto) = %v, %v", got, ok)
	}
	if _, ok := ParseStrategy("bogus"); ok {
		t.Fatal("ParseStrategy accepted a bogus strategy")
	}
}
