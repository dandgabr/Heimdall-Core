package store

import (
	"context"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// TestComboStoreSaveInsertThenUpdate covers the upsert path: a first Save
// inserts (returning the derived depth) and a second Save replaces.
func TestComboStoreSaveInsertThenUpdate(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()

	c := combos.NewCombo("fast", contracts.StrategyFallback, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-5"},
	})
	c.SchemaVer = 0 // force the default branch
	c.ID = ""       // force the id derivation branch
	stored, err := cs.Save(ctx, c)
	if err != nil {
		t.Fatalf("Save insert: %v", err)
	}
	if stored.ID != "fast" || stored.SchemaVer != combos.CurrentSchema || stored.Depth != 0 {
		t.Fatalf("stored = %+v", stored)
	}

	// Second Save replaces (Update path), and returns the same id.
	c2 := combos.NewCombo("fast", contracts.StrategyPriority, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-5"},
		{Kind: combos.StepComboRef, Ref: "base"},
	})
	// "base" must exist for the reference to resolve.
	if _, err := cs.Save(ctx, combos.NewCombo("base", contracts.StrategyAuto, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-5"},
	})); err != nil {
		t.Fatalf("seed base: %v", err)
	}
	stored2, err := cs.Save(ctx, c2)
	if err != nil {
		t.Fatalf("Save update: %v", err)
	}
	if stored2.Strategy != contracts.StrategyPriority || stored2.Depth != 1 {
		t.Fatalf("stored2 = %+v", stored2)
	}
}

// TestComboStoreSaveValidationError proves Save validates before writing.
func TestComboStoreSaveValidationError(t *testing.T) {
	cs := newComboStore(t)
	_, err := cs.Save(context.Background(), combos.NewCombo("w", contracts.StrategyAuto,
		[]combos.Step{{Kind: combos.StepProviderWildcard, Ref: "ghost"}}))
	if err == nil {
		t.Fatal("Save persisted an invalid combo")
	}
}

// TestComboStoreSaveReadError covers Save's Get-error branch (a non-not-found
// read error propagates) using the fault driver.
func TestComboStoreSaveReadError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{failOn: "FROM combos"}), testProviders())
	_, err := cs.Save(context.Background(), combos.NewCombo("x", contracts.StrategyAuto,
		[]combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Save swallowed a read error")
	}
}

// TestComboStoreSaveWriteError covers Save's write-error branch: the Get finds
// an existing row (combosRow) so insert=false, but the UPDATE fails.
func TestComboStoreSaveWriteError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{combosRow: true, failOn: "UPDATE combos"}), testProviders())
	_, err := cs.Save(context.Background(), combos.NewCombo("existing", contracts.StrategyAuto,
		[]combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Save swallowed a write error")
	}
}
