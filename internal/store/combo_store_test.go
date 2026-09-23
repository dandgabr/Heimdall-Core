package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// stubProviders is a controllable combos.ProviderSet for the store tests.
type stubProviders struct {
	known  map[domain.ProviderID]bool
	models map[domain.ModelID]bool
}

func (s stubProviders) Has(id domain.ProviderID) bool       { return s.known[id] }
func (s stubProviders) DeclaresModel(m domain.ModelID) bool { return s.models[m] }

func testProviders() stubProviders {
	return stubProviders{
		known:  map[domain.ProviderID]bool{"z.ai": true},
		models: map[domain.ModelID]bool{"glm-5": true},
	}
}

func newComboStore(t *testing.T) *ComboStore {
	t.Helper()
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	return NewComboStore(st, testProviders())
}

func TestComboStoreCRUD(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()

	combo := combos.NewCombo("primary", contracts.StrategyFallback, []combos.Step{
		{Kind: combos.StepModel, Ref: "glm-5", Weight: 2},
		{Kind: combos.StepProviderWildcard, Ref: "z.ai"},
	})
	if err := cs.Create(ctx, combo); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := cs.Get(ctx, "primary")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "primary" || got.Strategy != contracts.StrategyFallback {
		t.Fatalf("Get = %+v", got)
	}
	if len(got.Steps) != 2 || got.Steps[0].Weight != 2 || got.Steps[0].Ref != "glm-5" {
		t.Fatalf("steps round-trip failed: %+v", got.Steps)
	}
	if got.SchemaVer != combos.CurrentSchema {
		t.Fatalf("schema = %d", got.SchemaVer)
	}

	// Update changes the strategy and steps.
	got.Strategy = contracts.StrategyPriority
	got.Steps = []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}
	if err := cs.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	again, _ := cs.Get(ctx, "primary")
	if again.Strategy != contracts.StrategyPriority || len(again.Steps) != 1 {
		t.Fatalf("update not persisted: %+v", again)
	}

	// List returns it.
	list, err := cs.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}

	// Delete.
	if err := cs.Delete(ctx, "primary"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.Get(ctx, "primary"); !combos.IsNotFound(err) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestComboStoreNotFound(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()

	if _, err := cs.Get(ctx, "ghost"); !combos.IsNotFound(err) {
		t.Errorf("Get = %v, want not found", err)
	}
	if err := cs.Delete(ctx, "ghost"); !combos.IsNotFound(err) {
		t.Errorf("Delete = %v, want not found", err)
	}
	if err := cs.Update(ctx, combos.NewCombo("ghost", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}})); !combos.IsNotFound(err) {
		t.Errorf("Update = %v, want not found", err)
	}
}

func TestComboStoreCreateDuplicate(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()
	combo := combos.NewCombo("dup", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}})
	if err := cs.Create(ctx, combo); err != nil {
		t.Fatalf("Create: %v", err)
	}
	err := cs.Create(ctx, combo)
	assertDomainCode(t, err, domain.CodeRouteInvalidCombo)
}

func TestComboStoreCreateValidates(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()

	// Bad name.
	err := cs.Create(ctx, combos.NewCombo("bad name", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	assertDomainCode(t, err, domain.CodeRouteInvalidCombo)

	// Unknown provider wildcard.
	err = cs.Create(ctx, combos.NewCombo("w", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepProviderWildcard, Ref: "ghost"}}))
	assertDomainCode(t, err, domain.CodeRouteUnknownProvider)

	// Reference to a missing combo.
	err = cs.Create(ctx, combos.NewCombo("r", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepComboRef, Ref: "ghost"}}))
	assertDomainCode(t, err, domain.CodeRouteInvalidCombo)
}

func TestComboStoreRejectsCycle(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()

	// a references b (which does not exist yet) -> refused at create.
	a := combos.NewCombo("a", contracts.StrategyPipeline, []combos.Step{{Kind: combos.StepComboRef, Ref: "b"}})
	if err := cs.Create(ctx, a); err == nil {
		t.Fatal("create with unknown ref accepted")
	}

	// Save b (leaf), then a referencing b, then a self-loop on b that closes the
	// cycle a -> b -> a.
	b := combos.NewCombo("b", contracts.StrategyPipeline, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}})
	if err := cs.Create(ctx, b); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	if err := cs.Create(ctx, a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	// Now update b to reference a: cycle.
	b.Steps = []combos.Step{{Kind: combos.StepComboRef, Ref: "a"}}
	err := cs.Update(ctx, b)
	assertDomainCode(t, err, domain.CodeRouteCyclicCombo)
}

func TestComboStoreRejectsSelfReference(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()
	self := combos.NewCombo("self", contracts.StrategyPipeline, []combos.Step{{Kind: combos.StepComboRef, Ref: "self"}})
	err := cs.Create(ctx, self)
	assertDomainCode(t, err, domain.CodeRouteCyclicCombo)
}

func TestComboStorePersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "heimdall.db")
	st, _, _ := newTestVault(t, dbPath, "material")
	cs := NewComboStore(st, testProviders())
	ctx := context.Background()

	combo := combos.NewCombo("keep", contracts.StrategyWeighted, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5", Weight: 3}})
	if err := cs.Create(ctx, combo); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	cs2 := NewComboStore(st2, testProviders())
	got, err := cs2.Get(ctx, "keep")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Strategy != contracts.StrategyWeighted || got.Steps[0].Weight != 3 {
		t.Fatalf("combo did not survive reopen: %+v", got)
	}
}

// TestComboStoreRefusesNewerSchema writes a row with a future schema version and
// asserts the load refuses it fail-closed (ADR-0013 §4).
func TestComboStoreRefusesNewerSchema(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	// Insert directly, bypassing the store's Create (which stamps current schema).
	_, err := st.write.Exec(
		`INSERT INTO combos (name, schema_ver, policy, body, depth, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"future", combos.CurrentSchema+1, string(contracts.StrategyAuto), `[]`, 0,
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	cs := NewComboStore(st, testProviders())
	_, err = cs.Get(context.Background(), "future")
	assertDomainCode(t, err, domain.CodeRouteInvalidCombo)
}

// TestComboStoreMalformedRows covers the scan error branches: bad JSON steps, an
// unknown strategy and corrupt timestamps.
func TestComboStoreMalformedRows(t *testing.T) {
	cases := []struct {
		name    string
		policy  string
		body    string
		created string
		updated string
	}{
		{"bad steps", string(contracts.StrategyAuto), `{not json`, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
		{"bad policy", "bogus", `[]`, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
		{"bad created", string(contracts.StrategyAuto), `[]`, "nope", "2026-01-01T00:00:00Z"},
		{"bad updated", string(contracts.StrategyAuto), `[]`, "2026-01-01T00:00:00Z", "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
			_, err := st.write.Exec(
				`INSERT INTO combos (name, schema_ver, policy, body, depth, created_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				"x", combos.CurrentSchema, tc.policy, tc.body, 0, tc.created, tc.updated,
			)
			if err != nil {
				t.Fatalf("insert: %v", err)
			}
			cs := NewComboStore(st, testProviders())
			if _, err := cs.Get(context.Background(), "x"); err == nil {
				t.Fatal("malformed row accepted")
			}
		})
	}
}

// TestComboStoreNilProviders covers the explicit opt-out of the allowlist.
func TestComboStoreNilProviders(t *testing.T) {
	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	cs := NewComboStore(st, nil)
	combo := combos.NewCombo("any", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepProviderWildcard, Ref: "anything"}})
	if err := cs.Create(context.Background(), combo); err != nil {
		t.Fatalf("nil providers should allow any target: %v", err)
	}
}

// TestComboStoreListError covers the List read-error branch via a faulty store.
func TestComboStoreListError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{failOn: "FROM combos"}), testProviders())
	if _, err := cs.List(context.Background()); err == nil {
		t.Fatal("List accepted a failing read")
	}
	if _, err := cs.Get(context.Background(), "x"); err == nil {
		t.Fatal("Get accepted a failing read")
	}
}

// TestComboStoreCreateWriteError covers the write-error branch.
func TestComboStoreCreateWriteError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{failOn: "INSERT INTO combos"}), testProviders())
	// The existence check reads "FROM combos" -> the fault driver returns no
	// rows (empty), so Create proceeds to the INSERT, which fails.
	err := cs.Create(context.Background(), combos.NewCombo("x", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Create accepted a failing insert")
	}
}

// TestComboStoreDeleteWriteError covers the delete-error branch.
func TestComboStoreDeleteWriteError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{failOn: "DELETE FROM combos"}), testProviders())
	if err := cs.Delete(context.Background(), "x"); err == nil {
		t.Fatal("Delete accepted a failing delete")
	}
}

func assertDomainCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", want)
	}
	var de *domain.DomainError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v (%T), want *domain.DomainError", err, err)
	}
	if de.Code != want {
		t.Fatalf("code = %q, want %q", de.Code, want)
	}
}

// TestComboStoreDefaultsSchemaAndID covers Create's zero-value defaulting: a
// caller that leaves SchemaVer/ID unset gets them filled.
func TestComboStoreDefaultsSchemaAndID(t *testing.T) {
	cs := newComboStore(t)
	// A combo with no ID and no schema (a hand-built value, not via NewCombo).
	raw := combos.Combo{
		Name:     "raw",
		Strategy: contracts.StrategyAuto,
		Steps:    []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}},
	}
	if err := cs.Create(context.Background(), raw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := cs.Get(context.Background(), "raw")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SchemaVer != combos.CurrentSchema {
		t.Fatalf("schema not defaulted: %d", got.SchemaVer)
	}
}

// TestComboStoreUpdateDefaultsID covers Update's ID defaulting on an existing
// combo (matched by name).
func TestComboStoreUpdateDefaultsID(t *testing.T) {
	cs := newComboStore(t)
	ctx := context.Background()
	if err := cs.Create(ctx, combos.NewCombo("u", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}})); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Update with an empty ID but a name that exists.
	raw := combos.Combo{
		Name:      "u",
		Strategy:  contracts.StrategyPriority,
		SchemaVer: combos.CurrentSchema,
		Steps:     []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}},
	}
	if err := cs.Update(ctx, raw); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := cs.Get(ctx, "u")
	if got.Strategy != contracts.StrategyPriority {
		t.Fatalf("update not applied: %+v", got)
	}
}

// TestComboStoreLoadAllError covers validate's loadAll error branch.
func TestComboStoreLoadAllError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{failOn: "FROM combos"}), testProviders())
	err := cs.Create(context.Background(), combos.NewCombo("x", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Create proceeded past a failing List")
	}
}

// TestComboStoreUpdateRowsAffectedZero covers the update path where the row
// vanished between the existence check and the UPDATE.
func TestComboStoreUpdateRowsAffectedZero(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{combosRow: true, zeroRowsAffected: true}), testProviders())
	err := cs.Update(context.Background(), combos.NewCombo("existing", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if !combos.IsNotFound(err) {
		t.Fatalf("Update = %v, want not found", err)
	}
}

// TestComboStoreUpdateWriteError covers the update Exec error branch.
func TestComboStoreUpdateWriteError(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{combosRow: true, failOn: "UPDATE combos"}), testProviders())
	err := cs.Update(context.Background(), combos.NewCombo("existing", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Update accepted a failing UPDATE")
	}
}

// TestComboStoreMarshalError covers the write marshal branch via the seam.
func TestComboStoreMarshalError(t *testing.T) {
	old := marshalSteps
	marshalSteps = func(any) ([]byte, error) { return nil, errors.New("injected marshal failure") }
	defer func() { marshalSteps = old }()

	cs := newComboStore(t)
	err := cs.Create(context.Background(), combos.NewCombo("x", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Create accepted a failing marshal")
	}
}

// TestComboStoreUnmarshalError covers the scan unmarshal branch via the seam.
func TestComboStoreUnmarshalError(t *testing.T) {
	old := unmarshalSteps
	unmarshalSteps = func([]byte, any) error { return errors.New("injected unmarshal failure") }
	defer func() { unmarshalSteps = old }()

	st, _, _ := newTestVault(t, filepath.Join(t.TempDir(), "heimdall.db"), "material")
	_, err := st.write.Exec(
		`INSERT INTO combos (name, schema_ver, policy, body, depth, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"x", combos.CurrentSchema, string(contracts.StrategyAuto), `[{"kind":"model","ref":"glm-5"}]`, 0,
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	cs := NewComboStore(st, testProviders())
	if _, err := cs.Get(context.Background(), "x"); err == nil {
		t.Fatal("Get accepted a failing unmarshal")
	}
}

// TestComboStoreListRowsErr covers List's rows.Err() branch.
func TestComboStoreListRowsErr(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{failRowsNext: true}), testProviders())
	if _, err := cs.List(context.Background()); err == nil {
		t.Fatal("List succeeded against a failing rows iterator")
	}
}

// TestComboStoreListBadRowAndValidate covers scanCombo's decode-error branch and
// validate/loadAll propagation of a List error. The failure targets only the
// List query ("ORDER BY name"), so the Create existence check (a "WHERE name"
// Get) returns not-found and Create proceeds to validate.
func TestComboStoreListBadRowAndValidate(t *testing.T) {
	cs := NewComboStore(faultyStore(t, faultDriverConfig{combosBadRow: true}), testProviders())
	if _, err := cs.Get(context.Background(), "x"); err == nil {
		t.Fatal("Get accepted a malformed row")
	}
	// List hits the same bad row inside its loop, reaching scanCombo's error.
	if _, err := cs.List(context.Background()); err == nil {
		t.Fatal("List accepted a malformed row")
	}

	listFault := NewComboStore(faultyStore(t, faultDriverConfig{failOn: "ORDER BY name ASC"}), testProviders())
	// List fails.
	if _, err := listFault.List(context.Background()); err == nil {
		t.Fatal("List proceeded past a failing query")
	}
	// Create: the existence check (Get) returns no rows -> Create proceeds to
	// validate -> loadAll -> List error, propagated.
	err := listFault.Create(context.Background(), combos.NewCombo("x", contracts.StrategyAuto, []combos.Step{{Kind: combos.StepModel, Ref: "glm-5"}}))
	if err == nil {
		t.Fatal("Create proceeded past a failing loadAll")
	}
}
