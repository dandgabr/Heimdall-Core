package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// ComboStore is the SQLite persistence of named routing combos (ADR-0013).
//
// It persists the combo POLICY (name, strategy, steps, schema version, derived
// depth). The rotation cursor (round-robin/fill-first) is NOT stored: it is
// in-memory execution state that resets on restart (ADR-0013 §5).
//
// Concurrency: reads go through the read pool; Create/Update/Delete go through
// the single writer connection (store.go). Validation happens BEFORE the write,
// so an invalid combo never reaches the database.
//
// Validation needs the set of existing combos (for reference resolution and
// cycle detection) and the provider allowlist. Both are injected, so the store
// does not import the provider registry (which would create a cycle: providers
// import contracts, contracts/combos are leaves).
type ComboStore struct {
	store     *Store
	providers combos.ProviderSet
}

// NewComboStore builds the store over an open vault. providers is the allowlist
// used to validate provider/model targets; it may be nil, in which case the
// allowlist check is skipped (the caller is opting out explicitly).
func NewComboStore(s *Store, providers combos.ProviderSet) *ComboStore {
	return &ComboStore{store: s, providers: providers}
}

// Create validates and inserts a new combo. A combo with an existing name is a
// duplicate error; an invalid name/shape/graph is the matching route.* error.
func (c *ComboStore) Create(ctx context.Context, combo combos.Combo) error {
	if combo.SchemaVer == 0 {
		combo.SchemaVer = combos.CurrentSchema
	}
	if combo.ID == "" {
		combo.ID = domain.ComboID(combo.Name)
	}
	// A create must not already exist. Check first so the error is the typed
	// invalid_combo (duplicate), not a raw SQL constraint failure.
	if _, err := c.Get(ctx, combo.ID); err == nil {
		return comboInvalid(combo.Name, "a combo with this name already exists")
	} else if !errors.Is(err, combosNotFound()) {
		return err
	}

	depth, err := c.validate(ctx, combo, false)
	if err != nil {
		return err
	}
	combo.Depth = depth

	return c.write(ctx, combo, true)
}

// Update validates and replaces an existing combo. A missing combo is not found.
func (c *ComboStore) Update(ctx context.Context, combo combos.Combo) error {
	if combo.ID == "" {
		combo.ID = domain.ComboID(combo.Name)
	}
	if _, err := c.Get(ctx, combo.ID); err != nil {
		return err
	}
	depth, err := c.validate(ctx, combo, true)
	if err != nil {
		return err
	}
	combo.Depth = depth
	return c.write(ctx, combo, false)
}

// Save creates or replaces a combo and returns the PERSISTED combo with the
// derived Depth set. It is the management API's entry point: unlike Create
// (duplicate is an error) it upserts, and unlike a separate Get after a write it
// returns the value directly, so the caller never performs a second read whose
// only possible outcome is the row it just wrote.
//
// Validation runs BEFORE the write, so an invalid combo never reaches the
// database; Depth is the value ValidateGraph computed, not a re-derivation.
func (c *ComboStore) Save(ctx context.Context, combo combos.Combo) (combos.Combo, error) {
	if combo.SchemaVer == 0 {
		combo.SchemaVer = combos.CurrentSchema
	}
	if combo.ID == "" {
		combo.ID = domain.ComboID(combo.Name)
	}
	_, getErr := c.Get(ctx, combo.ID)
	insert := errors.Is(getErr, combosNotFound())
	if !insert && getErr != nil {
		return combos.Combo{}, getErr
	}
	depth, err := c.validate(ctx, combo, !insert)
	if err != nil {
		return combos.Combo{}, err
	}
	combo.Depth = depth
	if err := c.write(ctx, combo, insert); err != nil {
		return combos.Combo{}, err
	}
	return combo, nil
}

// validate runs the pure combo validation with the currently stored combos and
// the injected provider allowlist.
func (c *ComboStore) validate(ctx context.Context, combo combos.Combo, update bool) (int, error) {
	existing, err := c.loadAll(ctx)
	if err != nil {
		return 0, err
	}
	// On update the combo already exists; remove it so ValidateGraph treats it
	// as `self` rather than as a pre-existing reference target.
	if update {
		delete(existing, combo.ID)
	}
	return combos.ValidateGraph(combo, existing, c.providers)
}

// write serialises and upserts the combo. insert controls created_at.
func (c *ComboStore) write(ctx context.Context, combo combos.Combo, insert bool) error {
	body, err := marshalSteps(combo.Steps)
	if err != nil {
		return comboStoreError("marshal", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	if insert {
		_, err = c.store.write.ExecContext(ctx, `
			INSERT INTO combos (name, schema_ver, policy, body, depth, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			combo.Name, combo.SchemaVer, string(combo.Strategy), string(body),
			combo.Depth, now, now,
		)
	} else {
		res, execErr := c.store.write.ExecContext(ctx, `
			UPDATE combos SET schema_ver = ?, policy = ?, body = ?, depth = ?, updated_at = ?
			WHERE name = ?`,
			combo.SchemaVer, string(combo.Strategy), string(body), combo.Depth, now, combo.Name,
		)
		if execErr == nil {
			if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 0 {
				return combosNotFound()
			}
		}
		err = execErr
	}
	if err != nil {
		return comboStoreError("write", err)
	}
	return nil
}

// Get returns one combo or combos.NotFound. A persisted schema version newer
// than this build is refused fail-closed by Upgrade (ADR-0013 §4).
func (c *ComboStore) Get(ctx context.Context, id domain.ComboID) (combos.Combo, error) {
	row := c.store.read.QueryRowContext(ctx, `
		SELECT name, schema_ver, policy, body, depth, created_at, updated_at
		FROM combos WHERE name = ?`, string(id))
	combo, err := scanCombo(row)
	if errors.Is(err, sql.ErrNoRows) {
		return combos.Combo{}, combosNotFound()
	}
	if err != nil {
		return combos.Combo{}, err
	}
	return combo, nil
}

// List returns every combo in deterministic (name) order.
func (c *ComboStore) List(ctx context.Context) ([]combos.Combo, error) {
	rows, err := c.store.read.QueryContext(ctx, `
		SELECT name, schema_ver, policy, body, depth, created_at, updated_at
		FROM combos ORDER BY name ASC`)
	if err != nil {
		return nil, comboStoreError("list", err)
	}
	defer rows.Close()

	var out []combos.Combo
	for rows.Next() {
		combo, err := scanCombo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, combo)
	}
	if err := rows.Err(); err != nil {
		return nil, comboStoreError("list", err)
	}
	return out, nil
}

// Delete removes a combo. A missing combo is not found.
func (c *ComboStore) Delete(ctx context.Context, id domain.ComboID) error {
	res, err := c.store.write.ExecContext(ctx, `DELETE FROM combos WHERE name = ?`, string(id))
	if err != nil {
		return comboStoreError("delete", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 0 {
		return combosNotFound()
	}
	return nil
}

// loadAll is the internal read used by validation: the current combos keyed by
// id. It tolerates the pre-migration state (no combos table) by returning an
// empty set rather than failing validation.
func (c *ComboStore) loadAll(ctx context.Context) (map[domain.ComboID]combos.Combo, error) {
	list, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[domain.ComboID]combos.Combo, len(list))
	for _, combo := range list {
		out[combo.ID] = combo
	}
	return out, nil
}

// --- row scanning ---

func scanCombo(s rowScanner) (combos.Combo, error) {
	var (
		name, policy, body, created, updated string
		schemaVer, depth                     int
	)
	if err := s.Scan(&name, &schemaVer, &policy, &body, &depth, &created, &updated); err != nil {
		return combos.Combo{}, err
	}

	var steps []combos.Step
	if body != "" {
		if err := unmarshalSteps([]byte(body), &steps); err != nil {
			return combos.Combo{}, comboStoreError("decode steps", err)
		}
	}

	strategy, ok := parseStrategy(policy)
	if !ok {
		return combos.Combo{}, comboInvalid(name, "unknown strategy "+policy)
	}

	createdAt, err := parseTime(created)
	if err != nil {
		return combos.Combo{}, comboStoreError("decode created_at", err)
	}
	updatedAt, err := parseTime(updated)
	if err != nil {
		return combos.Combo{}, comboStoreError("decode updated_at", err)
	}

	combo := combos.Combo{
		ID:        domain.ComboID(name),
		Name:      name,
		Strategy:  strategy,
		Steps:     steps,
		SchemaVer: schemaVer,
		Depth:     depth,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
	return combos.Upgrade(combo)
}

// --- helpers ---

// combosNotFound is the sentinel the store returns for a missing combo. It is
// the same value combos.NotFound returns, so a caller can errors.Is against
// either.
func combosNotFound() error {
	return combos.NotFound()
}

func comboInvalid(name, reason string) error {
	return combos.InvalidError(name, reason)
}

func comboStoreError(op string, err error) error {
	return domain.New(domain.CodeStoreOpenFailed,
		domain.WithHTTPStatus(500),
		domain.WithCause(err),
		domain.WithParams(map[string]string{"reason": "combo " + op + ": " + err.Error()}),
	)
}

// parseStrategy reverses the shared strategy vocabulary via the combo package.
func parseStrategy(s string) (contracts.StrategyKind, bool) {
	return combos.ParseStrategy(s)
}

// marshalSteps is a seam over json.Marshal for the step body. The steps are all
// JSON-marshalable, so the error branch is unreachable without the seam; routing
// it through a variable lets a test prove the failure is a typed error rather
// than a partial write.
var marshalSteps = json.Marshal

// unmarshalSteps is the matching seam for the read side.
var unmarshalSteps = json.Unmarshal
