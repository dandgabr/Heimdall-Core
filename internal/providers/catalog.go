package providers

import (
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// Catalog adapts the provider registry to the Router's ModelCatalog port
// (internal/router.ModelCatalog) WITHOUT importing the router: the interface is
// satisfied structurally by the methods below, which keeps the dependency graph
// acyclic (providers is below router).
//
// It is the production model catalog: the Router uses it to expand a model step,
// a provider wildcard and the capability-aware ordering. A family that declines
// a model returns ok=false and the Router skips that provider for that model,
// exactly as ADR-0001 requires.
type Catalog struct {
	registry *Registry
}

// compile-time shape check against the router port (kept as a local interface so
// providers does not import router).
var _ interface {
	Providers() []domain.ProviderID
	Models(domain.ProviderID) []domain.ModelID
	Capabilities(domain.ProviderID, domain.ModelID) (contracts.Capabilities, bool)
	Modalities(domain.ProviderID, domain.ModelID) (contracts.ModalitySet, bool)
} = (*Catalog)(nil)

// NewCatalog builds the catalog over a registry.
func NewCatalog(r *Registry) *Catalog { return &Catalog{registry: r} }

// modelLister is the optional extension a family implements to enumerate its
// declared models (OpenAICompat and CloudCode both do). A family without it has
// no enumerable models, so a wildcard yields none for it.
type modelLister interface{ Models() []domain.ModelID }

// modalizer is the optional extension a family implements to report a model's
// modalities.
type modalizer interface {
	Modalities(model domain.ModelID) (contracts.ModalitySet, bool)
}

// Providers returns the known provider IDs in deterministic order.
func (c *Catalog) Providers() []domain.ProviderID { return c.registry.IDs() }

// Models returns a provider's declared models in deterministic order, or nil
// when the family does not enumerate them.
func (c *Catalog) Models(p domain.ProviderID) []domain.ModelID {
	family, err := c.registry.Get(p)
	if err != nil {
		return nil
	}
	if lister, ok := family.(modelLister); ok {
		return lister.Models()
	}
	return nil
}

// Capabilities reports a provider's capability set for a model. ok=false means
// the family does not declare the model.
func (c *Catalog) Capabilities(p domain.ProviderID, m domain.ModelID) (contracts.Capabilities, bool) {
	family, err := c.registry.Get(p)
	if err != nil {
		return 0, false
	}
	return family.Capabilities(m)
}

// Modalities reports a provider's modalities for a model, or ok=false.
func (c *Catalog) Modalities(p domain.ProviderID, m domain.ModelID) (contracts.ModalitySet, bool) {
	family, err := c.registry.Get(p)
	if err != nil {
		return 0, false
	}
	if mz, ok := family.(modalizer); ok {
		return mz.Modalities(m)
	}
	return 0, false
}
