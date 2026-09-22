package translators

import (
	"sort"
	"sync"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// Registry maps a (from, to) format pair to its translator.
//
// DETERMINISM: Pairs() and Formats() never iterate the map directly; they sort
// the keys, because Go randomises map iteration. Lookup is order-independent but
// the enumeration API is not allowed to be, so a caller that builds a table or a
// test that asserts a list gets the same result on every run.
type Registry struct {
	mu    sync.RWMutex
	pairs map[pairKey]contracts.Translator
}

// pairKey is the (from, to) key. It is a struct, not a "from->to" string, so a
// format name containing the separator cannot collide with another pair.
type pairKey struct {
	from contracts.WireFormat
	to   contracts.WireFormat
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{pairs: make(map[pairKey]contracts.Translator)}
}

// Register adds a translator for its (From, To) pair. A nil translator or a
// translator with an empty format is rejected, and a duplicate pair is rejected
// rather than silently overwritten: a duplicate means two components disagree on
// the wire format of a family, which must fail loudly at wiring time.
func (r *Registry) Register(t contracts.Translator) error {
	if t == nil {
		return unsupported("", "")
	}
	from, to := t.From(), t.To()
	if from == "" || to == "" {
		return unsupported(string(from), string(to))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	key := pairKey{from: from, to: to}
	if _, exists := r.pairs[key]; exists {
		return failed("translator already registered for "+string(from)+"->"+string(to), nil)
	}
	r.pairs[key] = t
	return nil
}

// Lookup returns the translator for (from, to), or translate.unsupported when
// there is none. An identity pair (from == to) is not special-cased: the OpenAI
// family registers its Identity explicitly, so a missing registration is a real
// wiring gap rather than a silent pass-through.
func (r *Registry) Lookup(from, to contracts.WireFormat) (contracts.Translator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.pairs[pairKey{from: from, to: to}]
	if !ok {
		return nil, unsupported(string(from), string(to))
	}
	return t, nil
}

// Pairs returns every registered (from, to) pair in deterministic order: sorted
// by from, then by to.
func (r *Registry) Pairs() [][2]contracts.WireFormat {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([]pairKey, 0, len(r.pairs))
	for k := range r.pairs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].from != keys[j].from {
			return keys[i].from < keys[j].from
		}
		return keys[i].to < keys[j].to
	})

	out := make([][2]contracts.WireFormat, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]contracts.WireFormat{k.from, k.to})
	}
	return out
}

// Formats returns the distinct wire formats that appear as a source, in
// deterministic order.
func (r *Registry) Formats() []contracts.WireFormat {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[contracts.WireFormat]struct{}, len(r.pairs))
	for k := range r.pairs {
		seen[k.from] = struct{}{}
	}
	out := make([]contracts.WireFormat, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Default builds the registry with the built-in translators: the OpenAI identity
// and the Anthropic and Gemini bidirectional pairs. It is the composition root's
// one-liner; a caller with custom translators uses NewRegistry directly.
func Default() (*Registry, error) {
	return buildDefault([]contracts.Translator{
		Identity{},
		AnthropicToOpenAI{},
		GeminiToOpenAI{},
	})
}

// buildDefault is the pure body of Default, taking the translator list as an
// argument. Keeping it a pure function (rather than reading a package variable)
// preserves the package's no-mutable-state rule and still lets a test drive the
// registration-failure branch.
func buildDefault(list []contracts.Translator) (*Registry, error) {
	r := NewRegistry()
	for _, t := range list {
		if err := r.Register(t); err != nil {
			return nil, err
		}
	}
	return r, nil
}
