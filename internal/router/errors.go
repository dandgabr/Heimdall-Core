package router

import (
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file holds the typed errors of the Router. They are all ScopeRequest,
// non-retryable (ADR-0009 §7): a routing failure is the request's or the
// operator's input problem, so it must never cooldown a credential or retry.
// The i18n params match the catalog placeholders exactly (the i18n audit test
// asserts this).

// noCandidate is returned when the plan would be empty: the request is not
// serviceable (route.no_candidate, ADR-0009 §7).
func noCandidate() error {
	return domain.New(domain.CodeRouteNoCandidate,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
	)
}

// depthExceeded is returned when a nested combo-ref chain exceeds MaxDepth at
// runtime (route.depth_exceeded, ADR-0013 §3.4).
func depthExceeded(name string) error {
	return domain.New(domain.CodeRouteDepthExceeded,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "max": itoa(maxDepth)}),
	)
}

// cyclicCombo is returned when a combo-ref chain revisits a combo
// (route.cyclic_combo). The save-time validator should already have refused it,
// but the runtime re-checks defensively (ADR-0009 §3, ADR-0013 §3.3).
func cyclicCombo(name string) error {
	return domain.New(domain.CodeRouteCyclicCombo,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name}),
	)
}

// invalidCombo is returned when a combo is missing a required shape at resolve
// time (e.g. an unknown strategy, an empty target).
func invalidCombo(name, reason string) error {
	return domain.New(domain.CodeRouteInvalidCombo,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "reason": reason}),
	)
}

// unknownProvider is returned when an explicit provider target is not in the
// registry (route.unknown_provider).
func unknownProvider(name, provider string) error {
	return domain.New(domain.CodeRouteUnknownProvider,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name, "provider": provider}),
	)
}

// fusionSelfJudge is returned when a fusion combo's judge resolves to the fusion
// combo itself: that is infinite recursion and is refused (route.fusion_self_judge,
// ADR-0009 §3).
func fusionSelfJudge(name string) error {
	return domain.New(domain.CodeRouteFusionSelfJudge,
		domain.WithHTTPStatus(400),
		domain.WithScope(domain.ScopeRequest),
		domain.WithParams(map[string]string{"name": name}),
	)
}

// fusionAllFailed is returned when every fusion panel failed: there is no winner
// to judge (route.fusion_all_failed, ADR-0009 §3).
func fusionAllFailed(panels int) error {
	return domain.New(domain.CodeRouteFusionAllFailed,
		domain.WithHTTPStatus(502),
		domain.WithScope(domain.ScopeProvider),
		domain.WithParams(map[string]string{"panels": itoa(panels)}),
	)
}
