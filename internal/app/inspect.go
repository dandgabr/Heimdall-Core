package app

import (
	"context"
	"errors"
	"sort"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// This file exposes READ-ONLY introspection for the CLI (`quota`, `gate`
// commands). It is deliberately separate from the management-API adapter so the
// CLI does not depend on the JSON wire shapes, and both read the SAME underlying
// state (QuotaRec/GateOrder). Nothing here carries a secret: quotas are
// numbers/windows, gates are ids/stages/policies/caps.

// QuotaWindowInfo is one window of a credential, rendered for the CLI.
type QuotaWindowInfo struct {
	Kind      string
	Limit     float64
	Used      float64
	Remaining float64
	// ResetsAt is the RFC3339 instant, or "" when unknown.
	ResetsAt string
	Source   string
}

// QuotaInfo is one credential's quota state.
type QuotaInfo struct {
	Credential   string
	Provider     string
	Windows      []QuotaWindowInfo
	TerminalCode string
	// HasState is false when the credential has no recorded quota state yet
	// (the filter fail-opens); the CLI shows "no recorded state" rather than an
	// empty-but-present state.
	HasState bool
}

// QuotaInfos returns the quota state of every stored credential, deterministically
// ordered by credential id. A credential with no recorded windows is included
// with HasState=false so the operator sees the account exists.
func (a *App) QuotaInfos() ([]QuotaInfo, error) {
	creds, err := a.Credentials.List(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]QuotaInfo, 0, len(creds))
	for _, c := range creds {
		info := QuotaInfo{Credential: string(c.ID), Provider: string(c.Provider)}
		if state, ok := a.QuotaRec.Snapshot(context.Background(), c.ID); ok {
			info.HasState = true
			info.TerminalCode = state.TerminalCode
			for _, w := range state.Windows {
				info.Windows = append(info.Windows, QuotaWindowInfo{
					Kind:      w.Kind.String(),
					Limit:     w.Limit,
					Used:      w.Used,
					Remaining: w.Remaining,
					ResetsAt:  rfc3339OrEmpty(w.ResetsAt),
					Source:    w.Source.String(),
				})
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Credential < out[j].Credential })
	return out, nil
}

// QuotaInfoFor returns the quota state of ONE credential. found is false when no
// such credential exists in the vault.
func (a *App) QuotaInfoFor(id string) (QuotaInfo, bool, error) {
	cred, err := a.Credentials.Get(context.Background(), domain.CredentialID(id))
	if err != nil {
		// The vault's Get returns contracts.ErrNotFound for a missing id; treat
		// any miss as "not found" so the CLI reports a clean not-found, and
		// propagate a real read error.
		if errors.Is(err, contracts.ErrNotFound) {
			return QuotaInfo{}, false, nil
		}
		return QuotaInfo{}, false, err
	}
	info := QuotaInfo{Credential: string(cred.ID), Provider: string(cred.Provider)}
	if state, ok := a.QuotaRec.Snapshot(context.Background(), cred.ID); ok {
		info.HasState = true
		info.TerminalCode = state.TerminalCode
		for _, w := range state.Windows {
			info.Windows = append(info.Windows, QuotaWindowInfo{
				Kind:      w.Kind.String(),
				Limit:     w.Limit,
				Used:      w.Used,
				Remaining: w.Remaining,
				ResetsAt:  rfc3339OrEmpty(w.ResetsAt),
				Source:    w.Source.String(),
			})
		}
	}
	return info, true, nil
}

// GateInfo is one effective gate, rendered for the CLI. It carries the DAG
// order position, the stages, the failure policy and the declared read/write
// set. It never carries gate content.
type GateInfo struct {
	ID            string
	Stages        []string
	FailurePolicy string
	RequiredCaps  string
	// Reads and Writes are the declared data fields (ADR-0014 §1), sorted.
	Reads  []string
	Writes []string
	// After is the explicit dependency names, sorted.
	After []string
	// Group is the feature group the gate belongs to (token/memory/security/
	// logger), derived from its id for the config switch explanation.
	Group string
}

// GateInfos returns the effective gates in the DAG order they execute in. A gate
// that acts in several stages appears ONCE, positioned at its FIRST stage's
// place (pre_request order, then chunk-only gates, then post-only gates), so the
// listing reads as one row per gate while still reflecting the dependency-
// derived order. Its Stages column shows every stage it acts in.
func (a *App) GateInfos() []GateInfo {
	var out []GateInfo
	seen := map[string]bool{}
	appendStage := func(gates []contracts.Gate) {
		for _, g := range gates {
			if seen[g.ID()] {
				continue
			}
			seen[g.ID()] = true
			out = append(out, gateInfo(g))
		}
	}
	appendStage(a.GateOrder.PreRequest)
	appendStage(a.GateOrder.OnResponseChunk)
	appendStage(a.GateOrder.PostResponse)
	return out
}

// GateInfoByName returns the effective gate with the given id, or found=false.
func (a *App) GateInfoByName(name string) (GateInfo, bool) {
	for _, g := range a.GateOrder.All {
		if g.ID() == name {
			return gateInfo(g), true
		}
	}
	return GateInfo{}, false
}

// gateInfo renders one gate's non-content metadata.
func gateInfo(g contracts.Gate) GateInfo {
	info := GateInfo{
		ID:            g.ID(),
		Stages:        gateStageNames(g.Stages()),
		FailurePolicy: g.FailurePolicy().String(),
		RequiredCaps:  g.RequiredCaps().String(),
		Group:         gateGroup(g.ID()),
	}
	if d, ok := g.(contracts.GateDeclarer); ok {
		decl := d.Declare()
		info.Reads = dataFieldNames(decl.Reads)
		info.Writes = dataFieldNames(decl.Writes)
		info.After = append([]string(nil), decl.After...)
		sort.Strings(info.After)
	}
	return info
}

// dataFieldNames renders a data-field slice as sorted strings.
func dataFieldNames(fields []contracts.DataField) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, string(f))
	}
	sort.Strings(out)
	return out
}

// gateGroup maps a gate id to the feature group whose switch governs it. It
// mirrors the composition root's registration grouping so `gate list` can explain
// WHY a gate does not appear (its group or per-gate switch is off).
func gateGroup(id string) string {
	switch id {
	case "logger":
		return "logger"
	case "token":
		return "token"
	case "memory-retriever", "memory-writer":
		return "memory"
	case "credential-masker", "pii-masker", "injection-guard", "ssrf-guard", "rate-limit":
		return "security"
	default:
		return "unknown"
	}
}
