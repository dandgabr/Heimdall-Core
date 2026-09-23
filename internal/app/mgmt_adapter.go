package app

import (
	"context"
	"time"

	"github.com/dandgabr/heimdall-core/internal/api/mgmt"
	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/store"
)

// This file adapts the App to the management API port (internal/api/mgmt).
// It is the ONLY place the wire DTOs are populated, so the "no secret on the
// wire" guarantee has a single review point: every field assigned below comes
// from a non-secret source (metadata, counts, ids, i18n codes), and the two
// one-time reveals (rotated token, new client key) are the only fields that
// ever carry plaintext — deliberately, on responses the handler marks no-store.

// mgmtService is the adapter. It holds the App so the management surface runs
// against the same live vault, routing layer and gate chain the daemon uses.
type mgmtService struct {
	app *App
}

// NewManagementService builds the management port over the App.
func (a *App) NewManagementService() mgmt.Service {
	return &mgmtService{app: a}
}

// compile-time assertion that the adapter satisfies the port.
var _ mgmt.Service = (*mgmtService)(nil)

// Status implements mgmt.Service.
func (s *mgmtService) Status(ctx context.Context) (mgmt.StatusView, error) {
	comboList, err := s.app.Combos.List(ctx)
	if err != nil {
		return mgmt.StatusView{}, err
	}
	creds, err := s.app.Credentials.List(ctx)
	if err != nil {
		return mgmt.StatusView{}, err
	}
	keys, err := s.app.ClientKeys.List(ctx)
	if err != nil {
		return mgmt.StatusView{}, err
	}
	return mgmt.StatusView{
		Version:       s.app.version,
		UptimeSeconds: int64(time.Since(s.app.startedAt).Seconds()),
		Providers:     len(s.app.Providers.IDs()),
		Combos:        len(comboList),
		Credentials:   len(creds),
		ClientKeys:    len(keys),
		Gates:         s.effectiveGateIDs(),
	}, nil
}

// effectiveGateIDs lists the enabled gate ids in the order they were built
// (gates.Order.All is ID-sorted), never content.
func (s *mgmtService) effectiveGateIDs() []string {
	out := []string{}
	for _, g := range s.app.GateOrder.All {
		out = append(out, g.ID())
	}
	return out
}

// Providers implements mgmt.Service. The readiness rule is the SAME one the CLI
// uses (ProviderList), so GUI and CLI cannot disagree.
func (s *mgmtService) Providers(ctx context.Context) ([]mgmt.ProviderView, error) {
	list := s.app.ProviderList(ctx)
	out := make([]mgmt.ProviderView, 0, len(list))
	for _, p := range list {
		out = append(out, mgmt.ProviderView{
			ID:               string(p.ID),
			Protocol:         p.Protocol,
			AuthModes:        p.AuthModes,
			PendingEndpoints: p.PendingEndpoints,
			Ready:            p.Ready,
			ReasonCode:       p.ReasonCode,
			Future:           p.Future,
			RiskNotice:       p.RiskNotice,
		})
	}
	return out, nil
}

// ProviderTest implements mgmt.Service.
func (s *mgmtService) ProviderTest(ctx context.Context, id domain.ProviderID) (mgmt.ProviderTestView, error) {
	res, err := s.app.ProviderTest(ctx, id)
	view := mgmt.ProviderTestView{
		Provider:     string(res.Provider),
		CredentialID: string(res.CredentialID),
		Status:       res.Status,
	}
	if err != nil {
		return view, err
	}
	return view, nil
}

// Credentials implements mgmt.Service. The sealed secret is never read from the
// credential row into the view: the DTO has no field for it.
func (s *mgmtService) Credentials(ctx context.Context) ([]mgmt.CredentialView, error) {
	creds, err := s.app.Credentials.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mgmt.CredentialView, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialView(c))
	}
	return out, nil
}

// AddCredential implements mgmt.Service. The plaintext key is passed straight to
// AddAPIKey (which seals it) and is never stored in the view or an error.
func (s *mgmtService) AddCredential(ctx context.Context, req mgmt.AddCredentialRequest) (mgmt.CredentialView, error) {
	res, err := s.app.AddAPIKey(ctx, domain.ProviderID(req.Provider), req.Label, req.Key)
	if err != nil {
		return mgmt.CredentialView{}, err
	}
	return mgmt.CredentialView{
		ID:        string(res.CredentialID),
		Provider:  string(res.Provider),
		AuthMode:  contracts.AuthAPIKey.String(),
		Label:     res.Label,
		CreatedAt: rfc3339OrEmpty(res.CreatedAt),
	}, nil
}

// DeleteCredential implements mgmt.Service.
func (s *mgmtService) DeleteCredential(ctx context.Context, id domain.CredentialID) error {
	return s.app.Credentials.Delete(ctx, id)
}

// credentialView renders the NON-SECRET projection of a credential.
func credentialView(c contracts.Credential) mgmt.CredentialView {
	return mgmt.CredentialView{
		ID:        string(c.ID),
		Provider:  string(c.Provider),
		AuthMode:  c.AuthMode.String(),
		Label:     c.Label,
		CreatedAt: rfc3339OrEmpty(c.CreatedAt),
		ExpiresAt: rfc3339OrEmpty(c.ExpiresAt),
	}
}

// Combos implements mgmt.Service.
func (s *mgmtService) Combos(ctx context.Context) ([]mgmt.ComboView, error) {
	list, err := s.app.Combos.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mgmt.ComboView, 0, len(list))
	for _, c := range list {
		out = append(out, mgmt.ComboToView(c))
	}
	return out, nil
}

// CreateCombo implements mgmt.Service: it converts the wire request through the
// shared mapper, then upserts through the store's Save (which validates the DAG
// and returns the persisted, derived-depth combo).
func (s *mgmtService) CreateCombo(ctx context.Context, req mgmt.ComboRequest) (mgmt.ComboView, error) {
	combo, err := mgmt.ComboFromRequest(req)
	if err != nil {
		return mgmt.ComboView{}, err
	}
	stored, err := s.app.Combos.Save(ctx, combo)
	if err != nil {
		return mgmt.ComboView{}, err
	}
	return mgmt.ComboToView(stored), nil
}

// DeleteCombo implements mgmt.Service.
func (s *mgmtService) DeleteCombo(ctx context.Context, id domain.ComboID) error {
	return s.app.Combos.Delete(ctx, id)
}

// Quotas implements mgmt.Service. It reads the durable snapshot per credential
// (which survives a restart, ADR-0011 §4); a credential with no recorded window
// is reported with an empty window list rather than omitted, so the GUI shows
// every account.
func (s *mgmtService) Quotas(ctx context.Context) ([]mgmt.QuotaView, error) {
	creds, err := s.app.Credentials.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mgmt.QuotaView, 0, len(creds))
	for _, c := range creds {
		state, ok := s.app.QuotaRec.Snapshot(ctx, c.ID)
		view := mgmt.QuotaView{
			Credential: string(c.ID),
			Provider:   string(c.Provider),
			Windows:    []mgmt.QuotaWindowView{},
		}
		if ok {
			view.TerminalCode = state.TerminalCode
			for _, w := range state.Windows {
				view.Windows = append(view.Windows, mgmt.QuotaWindowView{
					Kind:      w.Kind.String(),
					Limit:     w.Limit,
					Used:      w.Used,
					Remaining: w.Remaining,
					ResetsAt:  rfc3339OrEmpty(w.ResetsAt),
					Source:    w.Source.String(),
				})
			}
		}
		out = append(out, view)
	}
	return out, nil
}

// Gates implements mgmt.Service: the DAG-ordered chain per stage, metadata only.
func (s *mgmtService) Gates(_ context.Context) (mgmt.GatesView, error) {
	return mgmt.GatesView{
		PreRequest:      gateViews(s.app.GateOrder.PreRequest),
		OnResponseChunk: gateViews(s.app.GateOrder.OnResponseChunk),
		PostResponse:    gateViews(s.app.GateOrder.PostResponse),
	}, nil
}

func gateViews(gates []contracts.Gate) []mgmt.GateView {
	out := []mgmt.GateView{}
	for _, g := range gates {
		out = append(out, mgmt.GateView{
			ID:            g.ID(),
			Stages:        gateStageNames(g.Stages()),
			FailurePolicy: g.FailurePolicy().String(),
			RequiredCaps:  uint64(g.RequiredCaps()),
		})
	}
	return out
}

// gateStageNames renders a gate's stage set as stable names. It is separate from
// the boot-log stageName (which renders one stage) because the API reports the
// SET per gate.
func gateStageNames(set contracts.GateStageSet) []string {
	out := []string{}
	for _, st := range []contracts.GateStage{
		contracts.StagePreRequest, contracts.StageOnResponseChunk, contracts.StagePostResponse,
	} {
		if set.Has(st) {
			out = append(out, stageName(st))
		}
	}
	return out
}

// Usage implements mgmt.Service: the aggregate over the durable attempt log.
func (s *mgmtService) Usage(ctx context.Context) (mgmt.UsageView, error) {
	total, byProvider, byCred, err := s.app.QuotaStore.AggregateUsage(ctx)
	if err != nil {
		return mgmt.UsageView{}, err
	}
	return mgmt.UsageView{
		Total:        usageView(total),
		ByProvider:   usageViews(byProvider),
		ByCredential: usageViews(byCred),
	}, nil
}

func usageView(r store.UsageRollup) mgmt.UsageAggView {
	return mgmt.UsageAggView{
		Key:        r.Key,
		Tokens:     int(r.Tokens),
		Requests:   int(r.Requests),
		CostMicros: r.CostMicros,
		Attempts:   int(r.Attempts),
	}
}

func usageViews(rows []store.UsageRollup) []mgmt.UsageAggView {
	out := make([]mgmt.UsageAggView, 0, len(rows))
	for _, r := range rows {
		out = append(out, usageView(r))
	}
	return out
}

// RotateToken implements mgmt.Service: it rotates, writes the token file and
// returns the plaintext exactly once.
func (s *mgmtService) RotateToken(_ context.Context) (mgmt.TokenRotateView, error) {
	token, path, err := s.app.RotateManagementTokenValue()
	if err != nil {
		return mgmt.TokenRotateView{}, err
	}
	return mgmt.TokenRotateView{Token: token, Path: path}, nil
}

// ClientKeys implements mgmt.Service.
func (s *mgmtService) ClientKeys(ctx context.Context) ([]mgmt.ClientKeyView, error) {
	keys, err := s.app.ListClientKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mgmt.ClientKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, mgmt.ClientKeyView{
			ID:        string(k.ID),
			Label:     k.Label,
			CreatedAt: rfc3339OrEmpty(k.CreatedAt),
			RevokedAt: rfc3339OrEmpty(k.RevokedAt),
		})
	}
	return out, nil
}

// CreateClientKey implements mgmt.Service: it issues and returns the plaintext
// exactly once.
func (s *mgmtService) CreateClientKey(ctx context.Context, label string) (mgmt.ClientKeyCreatedView, error) {
	rec, plaintext, err := s.app.CreateClientKey(ctx, label)
	if err != nil {
		return mgmt.ClientKeyCreatedView{}, err
	}
	return mgmt.ClientKeyCreatedView{
		ClientKeyView: mgmt.ClientKeyView{
			ID:        string(rec.ID),
			Label:     rec.Label,
			CreatedAt: rfc3339OrEmpty(rec.CreatedAt),
		},
		Key: plaintext,
	}, nil
}

// RevokeClientKey implements mgmt.Service.
func (s *mgmtService) RevokeClientKey(ctx context.Context, id domain.ClientID) error {
	return s.app.RevokeClientKey(ctx, id)
}

// rfc3339OrEmpty formats a timestamp, or "" for the zero time (so the GUI shows
// "unknown" rather than the year 1).
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
