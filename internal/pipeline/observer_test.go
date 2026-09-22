package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/gates"
)

var errBoom = errors.New("gate boom")

func TestNewObserverRejectsNilChain(t *testing.T) {
	if _, err := NewObserver(nil); err == nil {
		t.Fatal("nil chain accepted")
	}
}

func TestObserverRunsGatesAndNeverReadsBody(t *testing.T) {
	var records []map[string]string
	gate := gates.NewLogger(func(_ string, fields map[string]string) {
		records = append(records, fields)
	})
	chain, err := New([]contracts.Gate{gate})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	observer, err := NewObserver(chain)
	if err != nil {
		t.Fatalf("NewObserver: %v", err)
	}

	const secret = "sk-live-BODY-AND-HEADER-MUST-NOT-LEAK"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := observer.Handler(inner)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"key":"`+secret+`"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(records) == 0 {
		t.Fatal("observer did not run the gate")
	}
	for _, r := range records {
		for k, v := range r {
			if strings.Contains(v, secret) {
				t.Fatalf("observer leaked the secret in %s=%s", k, v)
			}
		}
	}
	// The header NAME must be present; the value must not.
	found := false
	for _, r := range records {
		if strings.Contains(r["header_names"], "Authorization") {
			found = true
		}
	}
	if !found {
		t.Errorf("header names not recorded: %+v", records)
	}
}

func TestObserverBlocksOnFailClosedGate(t *testing.T) {
	gate := preOnly("closed", contracts.FailClosed, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
		return contracts.Decision{}, errBoom
	})
	chain, _ := New([]contracts.Gate{gate})
	observer, _ := NewObserver(chain)

	called := false
	h := observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if called {
		t.Error("inner handler ran despite a fail-closed gate error")
	}
}

func TestObserverBlocksOnPreCommitDecision(t *testing.T) {
	for _, kind := range []contracts.DecisionKind{contracts.DecisionBlock, contracts.DecisionReroute} {
		gate := preOnly("decider", contracts.FailOpen, func(_ context.Context, _ contracts.GateInput) (contracts.Decision, error) {
			d := contracts.Decision{Kind: kind}
			if kind == contracts.DecisionBlock {
				d.Synthetic = &contracts.SyntheticResponse{Status: 200}
			} else {
				d.Reroute = &contracts.RerouteTarget{Provider: "p"}
			}
			return d, nil
		})
		chain, _ := New([]contracts.Gate{gate})
		observer, _ := NewObserver(chain)

		called := false
		h := observer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

		if rec.Code != http.StatusForbidden {
			t.Errorf("kind %v: status = %d, want 403", kind, rec.Code)
		}
		if called {
			t.Errorf("kind %v: inner handler ran despite a pre-commit decision", kind)
		}
	}
}
