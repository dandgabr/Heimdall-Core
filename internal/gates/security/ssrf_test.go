package security

import (
	"context"
	"strings"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
	"github.com/dandgabr/heimdall-core/internal/domain"
)

// TestSSRFGuardDeniesProtectedTargets is the required assertion table: every
// ADR-SEC-05 denylist class reachable from a body URL is refused, and a
// public https URL passes.
func TestSSRFGuardDeniesProtectedTargets(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantKind contracts.DecisionKind
		wantHost string
	}{
		{"aws metadata", `{"image_url":"http://169.254.169.254/latest/meta-data"}`, contracts.DecisionBlock, "169.254.169.254"},
		{"loopback", `{"image_url":"http://127.0.0.1:8080/admin"}`, contracts.DecisionBlock, "127.0.0.1"},
		{"ipv6 loopback", `{"image_url":"http://[::1]/x"}`, contracts.DecisionBlock, "::1"},
		{"mapped metadata", `{"image_url":"https://[::ffff:169.254.169.254]/a"}`, contracts.DecisionBlock, "169.254.169.254"},
		{"private 10/8", `{"image_url":"https://10.0.0.5/x"}`, contracts.DecisionBlock, "10.0.0.5"},
		{"private 172.16/12", `{"u":"https://172.16.0.1/x"}`, contracts.DecisionBlock, "172.16.0.1"},
		{"private 192.168/16", `{"u":"https://192.168.1.1/x"}`, contracts.DecisionBlock, "192.168.1.1"},
		{"alibaba metadata", `{"u":"https://100.100.100.200/x"}`, contracts.DecisionBlock, "100.100.100.200"},
		{"aws metadata v6", `{"u":"https://[fd00:ec2::254]/x"}`, contracts.DecisionBlock, "fd00:ec2::254"},
		{"metadata hostname", `{"u":"https://metadata.google.internal/computeMetadata"}`, contracts.DecisionBlock, "metadata.google.internal"},
		{"localhost hostname", `{"u":"https://localhost/secret"}`, contracts.DecisionBlock, "localhost"},
		{"cleartext http", `{"u":"http://cdn.example.com/img.png"}`, contracts.DecisionBlock, "cdn.example.com"},
		{"userinfo leak", `{"u":"https://user:pass@example.com/img.png"}`, contracts.DecisionBlock, "example.com"},
		{"no host", `{"u":"https:///path"}`, contracts.DecisionBlock, ""},
		{"unparseable", `{"u":"https://["}`, contracts.DecisionBlock, ""},
		{"fqdn trailing dot", `{"u":"https://metadata.google.internal./x"}`, contracts.DecisionBlock, "metadata.google.internal"},
		{"public https passes", `{"image_url":"https://cdn.example.com/img.png","text":"see the docs"}`, contracts.DecisionContinue, ""},
		{"public ip passes", `{"u":"https://8.8.8.8/dns-query"}`, contracts.DecisionContinue, ""},
		{"mapped public ip passes", `{"u":"https://[::ffff:8.8.8.8]/x"}`, contracts.DecisionContinue, ""},
		{"no urls", `{"content":"plain text only"}`, contracts.DecisionContinue, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewSSRFGuard()
			meta := map[string]string{}
			dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: []byte(tc.body), Meta: meta})
			if err != nil {
				t.Fatalf("PreRequest: %v", err)
			}
			if dec.Kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", dec.Kind, tc.wantKind)
			}
			if tc.wantKind == contracts.DecisionBlock {
				if dec.Synthetic == nil || dec.Synthetic.Status != 400 {
					t.Fatalf("synthetic = %+v", dec.Synthetic)
				}
				if dec.Code != domain.CodeSecurityDestinationDenied {
					t.Fatalf("code = %s", dec.Code)
				}
				if got := dec.Params["host"]; got != tc.wantHost {
					t.Fatalf("host param = %q, want %q", got, tc.wantHost)
				}
				// No path/query ever leaves the guard.
				for _, v := range dec.Params {
					if strings.ContainsAny(v, "/?&") {
						t.Fatalf("param %q carries URL detail beyond the host", v)
					}
				}
				if meta[IDSSRFGuard+".denied"] != tc.wantHost {
					t.Fatalf("meta = %v", meta)
				}
			}
		})
	}
}

// TestSSRFGuardFirstDenialWins proves the early-exit inside the scan: with two
// refused URLs the first (host) is reported.
func TestSSRFGuardFirstDenialWins(t *testing.T) {
	g := NewSSRFGuard()
	body := []byte(`{"a":"https://10.0.0.1/first","b":"https://127.0.0.1/second"}`)
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{Body: body, Meta: map[string]string{}})
	if err != nil || dec.Kind != contracts.DecisionBlock {
		t.Fatalf("dec=%v err=%v", dec, err)
	}
	if dec.Params["host"] != "10.0.0.1" {
		t.Fatalf("host = %q, want the first denial", dec.Params["host"])
	}
}

// TestSSRFGuardFailClosedAndContract covers the invalid-body error, the
// declaration (zero edges: containment phase) and the lifecycle methods.
func TestSSRFGuardFailClosedAndContract(t *testing.T) {
	g := NewSSRFGuard()
	if _, err := g.PreRequest(context.Background(), contracts.GateInput{Body: []byte("[")}); err == nil {
		t.Fatal("invalid body: want error (FailClosed)")
	}
	dec, err := g.PreRequest(context.Background(), contracts.GateInput{})
	if err != nil || dec.Kind != contracts.DecisionContinue {
		t.Fatalf("empty: %v %v", dec, err)
	}
	if g.ID() != IDSSRFGuard {
		t.Fatalf("id = %s", g.ID())
	}
	if g.Stages() != contracts.StageSet(contracts.StagePreRequest) {
		t.Fatalf("stages = %v", g.Stages())
	}
	if g.RequiredCaps() != 0 {
		t.Fatalf("caps = %v", g.RequiredCaps())
	}
	if g.FailurePolicy() != contracts.FailClosed {
		t.Fatal("SSRF guard must be FailClosed")
	}
	if !g.NeedsBody() {
		t.Fatal("SSRF guard must declare NeedsBody")
	}
	d := g.Declare()
	if len(d.Reads) != 0 || len(d.Writes) != 0 {
		t.Fatalf("declaration = %+v, want zero edges", d)
	}
	chunk, err := g.OnResponseChunk(context.Background(), contracts.ChunkInput{})
	if err != nil || chunk.Kind != contracts.ChunkPassThrough {
		t.Fatalf("chunk: %v %v", chunk, err)
	}
	if err := g.PostResponse(context.Background(), contracts.GateInput{}); err != nil {
		t.Fatalf("post: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := trimURLPunctuation(`https://a.example/x.`); got != "https://a.example/x" {
		t.Fatalf("trimURLPunctuation = %s", got)
	}
	if got := trimURLPunctuation(`https://[::1]:8080/`); got != "https://[::1]:8080/" {
		t.Fatalf("ipv6 bracket must survive: %s", got)
	}
}

// TestURLDeniedDirectly exercises the classifier on its decision branches.
func TestURLDeniedDirectly(t *testing.T) {
	if _, reason, denied := urlDenied("http://x.example/a"); !denied || reason != deniedScheme {
		t.Fatalf("http: denied=%v reason=%v", denied, reason)
	}
	if _, reason, denied := urlDenied("https://["); !denied || reason != deniedParse {
		t.Fatalf("unparseable: denied=%v reason=%v", denied, reason)
	}
	if _, reason, denied := urlDenied("https://u:p@h.example/a"); !denied || reason != deniedUserInfo {
		t.Fatalf("userinfo: denied=%v reason=%v", denied, reason)
	}
	if _, reason, denied := urlDenied("https:///nohost"); !denied || reason != deniedHost {
		t.Fatalf("nohost: denied=%v reason=%v", denied, reason)
	}
	if _, reason, denied := urlDenied("https://localhost/x"); !denied || reason != deniedHost {
		t.Fatalf("localhost: denied=%v reason=%v", denied, reason)
	}
	if _, reason, denied := urlDenied("https://192.168.0.9/x"); !denied || reason != deniedHost {
		t.Fatalf("private ip: denied=%v reason=%v", denied, reason)
	}
	if host, reason, denied := urlDenied("https://example.com/x"); denied {
		t.Fatalf("public https must pass, got host=%q reason=%v", host, reason)
	}
	if host, reason, denied := urlDenied("https://cdn.example/x"); denied || host != "" {
		t.Fatalf("hostname allow must carry no host, got %q %v", host, reason)
	}
}
