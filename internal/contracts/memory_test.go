package contracts

import "testing"

// TestMemoryProvenanceString pins the wire label of every provenance value,
// including the unknown fallback (a persisted row with a corrupt value must
// render a stable label, never panic).
func TestMemoryProvenanceString(t *testing.T) {
	cases := []struct {
		p    MemoryProvenance
		want string
	}{
		{SourceUser, "user"},
		{SourceAssistant, "assistant"},
		{SourceSystem, "system"},
		{MemoryProvenance(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("MemoryProvenance(%d).String() = %q, want %q", tc.p, got, tc.want)
		}
	}
}
