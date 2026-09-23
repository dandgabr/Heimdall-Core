package contracts

import "testing"

// TestIsSSEDone pins the shared sentinel check: exact, whitespace-tolerant, and
// never true for ordinary payloads.
func TestIsSSEDone(t *testing.T) {
	yes := [][]byte{
		[]byte("[DONE]"),
		[]byte(" [DONE]"),
		[]byte("[DONE] "),
		[]byte("  [DONE]  "),
		[]byte("\t[DONE]\n"),
	}
	for _, in := range yes {
		if !IsSSEDone(in) {
			t.Errorf("IsSSEDone(%q) = false, want true", in)
		}
	}
	no := [][]byte{
		nil,
		[]byte{},
		[]byte("done"),
		[]byte("[DONE"),
		[]byte("DONE]"),
		[]byte(`{"choices":[]}`),
		[]byte("[DONE]\nmore"),
	}
	for _, in := range no {
		if IsSSEDone(in) {
			t.Errorf("IsSSEDone(%q) = true, want false", in)
		}
	}
	if string(SSEDone) != "[DONE]" {
		t.Errorf("SSEDone = %q", SSEDone)
	}
}
