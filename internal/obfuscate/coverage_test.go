package obfuscate

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file drives the branches that are otherwise unreachable: the
// json.Marshal failure paths (via the marshalJSON seam) and the remaining
// openAIFunction misses. It swaps the seam with defer-restore so the test is
// isolated and the package has no cross-test mutable state.

// failingMarshal replaces marshalJSON so the Nth call returns an error.
func failingMarshal(t *testing.T, failOn int) {
	t.Helper()
	orig := marshalJSON
	calls := 0
	marshalJSON = func(v any) ([]byte, error) {
		calls++
		if calls == failOn {
			return nil, errors.New("injected marshal failure")
		}
		return orig(v)
	}
	t.Cleanup(func() { marshalJSON = orig })
}

var rewriteDesc = contracts.ProviderDescriptor{
	Obfuscation: contracts.Obfuscation{
		PromptRewrites: []contracts.PromptRewrite{{From: "a", To: "b"}},
		ToolCloaking:   &contracts.ToolCloaking{NameSuffix: "_x"},
	},
}

// TestApplyMarshalFailures covers each marshal error branch of Apply. The call
// order for a string body is: rewriteContent marshal(1st), rewriteMessages
// marshal(2nd), Apply body marshal(3rd).
func TestApplyMarshalFailures(t *testing.T) {
	stringBody := []byte(`{"messages":[{"role":"system","content":"a"}]}`)
	partsBody := []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"a"}]}]}`)

	t.Run("string content", func(t *testing.T) {
		failingMarshal(t, 1)
		if _, err := Apply(rewriteDesc, stringBody); err == nil {
			t.Fatal("string content marshal failure not surfaced")
		}
	})
	t.Run("parts content", func(t *testing.T) {
		// Parts path: marshal(part text)=1st (ignored), marshal(parts)=2nd.
		failingMarshal(t, 2)
		if _, err := Apply(rewriteDesc, partsBody); err == nil {
			t.Fatal("parts marshal failure not surfaced")
		}
	})
	t.Run("messages", func(t *testing.T) {
		failingMarshal(t, 2)
		if _, err := Apply(rewriteDesc, stringBody); err == nil {
			t.Fatal("messages marshal failure not surfaced")
		}
	})
	t.Run("body", func(t *testing.T) {
		failingMarshal(t, 3)
		if _, err := Apply(rewriteDesc, stringBody); err == nil {
			t.Fatal("body marshal failure not surfaced")
		}
	})
}

// TestCloakToolsMarshalFailures covers the declarations, decoys, history and body
// marshal error branches. For a tools-only body the order is declarations(1st),
// body(2nd); for a history-only body it is history(1st), body(2nd).
func TestCloakToolsMarshalFailures(t *testing.T) {
	withTools := []byte(`{"tools":[{"type":"function","function":{"name":"t"}}]}`)
	withHistory := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"c","function":{"name":"t"}}]}]}`)
	decoysOnly := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			ToolCloaking: &contracts.ToolCloaking{
				NameSuffix: "_x",
				DecoyTools: []contracts.ToolDecoy{{Name: "d"}},
			},
		},
	}

	t.Run("declarations", func(t *testing.T) {
		failingMarshal(t, 1)
		if _, _, err := CloakTools(rewriteDesc, withTools); err == nil {
			t.Fatal("declarations marshal failure not surfaced")
		}
	})
	t.Run("tools body", func(t *testing.T) {
		failingMarshal(t, 2)
		if _, _, err := CloakTools(rewriteDesc, withTools); err == nil {
			t.Fatal("tools body marshal failure not surfaced")
		}
	})
	t.Run("decoys", func(t *testing.T) {
		failingMarshal(t, 1)
		if _, _, err := CloakTools(decoysOnly, []byte(`{"messages":[]}`)); err == nil {
			t.Fatal("decoy marshal failure not surfaced")
		}
	})
	t.Run("history", func(t *testing.T) {
		failingMarshal(t, 1)
		if _, _, err := CloakTools(rewriteDesc, withHistory); err == nil {
			t.Fatal("history marshal failure not surfaced")
		}
	})
}

// TestApplyInvalidContentStrings covers the invalid-JSON branches of
// rewriteContent for both the string and the parts shapes.
func TestApplyInvalidContentStrings(t *testing.T) {
	// A content that begins with a quote but is not a valid JSON string.
	invalidString := []byte(`{"messages":[{"role":"system","content":"unterminated}]}`)
	if _, err := Apply(rewriteDesc, invalidString); err == nil {
		t.Fatal("invalid system content string accepted")
	}
	// A content that begins with '[' but is not a valid array.
	invalidParts := []byte(`{"messages":[{"role":"system","content":[not json]}]}`)
	if _, err := Apply(rewriteDesc, invalidParts); err == nil {
		t.Fatal("invalid system content parts accepted")
	}
}

// TestApplySkipsMessageWithoutContent covers rewriteMessages' content-missing
// continue.
func TestApplySkipsMessageWithoutContent(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system"},{"role":"system","content":"a"}]}`)
	got, err := Apply(rewriteDesc, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !containsBytes(got, []byte(`"b"`)) {
		t.Fatalf("second system message not rewritten: %s", got)
	}
}

// TestApplyInvalidRegexInsideParts covers rewriteText's error propagation from
// the content-parts path.
func TestApplyInvalidRegexInsideParts(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "([", To: "x", IsRegex: true}},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"anything"}]}]}`)
	if _, err := Apply(desc, body); err == nil {
		t.Fatal("invalid regex inside parts not surfaced")
	}
}

// TestOpenAIFunctionMisses covers the three openAIFunction false branches:
// no function key, malformed function, no name key.
func TestOpenAIFunctionMisses(t *testing.T) {
	cases := []string{
		`{"type":"retrieval"}`,
		`{"function":"not-an-object"}`,
		`{"function":{"description":"no name"}}`,
	}
	for _, raw := range cases {
		var container map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &container); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if _, _, ok := openAIFunction(container); ok {
			t.Errorf("openAIFunction(%s) = ok, want false", raw)
		}
	}
}

// TestCloakToolsHistoryNonFunctionAndNonStringName covers cloakHistory's
// continue branches: a tool_call without a function, and one whose name is not
// a string, must be skipped without erroring.
func TestCloakToolsHistoryNonFunctionAndNonStringName(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"c"},{"function":{"name":5}},{"function":{"name":"real"}}]}]}`)
	got, unmap, err := CloakTools(rewriteDesc, body)
	if err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
	if unmap["real_x"] != "real" {
		t.Fatalf("valid call not cloaked: %v", unmap)
	}
	if len(unmap) != 1 {
		t.Fatalf("unmap = %v, want only real_x", unmap)
	}
	if got == nil {
		t.Fatal("nil body")
	}
}

// TestCloakToolsHistoryMalformedJSONArray covers the unmarshal-error continue in
// cloakHistory (a tool_calls value that is not an array).
func TestCloakToolsHistoryMalformedJSONArray(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":"not-an-array"},{"role":"user","content":"x"}]}`)
	if _, _, err := CloakTools(rewriteDesc, body); err != nil {
		t.Fatalf("CloakTools: %v", err)
	}
}

// TestApplyPartsNonStringText covers the continue where a text part is not a
// string, and the continue where a text part has no "text" key.
func TestApplyPartsNonStringText(t *testing.T) {
	desc := contracts.ProviderDescriptor{
		Obfuscation: contracts.Obfuscation{
			PromptRewrites: []contracts.PromptRewrite{{From: "a", To: "b"}},
		},
	}
	body := []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":5},{"type":"text"},{"type":"image_url"},{"type":"text","text":"a"}]}]}`)
	got, err := Apply(desc, body)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The string part must still have been rewritten.
	if !containsBytes(got, []byte(`"b"`)) {
		t.Fatalf("string text not rewritten: %s", got)
	}
}

// TestTrimSpaceWhitespace covers trimSpace's leading and trailing loops.
func TestTrimSpaceWhitespace(t *testing.T) {
	if got := string(trimSpace([]byte("  \t\n x \r\n "))); got != "x" {
		t.Errorf("trimSpace = %q", got)
	}
	if got := trimSpace([]byte("   ")); len(got) != 0 {
		t.Errorf("all-space = %q", got)
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
