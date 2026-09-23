package memory

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLastUserTextExtraction pins the query/content derivation.
func TestLastUserTextExtraction(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"last user wins", `{"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"reply"},{"role":"user","content":"second"}]}`, "second"},
		{"no user", `{"messages":[{"role":"system","content":"sys"},{"role":"assistant","content":"r"}]}`, ""},
		{"no messages", `{"model":"m"}`, ""},
		{"empty array", `{"messages":[]}`, ""},
		{"not json", `zzz`, ""},
		{"empty", ``, ""},
		{"multipart", `{"messages":[{"role":"user","content":[{"type":"text","text":"part one"},{"type":"image_url","image_url":{"url":"https://x"}},{"type":"text","text":"part two"}]}]}`, "part one\npart two"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastUserText([]byte(tc.body), 1024); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTruncateTextRuneBoundary proves the truncation never splits a rune.
func TestTruncateTextRuneBoundary(t *testing.T) {
	s := "ééééé" // 10 bytes, 5 runes
	got := truncateText(s, 5)
	if !strings.HasSuffix(got, "é") {
		t.Fatalf("cut %q splits the trailing rune", got)
	}
	if len(got) > 5 {
		t.Fatalf("cut %q exceeds max", got)
	}
	if truncateText(s, 0) != "" {
		t.Fatal("max 0 must yield empty")
	}
	if truncateText("abc", 10) != "abc" {
		t.Fatal("short input must pass through")
	}
}

// TestInjectMessagesAppendSplice pins the byte-faithful array append.
func TestInjectMessagesAppendSplice(t *testing.T) {
	msg := []byte(`{"role":"user","content":"[memory]"}`)

	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{
			name:    "messages first, tail after",
			body:    `{"messages":[{"role":"user","content":"hi"}],"stream":true}`,
			wantSub: `{"messages":[{"role":"user","content":"hi"},{"role":"user","content":"[memory]"}],"stream":true}`,
		},
		{
			name:    "messages last",
			body:    `{"stream":true,"messages":[{"role":"user","content":"hi"}]}`,
			wantSub: `{"stream":true,"messages":[{"role":"user","content":"hi"},{"role":"user","content":"[memory]"}]}`,
		},
		{
			name:    "empty array",
			body:    `{"messages":[]}`,
			wantSub: `{"messages":[{"role":"user","content":"[memory]"}]}`,
		},
		{
			name:    "pretty printed",
			body:    "{\n  \"messages\": [\n    {\"role\": \"user\", \"content\": \"hi\"}\n  ]\n}",
			wantSub: `,{"role":"user","content":"[memory]"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := injectMessagesAppend([]byte(tc.body), msg)
			if !ok {
				t.Fatal("inject failed")
			}
			if !json.Valid(out) {
				t.Fatalf("splice produced invalid JSON: %s", out)
			}
			if !strings.Contains(string(out), tc.wantSub) {
				t.Fatalf("out = %s\nwant sub = %s", out, tc.wantSub)
			}
			// The untouched bytes survive verbatim (whitespace included).
			for _, original := range []string{"\"hi\"", "\"stream\":true"} {
				if strings.Contains(tc.body, original) && !strings.Contains(string(out), original) {
					t.Fatalf("original byte %s damaged: %s", original, out)
				}
			}
		})
	}

	// No messages array: refuse to inject.
	if _, ok := injectMessagesAppend([]byte(`{"model":"m"}`), msg); ok {
		t.Fatal("a body without messages must not be modified")
	}
	// Escaped quotes inside strings must not confuse the scanner.
	body := `{"messages":[{"role":"user","content":"say \"messages\": [ ] aloud"}]}`
	out, ok := injectMessagesAppend([]byte(body), msg)
	if !ok {
		t.Fatal("escaped content must not break the splice")
	}
	if !json.Valid(out) {
		t.Fatalf("invalid JSON after splice: %s", out)
	}
}

// TestFindTopLevelArraySkipsNestedAndStrings pins the scanner's depth and
// string rules.
func TestFindTopLevelArraySkipsNestedAndStrings(t *testing.T) {
	if _, _, ok := findTopLevelArray([]byte(`{"tools":[{"messages":[1]}]}`), "messages"); ok {
		t.Fatal("a nested messages key must not match")
	}
	if _, _, ok := findTopLevelArray([]byte(`{"system":"the messages: are here","messages":[{"role":"user"}]}`), "messages"); !ok {
		t.Fatal("a messages-like string must not block the real key")
	}
	if _, _, ok := findTopLevelArray([]byte(`{"messages": "not an array"}`), "messages"); ok {
		t.Fatal("a non-array messages value must not match")
	}
	if _, _, ok := findTopLevelArray([]byte(`{"unrelated": true}`), "messages"); ok {
		t.Fatal("an absent key must not match")
	}
}

// TestLastUserTextDegenerateContent covers the content shapes that yield no
// text: a message without a content key and an object content body.
func TestLastUserTextDegenerateContent(t *testing.T) {
	if got := lastUserText([]byte(`{"messages":[{"role":"user"}]}`), 64); got != "" {
		t.Fatalf("missing content key: %q", got)
	}
	if got := lastUserText([]byte(`{"messages":[{"role":"user","content":{"url":"https://x"}}]}`), 64); got != "" {
		t.Fatalf("object content: %q", got)
	}
}

// TestInjectMalformedBodyFailsSafe pins the byte-scanner's behaviour on
// non-JSON input (only reachable through direct calls): no injection, no
// panic, ok=false.
func TestInjectMalformedBodyFailsSafe(t *testing.T) {
	msg := []byte(`{"role":"user","content":"x"}`)
	for _, body := range []string{
		`{"messages":[`,           // unterminated array
		`{"messages": ["abc`,      // unterminated string inside the array
		`{"messages" :`,           // key matched, value missing
		`{"messages" : "scalar"}`, // matched key with a non-array value
	} {
		if _, ok := injectMessagesAppend([]byte(body), msg); ok {
			t.Fatalf("malformed body %q must not inject", body)
		}
	}
	// Whitespace between the key and the colon is legal JSON and must match.
	out, ok := injectMessagesAppend([]byte(`{"messages" :[]}`), msg)
	if !ok || !json.Valid(out) {
		t.Fatalf("spaced colon: ok=%v out=%s", ok, out)
	}
}

// TestBuildMemoryMessageEmptyHits covers the empty-hit guard directly (the
// retriever cannot reach it: it filters empty hit lists first).
func TestBuildMemoryMessageEmptyHits(t *testing.T) {
	if msg, ok := buildMemoryMessage(nil); ok || msg != nil {
		t.Fatalf("empty hits: msg=%s ok=%v", msg, ok)
	}
}
