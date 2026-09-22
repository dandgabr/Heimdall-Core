package translators

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file is the golden runner. It discovers every envelope under
// testdata/<translator>/<direction>/, runs the named translator and compares the
// compacted expected vs produced JSON byte for byte.
//
// To add a case: create a new .json file in the right directory (the naming
// convention is documented in the package comment). No code change is needed —
// the runner walks the tree. Comparison is on COMPACTED bytes, so the envelope
// itself may be pretty-printed.

// goldenEnvelope is the on-disk fixture format.
type goldenEnvelope struct {
	// Model is passed to the translator verbatim (Request and Response* all
	// take it, because some providers omit or restructure the model).
	Model string `json:"model"`
	// Stream is passed only to the Request direction.
	Stream bool `json:"stream"`
	// Input is the raw translator input (canonical JSON for Request, provider
	// payload for ResponseFull/ResponseChunk).
	Input json.RawMessage `json:"input"`
	// Expected is the exact translator output.
	Expected json.RawMessage `json:"expected"`
}

// translatorFor resolves a (translator name, direction) pair to the concrete
// translator under test.
func translatorFor(t *testing.T, name string) contracts.Translator {
	t.Helper()
	switch name {
	case "openai":
		return Identity{}
	case "anthropic":
		return AnthropicToOpenAI{}
	case "gemini":
		return GeminiToOpenAI{}
	default:
		t.Fatalf("unknown translator %q", name)
		return nil
	}
}

func TestGoldenFiles(t *testing.T) {
	root := "testdata"
	translatorDirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	total := 0
	for _, td := range translatorDirs {
		if !td.IsDir() {
			continue
		}
		translatorName := td.Name()
		translator := translatorFor(t, translatorName)

		for _, dir := range []string{"request", "response_full", "response_chunk"} {
			dirPath := filepath.Join(root, translatorName, dir)
			entries, err := os.ReadDir(dirPath)
			if err != nil {
				continue // no cases for this (translator, direction)
			}
			for _, e := range entries {
				if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
					continue
				}
				total++
				casePath := filepath.Join(dirPath, e.Name())
				t.Run(translatorName+"/"+dir+"/"+e.Name(), func(t *testing.T) {
					runGolden(t, translator, dir, casePath)
				})
			}
		}
	}
	if total == 0 {
		t.Fatal("no golden files discovered; the runner would pass vacuously")
	}
}

func runGolden(t *testing.T, translator contracts.Translator, direction, path string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	var env goldenEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode golden %s: %v", path, err)
	}

	var got []byte
	switch direction {
	case "request":
		got, err = translator.Request(env.Input, env.Model, env.Stream)
	case "response_full":
		got, err = translator.ResponseFull(env.Input, env.Model)
	case "response_chunk":
		got, err = translator.ResponseChunk(env.Input, env.Model)
	}
	if err != nil {
		t.Fatalf("%s: translator returned %v", path, err)
	}

	want := compact(t, env.Expected)
	gotCompact := compact(t, json.RawMessage(got))
	if !bytes.Equal(want, gotCompact) {
		t.Fatalf("%s mismatch\n want: %s\n  got: %s", path, want, gotCompact)
	}
}

// compact re-marshals raw into compact, deterministically-ordered JSON so the
// comparison is insensitive to the file's pretty-printing. An empty/nil expected
// is represented as the JSON literal null so a "nothing to emit" case is
// expressible.
func compact(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	if isJSONNull(raw) {
		return []byte("null")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("compact: invalid JSON %s: %v", raw, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("compact marshal: %v", err)
	}
	return out
}
