package obfuscate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file is the golden runner. It discovers every envelope under
// testdata/<direction>/, runs the named operation and compares the compacted
// expected vs produced result.
//
// To add a case: create a new .json file in the right directory. No code change
// is needed — the runner walks the tree. Comparison is on COMPACTED bytes, so
// the envelope itself may be pretty-printed.
//
// Directions:
//
//	apply     -> Apply(descriptor, input)                == expected
//	cloak     -> CloakTools(descriptor, input)           == expected + expected_map
//	uncloak   -> UncloakToolName per names               == expected_names
//	useragent -> UserAgent(descriptor)                   == expected_user_agent
//	project   -> SyntheticProject(seed)                  == expected_project

// goldenEnvelope is the on-disk fixture format.
type goldenEnvelope struct {
	Descriptor *contracts.ProviderDescriptor `json:"descriptor,omitempty"`
	Input      json.RawMessage               `json:"input,omitempty"`
	Unmap      map[string]string             `json:"unmap,omitempty"`
	Names      []string                      `json:"names,omitempty"`
	Seed       string                        `json:"seed,omitempty"`

	Expected          json.RawMessage   `json:"expected,omitempty"`
	ExpectedMap       map[string]string `json:"expected_map,omitempty"`
	ExpectedNames     []string          `json:"expected_names,omitempty"`
	ExpectedUserAgent string            `json:"expected_user_agent,omitempty"`
	ExpectedProject   string            `json:"expected_project,omitempty"`
}

func TestGoldenFiles(t *testing.T) {
	root := "testdata"
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	total := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dirPath := filepath.Join(root, d.Name())
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			t.Fatalf("read %s: %v", dirPath, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			total++
			casePath := filepath.Join(dirPath, e.Name())
			t.Run(d.Name()+"/"+e.Name(), func(t *testing.T) {
				runGolden(t, d.Name(), casePath)
			})
		}
	}
	if total == 0 {
		t.Fatal("no golden files discovered; the runner would pass vacuously")
	}
}

func runGolden(t *testing.T, direction, path string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	var env goldenEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode golden %s: %v", path, err)
	}

	switch direction {
	case "apply":
		got, err := Apply(descFor(t, env), env.Input)
		if err != nil {
			t.Fatalf("%s: Apply returned %v", path, err)
		}
		assertJSONEqual(t, path, env.Expected, got)

	case "cloak":
		got, unmap, err := CloakTools(descFor(t, env), env.Input)
		if err != nil {
			t.Fatalf("%s: CloakTools returned %v", path, err)
		}
		assertJSONEqual(t, path, env.Expected, got)
		assertMapEqual(t, path, env.ExpectedMap, unmap)

	case "uncloak":
		got := make([]string, 0, len(env.Names))
		for _, n := range env.Names {
			got = append(got, UncloakToolName(env.Unmap, n))
		}
		if !equalStrings(got, env.ExpectedNames) {
			t.Fatalf("%s: uncloak = %v, want %v", path, got, env.ExpectedNames)
		}

	case "useragent":
		if got := UserAgent(descFor(t, env)); got != env.ExpectedUserAgent {
			t.Fatalf("%s: UserAgent = %q, want %q", path, got, env.ExpectedUserAgent)
		}

	case "project":
		if got := SyntheticProject(env.Seed); got != env.ExpectedProject {
			t.Fatalf("%s: SyntheticProject(%q) = %q, want %q", path, env.Seed, got, env.ExpectedProject)
		}

	default:
		t.Fatalf("unknown golden direction %q", direction)
	}
}

func descFor(t *testing.T, env goldenEnvelope) contracts.ProviderDescriptor {
	t.Helper()
	if env.Descriptor == nil {
		t.Fatalf("golden case has no descriptor")
	}
	return *env.Descriptor
}

func assertJSONEqual(t *testing.T, path string, want, got json.RawMessage) {
	t.Helper()
	w := compact(t, path, want)
	g := compact(t, path, json.RawMessage(got))
	if !bytes.Equal(w, g) {
		t.Fatalf("%s mismatch\n want: %s\n  got: %s", path, w, g)
	}
}

func assertMapEqual(t *testing.T, path string, want, got map[string]string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s map len = %d, want %d (%v vs %v)", path, len(got), len(want), got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s map[%q] = %q, want %q", path, k, got[k], v)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// compact re-marshals raw into compact, deterministically-ordered JSON so the
// comparison is insensitive to the file's pretty-printing. An empty/nil expected
// is represented as the JSON literal null.
func compact(t *testing.T, path string, raw json.RawMessage) []byte {
	t.Helper()
	if isJSONNull(raw) {
		return []byte("null")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("compact %s: invalid JSON %s: %v", path, raw, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("compact %s: %v", path, err)
	}
	return out
}
