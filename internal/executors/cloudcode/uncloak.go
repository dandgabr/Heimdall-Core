package cloudcode

import (
	"encoding/json"

	"github.com/dandgabr/heimdall-core/internal/obfuscate"
)

// uncloakToolNames reverts cloaked tool names in a canonical response body or
// chunk. It walks the OpenAI-shaped structures that carry a tool name —
// choices[].message.tool_calls[] and choices[].delta.tool_calls[] — applying the
// pure obfuscate.UncloakToolName to each. Unknown names (decoys, native names)
// are returned unchanged, so it is safe to run on every frame, including
// parallel tool calls.
func uncloakToolNames(canonical []byte, toolMap map[string]string) ([]byte, error) {
	if len(toolMap) == 0 || len(canonical) == 0 {
		return canonical, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &root); err != nil {
		return nil, err
	}
	rawChoices, ok := root["choices"]
	if !ok {
		return canonical, nil
	}
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(rawChoices, &choices); err != nil {
		return nil, err
	}

	changed := false
	for _, choice := range choices {
		for _, key := range []string{"message", "delta"} {
			rawMsg, ok := choice[key]
			if !ok {
				continue
			}
			var msg map[string]json.RawMessage
			if err := json.Unmarshal(rawMsg, &msg); err != nil {
				continue
			}
			rawCalls, ok := msg["tool_calls"]
			if !ok {
				continue
			}
			var calls []map[string]json.RawMessage
			if err := json.Unmarshal(rawCalls, &calls); err != nil {
				continue
			}
			callsChanged := false
			for _, call := range calls {
				if uncloakFunction(call, toolMap) {
					callsChanged = true
				}
			}
			if callsChanged {
				msg["tool_calls"], _ = json.Marshal(calls)
				choice[key], _ = json.Marshal(msg)
				changed = true
			}
		}
	}
	if !changed {
		return canonical, nil
	}
	// Write the mutated choices slice back into root: mutating the decoded slice
	// does NOT change root["choices"], which still holds the original bytes.
	reencoded, err := jsonMarshal(choices)
	if err != nil {
		return nil, err
	}
	root["choices"] = reencoded
	out, err := jsonMarshal(root)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// uncloakFunction reverts the name inside a tool_call's function sub-object. It
// reports whether the name changed.
func uncloakFunction(call map[string]json.RawMessage, toolMap map[string]string) bool {
	rawFn, ok := call["function"]
	if !ok {
		return false
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(rawFn, &fn); err != nil {
		return false
	}
	rawName, ok := fn["name"]
	if !ok {
		return false
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil {
		return false
	}
	original := obfuscate.UncloakToolName(toolMap, name)
	if original == name {
		return false
	}
	fn["name"], _ = json.Marshal(original)
	call["function"], _ = json.Marshal(fn)
	return true
}
