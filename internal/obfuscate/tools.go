package obfuscate

import (
	"encoding/json"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// CloakTools renames every client tool in a canonical OpenAI-shaped request with
// desc.Obfuscation.ToolCloaking.NameSuffix and appends the DecoyTools. It returns
// the cloaked body and the map suffixed->original, which UncloakToolName uses to
// reverse a name in a response.
//
// If the descriptor declares no tool cloaking (ToolCloaking == nil), CloakTools
// returns the input unchanged and a nil map: identity, never a "just in case"
// rename. A body with no tools is likewise returned unchanged with a nil map.
//
// The rename covers the tool DECLARATIONS and the assistant tool_calls in the
// message history, so a multi-turn tool conversation stays consistent upstream.
// It does NOT touch tool_call_id (the opaque call id, which carries no brand).
func CloakTools(desc contracts.ProviderDescriptor, canonical []byte) ([]byte, map[string]string, error) {
	cloaking := desc.Obfuscation.ToolCloaking
	if cloaking == nil {
		return copyBytes(canonical), nil, nil
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &body); err != nil {
		return nil, nil, obfuscationError("invalid request body", err)
	}

	unmap := make(map[string]string)

	// 1. Rename the tool declarations and append the decoys.
	renamedTools, toolChanged, err := cloakDeclarations(body["tools"], cloaking, unmap)
	if err != nil {
		return nil, nil, err
	}
	if toolChanged {
		body["tools"] = renamedTools
	}

	// 2. Rename assistant tool_calls in the message history.
	if rawMessages, ok := body["messages"]; ok {
		renamed, histChanged, err := cloakHistory(rawMessages, unmap, cloaking)
		if err != nil {
			return nil, nil, err
		}
		if histChanged {
			body["messages"] = renamed
		}
	}

	if !toolChanged && len(unmap) == 0 {
		// Nothing was cloaked (no tools declared); stay identity.
		return copyBytes(canonical), nil, nil
	}

	out, err := marshalJSON(body)
	if err != nil {
		return nil, nil, obfuscationError("could not re-encode request body", err)
	}
	return out, unmap, nil
}

// cloakDeclarations renames the client tool names and appends the decoys. It
// records suffixed->original in unmap. The returned bool reports whether the
// tools array changed at all.
func cloakDeclarations(raw json.RawMessage, cloaking *contracts.ToolCloaking, unmap map[string]string) (json.RawMessage, bool, error) {
	if isJSONNull(raw) {
		// No tools: still inject decoys, because the provider expects its native
		// tools to be present even when the client sent none.
		if len(cloaking.DecoyTools) == 0 {
			return raw, false, nil
		}
		out, err := marshalJSON(decoyDeclarations(cloaking.DecoyTools))
		if err != nil {
			return nil, false, obfuscationError("could not encode decoy tools", err)
		}
		return out, true, nil
	}

	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		return nil, false, obfuscationError("invalid tools array", err)
	}

	changed := false
	seen := make(map[string]struct{}, len(tools)+len(cloaking.DecoyTools))
	out := make([]map[string]json.RawMessage, 0, len(tools)+len(cloaking.DecoyTools))

	for _, tool := range tools {
		name, fn, ok := openAIFunction(tool)
		if !ok {
			out = append(out, tool)
			continue
		}
		suffixed := name + cloaking.NameSuffix
		unmap[suffixed] = name
		fn["name"], _ = json.Marshal(suffixed)
		tool["function"], _ = json.Marshal(fn)
		out = append(out, tool)
		seen[suffixed] = struct{}{}
		changed = true
	}

	// Decoys follow the client tools, deduplicated by name so a client tool that
	// already collides with a decoy is not emitted twice.
	for _, decoy := range cloaking.DecoyTools {
		if _, dup := seen[decoy.Name]; dup {
			continue
		}
		out = append(out, decoyTool(decoy))
		seen[decoy.Name] = struct{}{}
		changed = true
	}

	encoded, err := marshalJSON(out)
	if err != nil {
		return nil, false, obfuscationError("could not re-encode tools", err)
	}
	return encoded, changed, nil
}

// cloakHistory renames the function name inside assistant tool_calls across the
// message history, using the same suffix rule. It records the mapping in unmap.
func cloakHistory(raw json.RawMessage, unmap map[string]string, cloaking *contracts.ToolCloaking) (json.RawMessage, bool, error) {
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &messages); err != nil {
		return nil, false, obfuscationError("invalid messages array", err)
	}

	changed := false
	for _, msg := range messages {
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
			name, fn, ok := openAIFunction(call)
			if !ok {
				continue
			}
			suffixed := name + cloaking.NameSuffix
			unmap[suffixed] = name
			fn["name"], _ = json.Marshal(suffixed)
			call["function"], _ = json.Marshal(fn)
			callsChanged = true
		}
		if callsChanged {
			msg["tool_calls"], _ = json.Marshal(calls)
			changed = true
		}
	}
	if !changed {
		return nil, false, nil
	}
	encoded, err := marshalJSON(messages)
	if err != nil {
		return nil, false, obfuscationError("could not re-encode messages", err)
	}
	return encoded, true, nil
}

// openAIFunction extracts the function object from an OpenAI tool or tool_call:
// {"type":"function","function":{...}}. It returns ok=false for any other shape
// so a non-function tool is passed through untouched.
func openAIFunction(container map[string]json.RawMessage) (name string, fn map[string]json.RawMessage, ok bool) {
	rawFn, hasFn := container["function"]
	if !hasFn {
		return "", nil, false
	}
	var fnObj map[string]json.RawMessage
	if err := json.Unmarshal(rawFn, &fnObj); err != nil {
		return "", nil, false
	}
	nameRaw, hasName := fnObj["name"]
	if !hasName {
		return "", nil, false
	}
	if err := json.Unmarshal(nameRaw, &name); err != nil {
		return "", nil, false
	}
	return name, fnObj, true
}

// decoyDeclarations renders the decoys as a full OpenAI tools array.
func decoyDeclarations(decoys []contracts.ToolDecoy) []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(decoys))
	for _, d := range decoys {
		out = append(out, decoyTool(d))
	}
	return out
}

// decoyTool renders one decoy as an OpenAI function tool with an empty object
// schema, matching the reference connector's neutral decoys.
func decoyTool(d contracts.ToolDecoy) map[string]json.RawMessage {
	fn := map[string]any{
		"name":        d.Name,
		"description": d.Description,
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
			"required":   []string{},
		},
	}
	fnJSON, _ := json.Marshal(fn)
	return map[string]json.RawMessage{
		"type":     json.RawMessage(`"function"`),
		"function": fnJSON,
	}
}

// UncloakToolName reverses a cloaked name using the map from CloakTools. It is
// total: an unknown name (a decoy, or a native name the client sent unchanged)
// is returned unchanged, never dropped. This is what makes it safe to call on
// every tool call in a response, including parallel tool calls, without knowing
// which names were cloaked.
func UncloakToolName(unmap map[string]string, name string) string {
	if unmap == nil {
		return name
	}
	if original, ok := unmap[name]; ok {
		return original
	}
	return name
}
