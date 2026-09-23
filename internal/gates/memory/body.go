package memory

import (
	"encoding/json"
	"unicode/utf8"
)

// This file holds the two byte-faithful body helpers both gates share: the
// extraction of the last user turn (READ path, plain decoding) and the
// append-into-messages splice (WRITE path, byte-level so the rest of the body
// survives untouched — provider extensions, key order and whitespace
// included).

// wireBody is the minimal read model of an OpenAI-compatible chat body.
type wireBody struct {
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

// lastUserText returns the text of the LAST user message, truncated to max
// bytes on a rune boundary. A body without messages, without a user turn, or
// not parseable yields "" (both gates then act as no-ops). Multi-part content
// contributes its text parts in order.
func lastUserText(body []byte, max int) string {
	if len(body) == 0 {
		return ""
	}
	var wb wireBody
	if json.Unmarshal(body, &wb) != nil {
		return ""
	}
	for i := len(wb.Messages) - 1; i >= 0; i-- {
		if wb.Messages[i].Role != "user" {
			continue
		}
		return truncateText(contentText(wb.Messages[i].Content), max)
	}
	return ""
}

// contentText decodes one message content: either a plain JSON string or an
// array of parts whose "text" fields are concatenated with newlines.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		out := ""
		for i, p := range parts {
			if p.Text == "" {
				continue
			}
			if i > 0 && out != "" {
				out += "\n"
			}
			out += p.Text
		}
		return out
	}
	return ""
}

// truncateText cuts s to at most max BYTES without splitting a UTF-8 rune
// (backs off up to three bytes when the cut lands mid-rune).
func truncateText(s string, max int) string {
	if max <= 0 {
		return "" // a zero budget carries no content
	}
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// injectMessagesAppend appends msg (one JSON object) into the TOP-LEVEL
// "messages" array of a valid JSON body, byte-splicing so everything else in
// the body — key order, whitespace, provider extensions — survives verbatim.
// ok is false when the body has no top-level messages array to append to.
//
// The splice cannot produce invalid JSON: body is valid (the boundary parses
// it before the gates), msg is a marshalled object, and the array boundary is
// found by a string-aware bracket walk. The invariant is pinned by tests.
func injectMessagesAppend(body, msg []byte) ([]byte, bool) {
	open, close, ok := findTopLevelArray(body, "messages")
	if !ok {
		return nil, false
	}
	// Empty-array detection: every byte strictly between the brackets is
	// whitespace.
	j := open + 1
	for j < close && isSpaceByte(body[j]) {
		j++
	}
	empty := j == close
	out := make([]byte, 0, len(body)+1+len(msg))
	out = append(out, body[:close]...) // up to, but excluding, the ']'
	if !empty {
		out = append(out, ',')
	}
	out = append(out, msg...)
	out = append(out, body[close:]...) // the ']' and everything after, verbatim
	return out, true
}

// findTopLevelArray locates the value array of a TOP-LEVEL key of the root
// object, returning the indexes of '[' and ']'. String contents are skipped,
// so a `"name":` inside prompt text can never match; nested keys (inside the
// messages themselves, or a tool schema) live at a deeper depth and are never
// considered.
func findTopLevelArray(body []byte, name string) (open, close int, ok bool) {
	depth := 0
	i := 0
	for i < len(body) {
		c := body[i]
		switch {
		case c == '"':
			end := scanStringEnd(body, i)
			// A KEY of the ROOT object: with depth counting braces, top-level
			// keys sit at depth 1 (the opening '{' raised it).
			if depth == 1 && string(body[i+1:end-1]) == name {
				k := end
				for k < len(body) && isSpaceByte(body[k]) {
					k++
				}
				if k < len(body) && body[k] == ':' {
					m := k + 1
					for m < len(body) && isSpaceByte(body[m]) {
						m++
					}
					if m < len(body) && body[m] == '[' {
						e, found := matchBracket(body, m)
						if found {
							return m, e, true
						}
					}
					return 0, 0, false // "name" is not followed by an array
				}
			}
			i = end
		case c == '{' || c == '[':
			depth++
			i++
		case c == '}' || c == ']':
			depth--
			i++
		default:
			i++
		}
	}
	return 0, 0, false
}

// matchBracket returns the index of the ']' matching the '[' at open, skipping
// string contents and nested brackets.
func matchBracket(body []byte, open int) (int, bool) {
	depth := 0
	i := open
	for i < len(body) {
		switch body[i] {
		case '"':
			i = scanStringEnd(body, i)
			continue
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i, true
			}
		}
		i++
	}
	return 0, false
}

// scanStringEnd returns the index just past the closing quote of the string
// that opens at open. For a valid JSON body the closing quote always exists.
func scanStringEnd(body []byte, open int) int {
	j := open + 1
	for j < len(body) {
		if body[j] == '\\' {
			j += 2
			continue
		}
		if body[j] == '"' {
			return j + 1
		}
		j++
	}
	return len(body)
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
