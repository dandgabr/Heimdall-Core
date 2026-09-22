package i18n

import (
	"strings"
	"testing"
)

// This file is measurement-only: it benchmarks RedactString, which runs on every
// log record and every API error. No production code is touched.
//
//	go test ./internal/i18n -bench . -benchmem -count=5

// fillerLine is one realistic structured log line with NO secret in it. Every
// field name is deliberately outside secretFieldNames and there is no 32+ hex
// run, so RedactString must return it unchanged (the "all rules scanned, nothing
// matched" path).
const fillerLine = `2026-09-22T12:00:00.000Z level=info msg="request completed" ` +
	`route=/v1/chat/completions model=gpt-4o-mini status=200 upstream_ms=142 ` +
	`downstream_ms=3 bytes_out=5120 client=loopback provider=openai-compat` + "\n"

// secretBlock is a log fragment carrying several DIFFERENT secret shapes, so the
// first pass matches early and all ten replacement rules then run over the whole
// string.
const secretBlock = `Authorization: Bearer sk-live-Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWY ` +
	`token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U ` +
	`{"refresh_token":"rt_0123456789abcdef0123456789abcdef","state":"QwErTyUiOpAsDfGh"} ` +
	`code=4/0AeanS0bXYZabcdefghijklmnop password=correct-horse-battery-staple ` +
	`Cookie: session=abc123def456` + "\n"

// padTo builds a string of roughly size bytes by repeating line and truncating.
func padTo(line string, size int) string {
	if size <= len(line) {
		return line[:size]
	}
	reps := size/len(line) + 1
	return strings.Repeat(line, reps)[:size]
}

// withTail appends the secret block to filler sized so the result is ~size bytes.
func withTail(block string, size int) string {
	if size <= len(block) {
		return block[:size] // never truncated in the sizes used below
	}
	return padTo(fillerLine, size-len(block)) + block
}

func BenchmarkRedactString(b *testing.B) {
	cases := []struct {
		name string
		in   string
	}{
		{"clean_1KiB", padTo(fillerLine, 1<<10)},
		{"clean_8KiB", padTo(fillerLine, 8<<10)},
		{"secrets_1KiB", withTail(secretBlock, 1<<10)},
		{"secrets_8KiB", withTail(secretBlock, 8<<10)},
		{"many_rules_1KiB", padTo(secretBlock, 1<<10)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.in)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = RedactString(tc.in)
			}
		})
	}
}
