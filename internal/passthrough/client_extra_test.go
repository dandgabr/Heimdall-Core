package passthrough

import "testing"

// TestHostOfParseError covers hostOf's parse-failure branch: a malformed URL
// yields "", which IsLoopbackLiteral rejects, so the loopback exception is never
// unlocked by a bad URL.
func TestHostOfParseError(t *testing.T) {
	if got := hostOf("http://exa mple.test/v1"); got != "" {
		t.Fatalf("hostOf(malformed) = %q, want empty", got)
	}
	// A well-formed URL still yields the hostname, including a port-bearing host.
	if got := hostOf("https://api.example.com:8443/v1"); got != "api.example.com" {
		t.Fatalf("hostOf(valid) = %q, want api.example.com", got)
	}
}
