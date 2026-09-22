package i18n

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// forbidden is a substring that must NOT survive redaction.
		forbidden string
	}{
		{
			name:      "bearer header",
			input:     "Authorization: Bearer sk-abcdef0123456789",
			forbidden: "sk-abcdef0123456789",
		},
		{
			name:      "openai key bare",
			input:     "using key sk-proj-AAAABBBBCCCCDDDD",
			forbidden: "sk-proj-AAAABBBBCCCCDDDD",
		},
		{
			name:      "query key",
			input:     "GET /v1?key=supersecretvalue&model=gpt",
			forbidden: "supersecretvalue",
		},
		{
			name:      "query token",
			input:     "https://x/y?access_token=abcdef123456",
			forbidden: "abcdef123456",
		},
		{
			name:      "query secret",
			input:     "https://x/y?secret=hunter2zzz",
			forbidden: "hunter2zzz",
		},
		{
			name:      "cookie header",
			input:     "Cookie: session=abcdef; theme=dark",
			forbidden: "session=abcdef",
		},
		{
			name:      "refresh token json",
			input:     `{"refresh_token":"rt_1234567890","x":1}`,
			forbidden: "rt_1234567890",
		},
		{
			name:      "json api key",
			input:     `{"api_key":"key_live_123456"}`,
			forbidden: "key_live_123456",
		},
		{
			name:      "password yaml",
			input:     "password: mypassword123",
			forbidden: "mypassword123",
		},
		{
			name:      "id token",
			input:     "id_token=eyJhbGciOiJIUzI1NiJ9.payload.sig",
			forbidden: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			// P1-4: the header rule used to stop at the first separator inside
			// a long token.
			name:      "authorization bearer 64 hex",
			input:     "Authorization: Bearer " + strings.Repeat("ab", 32),
			forbidden: strings.Repeat("ab", 32),
		},
		{
			name:      "authorization bearer long mixed",
			input:     "Authorization: Bearer eyJhbGciOi.eyJzdWIi-SFlYQ_abc/def+ghi==",
			forbidden: "eyJhbGciOi.eyJzdWIi-SFlYQ_abc/def+ghi==",
		},
		{
			// P1-4: no separator rule matched an assignment without '='/' :'.
			name:      "refresh token assignment",
			input:     "refresh_token=abcdef123456",
			forbidden: "abcdef123456",
		},
		{
			name:      "refresh token json",
			input:     `{"refresh_token":"abcdef123456"}`,
			forbidden: "abcdef123456",
		},
		{
			name:      "session cookie",
			input:     "Cookie: session=abcdef123456; theme=dark",
			forbidden: "abcdef123456",
		},
		{
			name:      "token query param",
			input:     "https://x/y?token=abcdef123456",
			forbidden: "abcdef123456",
		},
		{
			name:      "session assignment",
			input:     "session=abcdef123456",
			forbidden: "abcdef123456",
		},
		{
			// A bare 64-hex management token pasted into a log line.
			name:      "bare 64 hex token",
			input:     "token " + strings.Repeat("a1", 32),
			forbidden: strings.Repeat("a1", 32),
		},
		{
			// R1: field name + SPACE + value, no '='/':'.
			name:      "refresh token space separated",
			input:     "refresh_token abc123",
			forbidden: "abc123",
		},
		{
			name:      "session space separated",
			input:     "session xyz789",
			forbidden: "xyz789",
		},
		{
			name:      "access token space separated jwt",
			input:     "access_token eyJhbGciOiJIUzI1NiJ9.abc",
			forbidden: "eyJhbGciOiJIUzI1NiJ9.abc",
		},
		// P1-D: OAuth flow secrets that previously leaked.
		{
			name:      "device code assignment",
			input:     "device_code=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef",
			forbidden: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef",
		},
		{
			name:      "device code json",
			input:     `{"device_code":"GHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"}`,
			forbidden: "GHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij",
		},
		{
			name:      "user code",
			input:     "user_code=WXYZ-1234-ABCD",
			forbidden: "WXYZ-1234-ABCD",
		},
		{
			name:      "authorization code query",
			input:     "https://127.0.0.1/callback?code=4/0AeanS0bXYZabcdefghijklmnop&state=abcdefghijklmnopqrstuvwxyz123456",
			forbidden: "4/0AeanS0bXYZabcdefghijklmnop",
		},
		{
			name:      "authorization code assignment",
			input:     `code=4/0AeanS0bXYZabcdefghijklmnop`,
			forbidden: "4/0AeanS0bXYZabcdefghijklmnop",
		},
		{
			name:      "code verifier",
			input:     "code_verifier=dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			forbidden: "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:      "state json",
			input:     `{"state":"abcdefghijklmnopqrstuvwxyz0123456789ABCD"}`,
			forbidden: "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
		},
		{
			name:      "state assignment",
			input:     "state=abcdefghijklmnopqrstuvwxyz0123456789ABCD",
			forbidden: "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactString(tt.input)
			if strings.Contains(got, tt.forbidden) {
				t.Errorf("secret survived redaction: %q -> %q", tt.input, got)
			}
			if !strings.Contains(got, Redacted) {
				t.Errorf("no redaction marker in %q", got)
			}
		})
	}
}

// TestRedactDoesNotMaskProse is the counterweight to the space-separated rule:
// a field name followed by an ordinary word must survive, or the redactor would
// corrupt legitimate log lines and error messages.
func TestRedactDoesNotMaskProse(t *testing.T) {
	bundle := MustNew()
	_ = bundle

	tests := []string{
		"token expirado",
		"session iniciada",
		"refresh token inválido",
		"authorization denied",
		"secret required",
		"password required",
		"key not found",
		// P1-D: the ambiguous short OAuth fields must not eat ordinary prose.
		"code=200 status",
		"http code: 404",
		"state=ready",
		"state: failed",
		"code review requested",
		"state machine started",
		// code_challenge is the PUBLIC PKCE value: deliberately NOT masked.
		`code_challenge=dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
	}
	for _, in := range tests {
		if got := RedactString(in); got != in {
			t.Errorf("prose masked: %q -> %q", in, got)
		}
	}
}

// TestLooksLikeCredential pins the heuristic directly.
func TestLooksLikeCredential(t *testing.T) {
	tests := map[string]bool{
		"abc123":           true,  // digit
		"xyz789":           true,  // digit
		"AbCdEf":           true,  // mixed case
		"a.b/c-d_e":        true,  // symbol
		"expirado":         false, // short lowercase word
		"iniciada":         false,
		"inválido":         false,
		"abcdefghijklmnop": true, // long lowercase run (>=16)
		"ok":               false,
		"yes":              false,
	}
	for value, want := range tests {
		if got := looksLikeCredential(value); got != want {
			t.Errorf("looksLikeCredential(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestRedactLeavesPlainTextUntouched(t *testing.T) {
	in := "model=gpt-4 request_id=0192f0c1-aaaa-bbbb-cccc-ddddeeeeffff"
	if got := RedactString(in); got != in {
		t.Errorf("plain text changed: %q -> %q", in, got)
	}
}

func TestRedactPreservesContext(t *testing.T) {
	got := RedactString("Authorization: Bearer abcdef123456")
	if !strings.Contains(got, "Authorization:") {
		t.Errorf("header name must be preserved: %q", got)
	}
}
