package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// ---- padToBucket ----

func TestPadToBucket_PadsToPowerOfTwo(t *testing.T) {
	cases := []struct {
		in      string
		minSize int
		want    int
	}{
		{"", 512, 512},
		{"x", 512, 512},
		{strings.Repeat("x", 512), 512, 512}, // already at bucket — no-op
		{strings.Repeat("x", 513), 512, 1024},
		{strings.Repeat("x", 1024), 512, 1024},
		{strings.Repeat("x", 1025), 512, 2048},
		{strings.Repeat("x", 3000), 512, 4096},
	}
	for _, tc := range cases {
		out := padToBucket([]byte(tc.in), tc.minSize)
		if len(out) != tc.want {
			t.Errorf("padToBucket(len=%d, min=%d): got %d, want %d",
				len(tc.in), tc.minSize, len(out), tc.want)
		}
	}
}

func TestPadToBucket_PadsWithSpaces(t *testing.T) {
	out := padToBucket([]byte("abc"), 512)
	if string(out[:3]) != "abc" {
		t.Fatal("original data must be preserved at start")
	}
	for i := 3; i < len(out); i++ {
		if out[i] != ' ' {
			t.Fatalf("padding at index %d is %q, want space", i, out[i])
		}
	}
}

func TestPadToBucket_ResultIsValidJSONWhenInputIs(t *testing.T) {
	// JSON parsers should ignore trailing whitespace.
	plaintext := []byte(`{"name":"test.jpg","size":1234}`)
	padded := padToBucket(plaintext, 512)

	var parsed map[string]any
	if err := json.Unmarshal(padded, &parsed); err != nil {
		t.Fatalf("padded JSON should still parse: %v", err)
	}
	if parsed["name"] != "test.jpg" {
		t.Fatalf("got name=%v, want test.jpg", parsed["name"])
	}
}

// ---- sanitizeServerResponse ----

func TestSanitizeServerResponse_StripsNonPrintable(t *testing.T) {
	// ANSI escape + control chars + printable + non-ASCII
	in := []byte("safe\x1b[31m\x00\x07text\xe2\x98\xa0ok")
	got := sanitizeServerResponse(in)
	want := "safe[31mtextok"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizeServerResponse_TruncatesAt512(t *testing.T) {
	in := make([]byte, 1000)
	for i := range in {
		in[i] = 'A'
	}
	got := sanitizeServerResponse(in)
	if len(got) != 512 {
		t.Fatalf("got %d chars, want 512", len(got))
	}
}

func TestSanitizeServerResponse_Empty(t *testing.T) {
	if got := sanitizeServerResponse(nil); got != "" {
		t.Fatalf("empty input should produce empty string, got %q", got)
	}
}

// ---- isImage / isVideo ----

func TestIsImage(t *testing.T) {
	wantImage := []string{".jpg", ".jpeg", ".png", ".gif", ".webp"}
	for _, ext := range wantImage {
		if !isImage(ext) {
			t.Errorf("isImage(%q) = false, want true", ext)
		}
	}
	for _, ext := range []string{".mp4", ".txt", ".zip", ""} {
		if isImage(ext) {
			t.Errorf("isImage(%q) = true, want false", ext)
		}
	}
}

func TestIsVideo(t *testing.T) {
	wantVideo := []string{".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v"}
	for _, ext := range wantVideo {
		if !isVideo(ext) {
			t.Errorf("isVideo(%q) = false, want true", ext)
		}
	}
	for _, ext := range []string{".jpg", ".txt", ".pdf", ""} {
		if isVideo(ext) {
			t.Errorf("isVideo(%q) = true, want false", ext)
		}
	}
}

// ---- Filename sanitization for downloads ----
//
// Mirrors the logic in cmdDownload: filepath.Base strips directory components,
// then dotfile names are prefixed with the media ID to prevent overwriting
// shell configs when downloading into a home directory.

func sanitizeDownloadName(name, mediaID string) string {
	safe := filepath.Base(name)
	if safe == "." || safe == ".." || safe == "" {
		safe = mediaID
	}
	if strings.HasPrefix(safe, ".") {
		safe = mediaID + "_" + strings.TrimLeft(safe, ".")
	}
	return safe
}

func TestSanitizeDownloadName(t *testing.T) {
	mediaID := "abc-123"
	cases := []struct {
		in   string
		want string
	}{
		{"photo.jpg", "photo.jpg"},
		{"../../etc/passwd", "passwd"},
		{"/abs/path/vid.mp4", "vid.mp4"},
		{"..", "abc-123"},
		{".", "abc-123"},
		{"", "abc-123"},
		{".bashrc", "abc-123_bashrc"},
		{".ssh/authorized_keys", "authorized_keys"}, // filepath.Base strips the dot-dir
		{"...hidden.jpg", "abc-123_hidden.jpg"},
		{".env", "abc-123_env"},
	}
	for _, tc := range cases {
		got := sanitizeDownloadName(tc.in, mediaID)
		if got != tc.want {
			t.Errorf("sanitizeDownloadName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- buildAuthJSON ----

func TestBuildAuthJSON_ProducesValidJSON(t *testing.T) {
	body := buildAuthJSON("alice", []byte("p@ssw0rd!"))
	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (body=%s)", err, body)
	}
	if parsed["username"] != "alice" {
		t.Errorf("username: got %q", parsed["username"])
	}
	if parsed["password"] != "p@ssw0rd!" {
		t.Errorf("password: got %q", parsed["password"])
	}
}

func TestBuildAuthJSON_EscapesSpecialChars(t *testing.T) {
	// Password with quote, backslash, newline, tab, control char
	body := buildAuthJSON("user", []byte("a\"b\\c\nd\te\x01f"))
	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (body=%s)", err, body)
	}
	if parsed["password"] != "a\"b\\c\nd\te\x01f" {
		t.Errorf("round-tripped password differs: got %q", parsed["password"])
	}
}

func TestBuildAuthJSON_EscapesSpecialUsername(t *testing.T) {
	body := buildAuthJSON(`alice"admin`, []byte("pw"))
	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (body=%s)", err, body)
	}
	if parsed["username"] != `alice"admin` {
		t.Errorf("username: got %q", parsed["username"])
	}
}
