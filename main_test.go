package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
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
// These exercise the functions cmdDownload actually calls. (An earlier
// version tested a copy of the logic, which is how a traversal via the
// media-ID fallback went unnoticed.)

const testMediaID = "3f2b8c4e-1a2b-4c3d-8e9f-0a1b2c3d4e5f"

func TestLocalFileName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"photo.jpg", "photo.jpg"},
		{"../../etc/passwd", testMediaID + "__.._etc_passwd"},
		{"/abs/path/vid.mp4", "_abs_path_vid.mp4"},
		{`..\..\win.ini`, testMediaID + "__.._win.ini"},
		{"..", testMediaID},
		{".", testMediaID},
		{"", testMediaID},
		{"   ", testMediaID},
		{".bashrc", testMediaID + "_bashrc"},
		{".ssh/authorized_keys", testMediaID + "_ssh_authorized_keys"},
		{"...hidden.jpg", testMediaID + "_hidden.jpg"},
		{"evil\x1b]52;c;aGk=\x07.jpg", "evil]52;c;aGk=.jpg"},
		{"caf\u00e9.jpg", "caf\u00e9.jpg"},
		{"gpj.\u202eexe", "gpj.exe"},
	}
	for _, tc := range cases {
		got := localFileName(tc.in, testMediaID)
		if got != tc.want {
			t.Errorf("localFileName(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !filepath.IsLocal(got) || strings.ContainsAny(got, `/\`) {
			t.Errorf("localFileName(%q) = %q is not a single local path component", tc.in, got)
		}
	}
}

func TestSanitizeTerminal(t *testing.T) {
	in := "a\x1b[2Jb\x9bc\u202ed\te\nf"
	if got := sanitizeTerminal(in); got != "a[2Jbcdef" {
		t.Errorf("sanitizeTerminal(%q) = %q", in, got)
	}
}

func TestIsCanonicalUUID(t *testing.T) {
	for _, ok := range []string{testMediaID} {
		if !isCanonicalUUID(ok) {
			t.Errorf("isCanonicalUUID(%q) = false", ok)
		}
	}
	for _, bad := range []string{
		"", "../../home/victim/.bashrc", "urn:uuid:" + testMediaID,
		"{" + testMediaID + "}", strings.ReplaceAll(testMediaID, "-", ""),
		strings.ToUpper(testMediaID),
	} {
		if isCanonicalUUID(bad) {
			t.Errorf("isCanonicalUUID(%q) = true", bad)
		}
	}
}

func TestPublishNoClobber(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := os.WriteFile(filepath.Join(dir, "clip.mp4"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"clip (1).mp4", "clip (2).mp4"} {
		tmp := fmt.Sprintf(".part%d", i)
		if err := root.WriteFile(tmp, []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := publishNoClobber(root, tmp, "clip.mp4")
		if err != nil || got != want {
			t.Fatalf("publishNoClobber = %q, %v; want %q", got, err, want)
		}
		if _, err := root.Lstat(tmp); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("temp file %s left behind", tmp)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "clip.mp4")); string(b) != "existing" {
		t.Errorf("existing file was overwritten: %q", b)
	}
}

func TestRootRejectsEscape(t *testing.T) {
	// Defense in depth: even if a bad name slipped past localFileName, the
	// os.Root the download writes through must refuse to leave outDir,
	// including via a pre-planted symlink.
	parent := t.TempDir()
	out := filepath.Join(parent, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, filepath.Join(out, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(out)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"../escape", "link/escape", "/tmp/escape"} {
		if f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
			f.Close()
			t.Errorf("os.Root allowed creating %q", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "escape")); err == nil {
		t.Error("file escaped the output directory")
	}
}

func TestFetchAllMediaDropsNonUUIDIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]string{
				{"id": testMediaID},
				{"id": "../../../home/victim/.bashrc"},
				{"id": "urn:uuid:" + testMediaID},
			},
			"total": 3,
		})
	}))
	defer srv.Close()
	items, err := fetchAllMedia(srv.URL, []byte("tok"))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != testMediaID {
		t.Fatalf("fetchAllMedia returned %+v, want only the canonical UUID item", items)
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
