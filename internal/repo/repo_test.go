package repo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newRepo creates a git repository with one committed C file.
func newRepo(t *testing.T) Repo {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "ext"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := "int php_overflow(int len) {\n\treturn len * 2;\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "ext", "a.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "."},
		{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "Fix overflow in php_overflow"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}

	return Repo{Dir: dir}
}

func TestReadFile(t *testing.T) {
	r := newRepo(t)

	got, err := r.ReadFile("ext/a.c", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2\t\treturn len * 2;\n" {
		t.Fatalf("got %q", got)
	}
}

func TestReadFileRefusesEscapes(t *testing.T) {
	r := newRepo(t)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(r.Dir, "link")); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"../secret", outside, "link"} {
		if _, err := r.ReadFile(path, 0, 0); err == nil {
			t.Errorf("%s: expected an error", path)
		}
	}
}

func TestReadFileOnlyReadsTrackedFiles(t *testing.T) {
	r := newRepo(t)
	if err := os.WriteFile(filepath.Join(r.Dir, "untracked.txt"), []byte("token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".git/config", filepath.Join(r.Dir, "config-link")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", r.Dir, "add", "config-link").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}

	for _, path := range []string{".git/config", ".git/HEAD", "untracked.txt", "config-link", ":(glob)**/a.c", "ext"} {
		if got, err := r.ReadFile(path, 0, 0); err == nil {
			t.Errorf("%s: expected an error, got %q", path, got)
		}
	}
}

func TestExists(t *testing.T) {
	r := newRepo(t)

	if !r.Exists("ext/a.c") {
		t.Error("ext/a.c should exist")
	}
	if !r.Exists("ext") {
		t.Error("ext holds tracked files")
	}
	for _, path := range []string{"ext/missing.c", "../", ".git/config", "", ":(glob)**"} {
		if r.Exists(path) {
			t.Errorf("%q should not exist", path)
		}
	}
}

func TestGrep(t *testing.T) {
	r := newRepo(t)

	got, err := r.Grep(`php_[a-z]+\(`, "ext")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "ext/a.c:1:int php_overflow") {
		t.Fatalf("got %q", got)
	}

	got, err = r.Grep("nothing_like_this", "")
	if err != nil || got != "no match" {
		t.Fatalf("got %q, %v", got, err)
	}

	if _, err := r.Grep("(", ""); err == nil {
		t.Fatal("an invalid pattern should fail")
	}
}

func TestHasSymbol(t *testing.T) {
	r := newRepo(t)

	for symbol, want := range map[string]bool{"php_overflow": true, "php_over": false, "--version": false} {
		got, err := r.HasSymbol("ext/a.c", symbol)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: got %v", symbol, got)
		}
	}
}

func TestLog(t *testing.T) {
	r := newRepo(t)

	got, err := r.Log("ext/a.c", "OVERFLOW")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Fix overflow in php_overflow") {
		t.Fatalf("got %q", got)
	}

	got, err = r.Log("", "unrelated")
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTruncateLines(t *testing.T) {
	got := truncateLines("a\nb\nc\n", 2)
	if got != "a\nb\n... 2 more lines, narrow the search\n" {
		t.Fatalf("got %q", got)
	}
}
