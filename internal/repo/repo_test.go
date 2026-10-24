package repo

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// newRepo creates a git repository with one committed C file.
func newRepo(t testing.TB) Repo {
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

func TestMissingRepository(t *testing.T) {
	r := Repo{Dir: filepath.Join(t.TempDir(), "missing")}

	if _, err := r.ReadFile("a.c", 0, 0); err == nil {
		t.Error("ReadFile should fail")
	}
	if r.Exists("a.c") {
		t.Error("Exists should be false")
	}
	if _, err := r.Grep("a", ""); err == nil {
		t.Error("Grep should fail")
	}
	if _, err := r.Log("", ""); err == nil {
		t.Error("Log should fail")
	}
	if _, err := r.HasSymbol("", "a"); err == nil {
		t.Error("HasSymbol should fail")
	}
}

func TestReadFileClampsTheRange(t *testing.T) {
	r := newRepo(t)

	got, err := r.ReadFile("ext/a.c", 3, 1)
	if err != nil || got != "3\t}\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = r.ReadFile("ext/a.c", 0, 0)
	if err != nil || !strings.HasPrefix(got, "1\tint php_overflow") {
		t.Fatalf("got %q, %v", got, err)
	}
}

func FuzzReadFileStaysInTrackedFiles(f *testing.F) {
	for _, seed := range []string{"ext/a.c", ".git/config", "../secret", "/etc/passwd", "ext/../.git/HEAD", ":(glob)**", "./.git/config", "EXT/A.C", "ext//a.c"} {
		f.Add(seed)
	}
	r := newRepo(f)
	tracked := "int php_overflow(int len) {\n\treturn len * 2;\n}\n"

	f.Fuzz(func(t *testing.T, path string) {
		got, err := r.ReadFile(path, 0, 0)
		if err != nil {
			return
		}
		// Whatever the path, the only readable content is the one tracked file.
		var lines []string
		for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
			_, text, _ := strings.Cut(l, "\t")
			lines = append(lines, text)
		}
		if strings.Join(lines, "\n")+"\n" != tracked {
			t.Fatalf("ReadFile(%q) read %q", path, got)
		}
	})
}

func TestFiles(t *testing.T) {
	r := newRepo(t)
	if err := os.WriteFile(filepath.Join(r.Dir, "with space.md"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", r.Dir, "add", "with space.md").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}

	got, err := r.Files()
	if err != nil || !slices.Equal(got, []string{"ext/a.c", "with space.md"}) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}

	return strings.TrimSpace(string(out))
}

func TestHead(t *testing.T) {
	r := newRepo(t)
	sha, branch := gitIn(t, r.Dir, "rev-parse", "HEAD"), gitIn(t, r.Dir, "branch", "--show-current")

	commit, got, err := r.Head()
	if err != nil || commit != sha || got != branch || branch == "" {
		t.Fatalf("got %q %q %v, want %q %q", commit, got, err, sha, branch)
	}

	gitIn(t, r.Dir, "checkout", "-q", "--detach")
	if commit, got, err := r.Head(); err != nil || commit != sha || got != "" {
		t.Fatalf("detached: got %q %q %v", commit, got, err)
	}
}

func TestHeadOutsideARepository(t *testing.T) {
	if _, _, err := (Repo{Dir: t.TempDir()}).Head(); err == nil {
		t.Fatal("want an error outside a repository")
	}
}

func TestLines(t *testing.T) {
	r := newRepo(t)

	lines, ok, err := r.Lines("ext/a.c")
	if err != nil || !ok || len(lines) != 3 || lines[1] != "\treturn len * 2;" {
		t.Fatalf("got %q %v %v", lines, ok, err)
	}
	for _, path := range []string{"", "ext", "ext/missing.c", "../secret"} {
		if lines, ok, err := r.Lines(path); err != nil || ok || lines != nil {
			t.Errorf("%q: got %q %v %v", path, lines, ok, err)
		}
	}
}

func TestLinesReadsTheCommittedFile(t *testing.T) {
	r := newRepo(t)
	if err := os.WriteFile(filepath.Join(r.Dir, "ext", "a.c"), []byte("uncommitted\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if lines, _, _ := r.Lines("ext/a.c"); len(lines) != 3 {
		t.Fatalf("got %q, want the committed lines", lines)
	}
}

func TestLastChange(t *testing.T) {
	r := newRepo(t)
	if err := os.WriteFile(filepath.Join(r.Dir, "ext", "a.c"), []byte("int php_overflow(int len) {\n\treturn len;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, r.Dir, "commit", "-q", "-am", "Stop doubling")
	sha := gitIn(t, r.Dir, "rev-parse", "HEAD")

	commit, date, err := r.LastChange("ext/a.c", "return len * 2;")
	if err != nil || commit != sha || len(date) != len("2026-10-24") {
		t.Fatalf("got %q %q %v, want %q", commit, date, err, sha)
	}
	if commit, date, err := r.LastChange("ext/a.c", "never written"); err != nil || commit != "" || date != "" {
		t.Fatalf("got %q %q %v, want nothing", commit, date, err)
	}
}
