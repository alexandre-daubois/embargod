package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitCommandsStopWithTheirContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := Repo{Dir: t.TempDir(), Context: ctx}
	_, err := r.Commit()
	require.Error(t, err, "a canceled command ran")
}

// newRepo creates a git repository with one committed C file.
func newRepo(t testing.TB) Repo {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ext"), 0o755))
	src := "int php_overflow(int len) {\n\treturn len * 2;\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ext", "a.c"), []byte(src), 0o644))
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "."},
		{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "Fix overflow in php_overflow"},
	} {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	return Repo{Dir: dir}
}

func TestReadFile(t *testing.T) {
	r := newRepo(t)

	got, err := r.ReadFile("ext/a.c", 2, 2)
	require.NoError(t, err)
	require.Equal(t, "2\t\treturn len * 2;\n", got)
}

func TestReadFileRefusesEscapes(t *testing.T) {
	r := newRepo(t)
	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(r.Dir, "link")))

	for _, path := range []string{"../secret", outside, "link"} {
		_, err := r.ReadFile(path, 0, 0)
		assert.Error(t, err, "%s: expected an error", path)
	}
}

func TestReadFileOnlyReadsTrackedFiles(t *testing.T) {
	r := newRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(r.Dir, "untracked.txt"), []byte("token"), 0o644))
	require.NoError(t, os.Symlink(".git/config", filepath.Join(r.Dir, "config-link")))
	out, err := exec.Command("git", "-C", r.Dir, "add", "config-link").CombinedOutput()
	require.NoError(t, err, "git add: %s", out)

	for _, path := range []string{".git/config", ".git/HEAD", "untracked.txt", "config-link", ":(glob)**/a.c", "ext"} {
		got, err := r.ReadFile(path, 0, 0)
		assert.Error(t, err, "%s: expected an error, got %q", path, got)
	}
}

func TestExists(t *testing.T) {
	r := newRepo(t)

	assert.True(t, r.Exists("ext/a.c"), "ext/a.c should exist")
	assert.True(t, r.Exists("ext"), "ext holds tracked files")
	for _, path := range []string{"ext/missing.c", "../", ".git/config", "", ":(glob)**"} {
		assert.False(t, r.Exists(path), "%q should not exist", path)
	}
}

func TestGrep(t *testing.T) {
	r := newRepo(t)

	got, err := r.Grep(`php_[a-z]+\(`, "ext")
	require.NoError(t, err)
	require.Contains(t, got, "ext/a.c:1:int php_overflow")

	got, err = r.Grep("nothing_like_this", "")
	require.NoError(t, err)
	require.Equal(t, "no match", got)

	_, err = r.Grep("(", "")
	require.Error(t, err, "an invalid pattern should fail")
}

func TestHasSymbol(t *testing.T) {
	r := newRepo(t)

	for symbol, want := range map[string]bool{"php_overflow": true, "php_over": false, "--version": false} {
		got, err := r.HasSymbol("ext/a.c", symbol)
		require.NoError(t, err)
		assert.Equal(t, want, got, "%s", symbol)
	}
}

func TestLog(t *testing.T) {
	r := newRepo(t)

	got, err := r.Log("ext/a.c", "OVERFLOW")
	require.NoError(t, err)
	require.Contains(t, got, "Fix overflow in php_overflow")

	got, err = r.Log("", "unrelated")
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestTruncateLines(t *testing.T) {
	got := truncateLines("a\nb\nc\n", 2)
	require.Equal(t, "a\nb\n... 2 more lines, narrow the search\n", got)
}

func TestMissingRepository(t *testing.T) {
	r := Repo{Dir: filepath.Join(t.TempDir(), "missing")}

	_, err := r.ReadFile("a.c", 0, 0)
	assert.Error(t, err, "ReadFile should fail")
	assert.False(t, r.Exists("a.c"), "Exists should be false")
	_, err = r.Grep("a", "")
	assert.Error(t, err, "Grep should fail")
	_, err = r.Log("", "")
	assert.Error(t, err, "Log should fail")
	_, err = r.HasSymbol("", "a")
	assert.Error(t, err, "HasSymbol should fail")
}

func TestReadFileClampsTheRange(t *testing.T) {
	r := newRepo(t)

	got, err := r.ReadFile("ext/a.c", 3, 1)
	require.NoError(t, err)
	require.Equal(t, "3\t}\n", got)
	got, err = r.ReadFile("ext/a.c", 0, 0)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(got, "1\tint php_overflow"))
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
		require.Equal(t, tracked, strings.Join(lines, "\n")+"\n", "ReadFile(%q) read %q", path, got)
	})
}

func TestFiles(t *testing.T) {
	r := newRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(r.Dir, "with space.md"), nil, 0o644))
	out, err := exec.Command("git", "-C", r.Dir, "add", "with space.md").CombinedOutput()
	require.NoError(t, err, "git add: %s", out)

	got, err := r.Files()
	require.NoError(t, err)
	require.Equal(t, []string{"ext/a.c", "with space.md"}, got)
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...).CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)

	return strings.TrimSpace(string(out))
}

func TestHead(t *testing.T) {
	r := newRepo(t)
	sha, branch := gitIn(t, r.Dir, "rev-parse", "HEAD"), gitIn(t, r.Dir, "branch", "--show-current")

	commit, got, err := r.Head()
	require.NoError(t, err)
	require.Equal(t, sha, commit)
	require.Equal(t, branch, got)
	require.NotEmpty(t, branch)

	gitIn(t, r.Dir, "checkout", "-q", "--detach")
	commit, got, err = r.Head()
	require.NoError(t, err, "detached")
	require.Equal(t, sha, commit, "detached")
	require.Empty(t, got, "detached")
}

func TestHeadOutsideARepository(t *testing.T) {
	_, _, err := (Repo{Dir: t.TempDir()}).Head()
	require.Error(t, err, "want an error outside a repository")
}

func TestLines(t *testing.T) {
	r := newRepo(t)

	lines, ok, err := r.Lines("ext/a.c")
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, lines, 3)
	require.Equal(t, "\treturn len * 2;", lines[1])
	for _, path := range []string{"", "ext", "ext/missing.c", "../secret"} {
		lines, ok, err := r.Lines(path)
		assert.NoError(t, err, "%q", path)
		assert.False(t, ok, "%q", path)
		assert.Nil(t, lines, "%q", path)
	}
}

func TestLinesReadsTheCommittedFile(t *testing.T) {
	r := newRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(r.Dir, "ext", "a.c"), []byte("uncommitted\n"), 0o644))

	lines, _, _ := r.Lines("ext/a.c")
	require.Len(t, lines, 3, "want the committed lines")
}

func TestLastChange(t *testing.T) {
	r := newRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(r.Dir, "ext", "a.c"), []byte("int php_overflow(int len) {\n\treturn len;\n}\n"), 0o644))
	gitIn(t, r.Dir, "commit", "-q", "-am", "Stop doubling")
	sha := gitIn(t, r.Dir, "rev-parse", "HEAD")

	commit, date, err := r.LastChange("ext/a.c", "return len * 2;")
	require.NoError(t, err)
	require.Equal(t, sha, commit)
	require.Len(t, date, len("2026-10-24"))
	commit, date, err = r.LastChange("ext/a.c", "never written")
	require.NoError(t, err)
	require.Empty(t, commit)
	require.Empty(t, date)
}
