package report

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/php/tamis/internal/repo"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...).CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)

	return strings.TrimSpace(string(out))
}

// historyRepo commits url.c with a length check, then a second version without it where decode moved down.
// It returns the repository and the commit that removed the check.
func historyRepo(t *testing.T) (repo.Repo, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(content string) {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "ext", "std dir"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ext", "std dir", "url.c"), []byte(content), 0o644))
	}
	write("int decode(char *s, int len) {\n\tif (len > MAX_LEN) return -1;\n\treturn s[len];\n}\n")
	git(t, dir, "init", "-q")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "Add decode")
	write("/* decoder */\n\nint decode(char *s, int len) {\n\treturn s[len];\n}\n")
	git(t, dir, "commit", "-q", "-am", "Drop the length check")

	return repo.Repo{Dir: dir}, git(t, dir, "rev-parse", "HEAD")
}

func TestVerifyPlacesCitedLines(t *testing.T) {
	code, removal := historyRepo(t)
	const file = "ext/std dir/url.c"
	for name, tc := range map[string]struct {
		ref     CodeReference
		place   Place
		current int
		commit  string
	}{
		"same line":         {CodeReference{Path: file, Line: 4, Snippet: "  return   s[len];"}, PlaceSame, 4, ""},
		"moved":             {CodeReference{Path: file, Line: 3, Snippet: "return s[len];"}, PlaceMoved, 4, ""},
		"quote only":        {CodeReference{Path: file, Snippet: "return s[len];"}, PlaceMoved, 4, ""},
		"changed":           {CodeReference{Path: file, Line: 2, Snippet: "if (len > MAX_LEN) return -1;"}, PlaceChanged, 0, removal},
		"never in the file": {CodeReference{Path: file, Line: 2, Snippet: "memcpy(dst, src, len);"}, PlaceMissing, 0, ""},
		"proof of concept":  {CodeReference{Path: file, Snippet: `rawurldecode("%\x80\x80");`}, "", 0, ""},
		"changed, no line":  {CodeReference{Path: file, Snippet: "if (len > MAX_LEN) return -1;"}, PlaceChanged, 0, removal},
		"unquoted line":     {CodeReference{Path: file, Line: 5}, PlaceUnquoted, 0, ""},
		"past the end":      {CodeReference{Path: file, Line: 99}, PlacePastEnd, 5, ""},
		"directory":         {CodeReference{Path: "ext", Line: 2, Snippet: "return s[len];"}, "", 0, ""},
		"missing file":      {CodeReference{Path: "ext/gone.c", Line: 2, Snippet: "return s[len];"}, "", 0, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := Report{CodeReferences: []CodeReference{tc.ref}}

			require.NoError(t, (Checker{Repo: "o/r", Issues: fakeIssues{}, Code: code}).Verify(context.Background(), &r))

			got := r.CodeReferences[0]
			require.Equal(t, tc.place, got.Place)
			require.Equal(t, tc.current, got.Current)
			require.Equal(t, tc.commit, got.Commit)
			if tc.commit != "" {
				require.Len(t, got.Date, len("2026-10-24"), "missing date: %+v", got)
			}
		})
	}
}

func TestVerifyRecordsTheScannedCommit(t *testing.T) {
	code, head := historyRepo(t)
	r := Report{}

	require.NoError(t, (Checker{Repo: "o/r", Issues: fakeIssues{}, Code: code}).Verify(context.Background(), &r))

	require.Equal(t, "o/r", r.Repo)
	require.Equal(t, head, r.Commit)
	require.NotEmpty(t, r.Branch)
}

func TestVerifyDoesNotPlaceWithoutCommit(t *testing.T) {
	r := Report{CodeReferences: []CodeReference{{Path: "a.c", Line: 1, Snippet: "void real_func(void) {}"}}}

	require.NoError(t, checker(t).Verify(context.Background(), &r))

	got := r.CodeReferences[0]
	require.True(t, got.Found)
	require.Empty(t, got.Place)
	require.Empty(t, r.Commit)
}

func TestKeepCitedDropsLinesAndQuotesNotInTheReport(t *testing.T) {
	r := Report{CodeReferences: []CodeReference{
		{Path: "ext/url.c", Line: 592, Snippet: "if (len > MAX_LEN)"},
		{Path: "ext/url.c", Line: 17, Snippet: "memcpy(dst, src, len);"},
		{Path: "ext/url.c", Line: 592, Snippet: "}"},
	}}

	r.KeepCited("In `ext/url.c:592`:\n\n```c\n    if (len   >   MAX_LEN)\n```")

	want := []CodeReference{
		{Path: "ext/url.c", Line: 592, Snippet: "if (len > MAX_LEN)"},
		{Path: "ext/url.c"},
		{Path: "ext/url.c", Line: 592},
	}
	for i := range want {
		assert.Equal(t, want[i], r.CodeReferences[i], "reference %d", i)
	}
}

func TestRenderScanHeader(t *testing.T) {
	at := time.Date(2026, 10, 24, 16, 32, 0, 0, time.FixedZone("CEST", 2*3600))
	for name, tc := range map[string]struct {
		r    Report
		want string
	}{
		"branch":    {Report{ScannedAt: at, Commit: "21a7561c0ffee", Branch: "main"}, "Scanned on 2026-10-24 at 14:32 UTC on `main` at `21a7561`.\n"},
		"detached":  {Report{ScannedAt: at, Commit: "21a7561c0ffee"}, "Scanned on 2026-10-24 at 14:32 UTC at `21a7561`.\n"},
		"no commit": {Report{ScannedAt: at}, "Scanned on 2026-10-24 at 14:32 UTC.\n"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Contains(t, Render(tc.r), tc.want)
		})
	}
	require.NotContains(t, Render(Report{}), "Scanned on", "a report without a scan time must not show one")
}

func TestRenderPlaces(t *testing.T) {
	const sha = "9f3c2ab0123456789"
	r := Report{Repo: "o/r", Commit: "21a7561c0ffee", Branch: "main", CodeReferences: []CodeReference{
		{Path: "ext/std dir/url.c", Symbol: "decode", Line: 592, Found: true, Place: PlaceSame, Current: 592},
		{Path: "ext/url.c", Line: 480, Found: true, Place: PlaceMoved, Current: 512},
		{Path: "ext/url.c", Found: true, Place: PlaceMoved, Current: 512},
		{Path: "main/streams.c", Line: 1200, Found: true, Place: PlaceChanged, Commit: sha, Date: "2026-09-01"},
		{Path: "ext/url.c", Line: 3, Found: true, Place: PlaceMissing},
		{Path: "ext/url.c", Line: 700, Found: true, Place: PlaceUnquoted},
		{Path: "ext/url.c", Line: 9999, Found: true, Place: PlacePastEnd, Current: 812},
		{Path: "ext/gone.c", Line: 3},
	}}

	got := Render(r)

	for _, want := range []string{
		"| Cited | In the repository on `main` at `21a7561` |",
		"| `ext/std dir/url.c:592` `decode` | Same line, [L592](https://github.com/o/r/blob/21a7561c0ffee/ext/std%20dir/url.c#L592) |",
		"| `ext/url.c:480` | Moved to [L512](https://github.com/o/r/blob/21a7561c0ffee/ext/url.c#L512) |",
		"| `ext/url.c` | At [L512](https://github.com/o/r/blob/21a7561c0ffee/ext/url.c#L512) |",
		"| `main/streams.c:1200` | Quoted code changed by [`9f3c2ab`](https://github.com/o/r/commit/9f3c2ab0123456789) on 2026-09-01 |",
		"| `ext/url.c:3` | Quoted code not found in the file's history |",
		"| `ext/url.c:700` | [L700](https://github.com/o/r/blob/21a7561c0ffee/ext/url.c#L700), the report quotes no code |",
		"| `ext/url.c:9999` | Past the end of the file (812 lines) |",
		"| `ext/gone.c:3` | Not found |",
	} {
		assert.Contains(t, got, want)
	}
}

func TestLineLinkEscapesThePath(t *testing.T) {
	got := Report{Repo: "o/r", Commit: "abc"}.lineLink("a/b) [x](y#z.c", 1)

	require.Equal(t, "[L1](https://github.com/o/r/blob/abc/a/b%29%20%5Bx%5D%28y%23z.c#L1)", got)
}
