package report

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandre-daubois/advisory-triage/internal/github"
	"github.com/alexandre-daubois/advisory-triage/internal/repo"
)

type fakeIssues map[int]github.Issue

func (f fakeIssues) GetIssue(_ context.Context, _ string, n int) (github.Issue, error) {
	if n == 500 {
		return github.Issue{}, errors.New("boom")
	}
	i, ok := f[n]
	if !ok {
		return github.Issue{}, fmt.Errorf("issue %d: %w", n, github.ErrNotFound)
	}

	return i, nil
}

func codeRepo(t *testing.T) repo.Repo {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.c"), []byte("void real_func(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}

	return repo.Repo{Dir: dir}
}

func checker(t *testing.T) Checker {
	return Checker{
		Repo:       "o/r",
		Issues:     fakeIssues{12: {Number: 12, Title: "Harden len check", State: "open", HTMLURL: "https://github.com/o/r/pull/12", PullRequest: &struct{}{}}},
		Code:       codeRepo(t),
		Advisories: map[string]string{"GHSA-real": "https://github.com/o/r/security/advisories/GHSA-real"},
	}
}

func TestVerifyKeepsWhatExists(t *testing.T) {
	r := Report{
		Duplicates:     []Duplicate{{GHSAID: "GHSA-real", Reason: "same"}},
		Related:        []Related{{Number: 12, Reason: "hardens it"}},
		CodeReferences: []CodeReference{{Path: "a.c", Symbol: "real_func"}, {Path: "a.c"}},
		CWE:            []CWE{{ID: "CWE-787"}},
		CVSS:           CVSS{Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
	}

	if err := checker(t).Verify(context.Background(), &r); err != nil {
		t.Fatal(err)
	}

	if r.Removed != 0 || len(r.Duplicates) != 1 || len(r.Related) != 1 || len(r.CWE) != 1 || r.CVSS.Vector == "" {
		t.Fatalf("nothing should be removed: %+v", r)
	}
	if r.Duplicates[0].URL == "" || r.Related[0].Title != "Harden len check" || !r.Related[0].PullRequest {
		t.Fatalf("facts not filled: %+v", r)
	}
	if !r.CodeReferences[0].Found || !r.CodeReferences[1].Found {
		t.Fatalf("references should be found: %+v", r.CodeReferences)
	}
}

func TestVerifyDropsWhatDoesNotExist(t *testing.T) {
	r := Report{
		Duplicates:     []Duplicate{{GHSAID: "GHSA-invented"}},
		Related:        []Related{{Number: 999}},
		CodeReferences: []CodeReference{{Path: "a.c", Symbol: "invented_func"}, {Path: "missing.c"}, {Path: "../etc/passwd"}},
		CWE:            []CWE{{ID: "CWE-0"}, {ID: "buffer overflow"}},
		CVSS:           CVSS{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}

	if err := checker(t).Verify(context.Background(), &r); err != nil {
		t.Fatal(err)
	}

	if len(r.Duplicates) != 0 || len(r.Related) != 0 || len(r.CWE) != 0 || r.CVSS.Vector != "" {
		t.Fatalf("invented claims should be removed: %+v", r)
	}
	if r.Removed != 5 {
		t.Fatalf("Removed = %d, want 5", r.Removed)
	}
	if len(r.CodeReferences) != 3 {
		t.Fatalf("code references are kept and flagged: %+v", r.CodeReferences)
	}
	for _, ref := range r.CodeReferences {
		if ref.Found {
			t.Errorf("%+v should not be found", ref)
		}
	}
}

func TestVerifyFailsOnGitHubErrors(t *testing.T) {
	r := Report{Related: []Related{{Number: 500}}}

	if err := checker(t).Verify(context.Background(), &r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRender(t *testing.T) {
	got := Render(Report{
		Summary:        "Heap overflow claimed, cc @someone",
		Duplicates:     []Duplicate{{GHSAID: "GHSA-real", URL: "https://x/GHSA-real", Reason: "same\nroot cause"}},
		Related:        []Related{{Number: 12, Title: "Harden", URL: "https://x/12", State: "open", PullRequest: true, Reason: "fix"}},
		CodeReferences: []CodeReference{{Path: "a.c", Symbol: "f", Found: true}, {Path: "b|c.c"}},
		CWE:            []CWE{{ID: "CWE-787", Reason: "write"}},
		CVSS:           CVSS{Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", Reason: "remote"},
		Removed:        2,
	})

	for _, want := range []string{
		Marker,
		"cc @​someone",
		"- [GHSA-real](https://x/GHSA-real): same root cause",
		"- [#12 Harden](https://x/12) (pull request, open): fix",
		"| `a.c` `f` | yes |",
		"| `b\\|c.c` | no |",
		"- CWE-787: write",
		"(https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/",
		"2 suggestion(s) removed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderEmpty(t *testing.T) {
	got := Render(Report{Summary: "Nothing"})

	for _, want := range []string{"None found among the repository advisories.", "None found.", "No estimate."} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Code cited") || strings.Contains(got, "removed") {
		t.Errorf("empty sections should be omitted:\n%s", got)
	}
}
