package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alexandre-daubois/securibot/internal/engine"
	"github.com/alexandre-daubois/securibot/internal/github"
	"github.com/alexandre-daubois/securibot/internal/report"
	"github.com/alexandre-daubois/securibot/internal/tools"
)

var since = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

type fakeGitHub struct {
	advisories  []github.Advisory
	comments    map[string][]github.Comment
	posted      map[string]string
	commentsErr error
}

func (f *fakeGitHub) ListAdvisories(context.Context, string, string) ([]github.Advisory, error) {
	return f.advisories, nil
}

func (f *fakeGitHub) GetAdvisory(context.Context, string, string) (github.Advisory, error) {
	return github.Advisory{}, github.ErrNotFound
}

func (f *fakeGitHub) SearchIssues(context.Context, string, string) ([]github.Issue, error) {
	return nil, nil
}

func (f *fakeGitHub) GetIssue(context.Context, string, int) (github.Issue, error) {
	return github.Issue{}, github.ErrNotFound
}

func (f *fakeGitHub) ListComments(_ context.Context, _, ghsa string) ([]github.Comment, error) {
	if ghsa == "GHSA-other" && f.commentsErr != nil {
		return nil, f.commentsErr
	}

	return f.comments[ghsa], nil
}

func (f *fakeGitHub) PostComment(_ context.Context, _, ghsa, body string) error {
	f.posted[ghsa] = body

	return nil
}

type fakeEngine struct {
	prompts []string
	system  string
	fail    string
}

func (e *fakeEngine) Run(_ context.Context, system, prompt string, ts []tools.Tool) (json.RawMessage, error) {
	e.system = system
	e.prompts = append(e.prompts, prompt)
	if !slices.ContainsFunc(ts, func(t tools.Tool) bool { return t.Name == tools.Submit }) {
		return nil, errors.New("submit tool missing")
	}
	if e.fail != "" && strings.Contains(prompt, e.fail) {
		return nil, errors.New("model unavailable while reading SECRET-PAYLOAD from " + prompt)
	}

	return json.RawMessage(`{"summary":"Looks like a heap overflow.","duplicates":[{"ghsa_id":"GHSA-old","confidence":"high","exact":true}],"policy_exclusions":[{"point":"Malicious unserialize() inputs","reason":"The PoC calls unserialize()."}],"cwe":[{"id":"CWE-787","reason":"write"}]}`), nil
}

func newFixture() *fakeGitHub {
	return &fakeGitHub{
		advisories: []github.Advisory{
			{GHSAID: "GHSA-old", State: "triage", CreatedAt: since.Add(-time.Hour), HTMLURL: "https://x/GHSA-old"},
			{GHSAID: "GHSA-new", State: "triage", CreatedAt: since.Add(time.Hour), Summary: "Overflow in foo"},
			{GHSAID: "GHSA-done", State: "triage", CreatedAt: since.Add(time.Hour)},
			{GHSAID: "GHSA-draft", State: "draft", CreatedAt: since.Add(time.Hour)},
		},
		comments: map[string][]github.Comment{"GHSA-done": {{Body: report.Marker + "\nprevious run"}}},
		posted:   map[string]string{},
	}
}

func run(t *testing.T, cfg Config, gh *fakeGitHub, eng *fakeEngine) error {
	t.Helper()

	return runLogged(t, cfg, gh, eng, io.Discard)
}

func runLogged(t *testing.T, cfg Config, gh *fakeGitHub, eng *fakeEngine, logs io.Writer) error {
	t.Helper()
	cfg.Repo = "o/r"
	if cfg.RepoPath == "" {
		cfg.RepoPath = t.TempDir()
	}

	return Run(context.Background(), cfg, gh, eng, slog.New(slog.NewTextHandler(logs, nil)))
}

func TestRunOnlyPostsOnNewUntriagedAdvisories(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{}

	if err := run(t, Config{Since: since}, gh, eng); err != nil {
		t.Fatal(err)
	}

	if len(gh.posted) != 1 || gh.posted["GHSA-new"] == "" {
		t.Fatalf("posted = %v", gh.posted)
	}
	body := gh.posted["GHSA-new"]
	for _, want := range []string{report.Marker, "Looks like a heap overflow.", "| [GHSA-old](https://x/GHSA-old) |", "High • Exact duplicate", "CWE-787"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if len(eng.prompts) != 1 || !strings.Contains(eng.prompts[0], "Overflow in foo") || !strings.Contains(eng.prompts[0], "no security policy") {
		t.Fatalf("prompts = %v", eng.prompts)
	}
	if strings.Contains(body, "Security policy") {
		t.Errorf("no policy file, no policy section:\n%s", body)
	}
}

func TestRunChecksTheSecurityPolicy(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "SECURITY.md"), []byte("Malicious unserialize() inputs are not security issues."), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run(t, Config{Since: since, RepoPath: dir}, gh, eng); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(eng.prompts[0], "The repository security policy is in .github/SECURITY.md.") {
		t.Errorf("prompt = %s", eng.prompts[0])
	}
	if body := gh.posted["GHSA-new"]; !strings.Contains(body, "Checked against `.github/SECURITY.md`.") || !strings.Contains(body, "- Malicious unserialize() inputs: The PoC calls unserialize().") {
		t.Errorf("missing policy section:\n%s", body)
	}
}

func TestRunDryRunDoesNotPost(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{}
	var out bytes.Buffer

	if err := run(t, Config{Since: since, DryRun: true, Output: &out}, gh, eng); err != nil {
		t.Fatal(err)
	}

	if len(gh.posted) != 0 {
		t.Fatalf("dry run posted %v", gh.posted)
	}
	if !strings.Contains(out.String(), "## GHSA-new") || !strings.Contains(out.String(), report.Marker) {
		t.Fatalf("output = %s", out.String())
	}
}

func TestRunTargetedAdvisoryIgnoresSinceAndState(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{}

	if err := run(t, Config{Advisory: "ghsa-draft"}, gh, eng); err != nil {
		t.Fatal(err)
	}

	if len(gh.posted) != 1 || gh.posted["GHSA-draft"] == "" {
		t.Fatalf("posted = %v", gh.posted)
	}
}

func TestRunTargetedAdvisoryAlreadyCommented(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{}

	if err := run(t, Config{Advisory: "GHSA-done"}, gh, eng); err != nil {
		t.Fatal(err)
	}

	if len(gh.posted) != 0 || len(eng.prompts) != 0 {
		t.Fatalf("an advisory must not be commented twice: %v", gh.posted)
	}
}

func TestRunReportsFailuresAndContinues(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{fail: "GHSA-new"}
	gh.advisories = append(gh.advisories, github.Advisory{GHSAID: "GHSA-other", State: "triage", CreatedAt: since.Add(2 * time.Hour)})

	err := run(t, Config{Since: since}, gh, eng)
	if err == nil || !strings.Contains(err.Error(), "1 advisory") {
		t.Fatalf("want one failure, got %v", err)
	}
	if gh.posted["GHSA-other"] == "" {
		t.Fatalf("the other advisory should still be triaged: %v", gh.posted)
	}
}

func TestRunAppendsProjectProfile(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProfilePath), []byte("Score CVSS for php-fpm deployments."), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run(t, Config{Since: since, RepoPath: dir}, gh, eng); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(eng.system, "# Advisory triage") || !strings.Contains(eng.system, "Score CVSS for php-fpm deployments.") {
		t.Fatalf("system prompt = %s", eng.system)
	}
}

func TestRunLogsNothingAboutTheAdvisories(t *testing.T) {
	gh, eng := newFixture(), &fakeEngine{fail: "GHSA-new"}
	gh.advisories = append(gh.advisories,
		github.Advisory{GHSAID: "GHSA-other", State: "triage", CreatedAt: since.Add(2 * time.Hour)},
		github.Advisory{GHSAID: "GHSA-third", State: "triage", CreatedAt: since.Add(3 * time.Hour)},
	)
	gh.commentsErr = fmt.Errorf("listing GHSA-other: %w", &github.HTTPError{Status: 403})
	var logs bytes.Buffer

	err := runLogged(t, Config{Since: since}, gh, eng, &logs)

	if err == nil || strings.Contains(err.Error(), "GHSA-") || strings.Contains(err.Error(), "SECRET-PAYLOAD") {
		t.Fatalf("unexpected error: %v", err)
	}
	if gh.posted["GHSA-third"] == "" {
		t.Fatalf("the third advisory should be triaged: %v", gh.posted)
	}
	got := logs.String()
	for _, leak := range []string{"GHSA-", "SECRET-PAYLOAD", "Overflow in foo"} {
		if strings.Contains(got, leak) {
			t.Errorf("logs leak %q:\n%s", leak, got)
		}
	}
	for _, want := range []string{"reason=\"unexpected error\"", "reason=\"github: HTTP 403\"", "triaged=1 already_triaged=1 failed=2"} {
		if !strings.Contains(got, want) {
			t.Errorf("logs miss %q:\n%s", want, got)
		}
	}
}

func TestDescribe(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("x GHSA-1: %w", &github.HTTPError{Status: 404}):             "github: HTTP 404",
		fmt.Errorf("x: %w", &engine.APIError{Provider: "openai", Status: 429}): "openai: HTTP 429",
		&engine.RefusalError{Category: "cyber"}:                                `the model refused (category "cyber")`,
		fmt.Errorf("x: %w", engine.ErrNoReport):                                engine.ErrNoReport.Error(),
		errInvalidReport:                                                       errInvalidReport.Error(),
		fmt.Errorf("SECRET: %w", context.Canceled):                             "canceled",
		errors.New("SECRET-PAYLOAD"):                                           "unexpected error",
	} {
		if got := describe(err); got != want {
			t.Errorf("describe(%v) = %q, want %q", err, got, want)
		}
	}
}
