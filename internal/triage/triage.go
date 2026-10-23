// Package triage selects the advisories to triage, runs the model on each and publishes the result.
package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexandre-daubois/embargod/internal/engine"
	"github.com/alexandre-daubois/embargod/internal/github"
	"github.com/alexandre-daubois/embargod/internal/repo"
	"github.com/alexandre-daubois/embargod/internal/report"
	"github.com/alexandre-daubois/embargod/internal/tools"
	"github.com/alexandre-daubois/embargod/skill"
)

// ProfilePath holds project-specific guidance, relative to the repository root.
const ProfilePath = ".github/embargod.md"

var errInvalidReport = errors.New("the model submitted an invalid report")

type GitHub interface {
	tools.IssueSearcher
	report.IssueGetter
	ListAdvisories(ctx context.Context, repo, state string) ([]github.Advisory, error)
	Login(ctx context.Context) (string, error)
	ListComments(ctx context.Context, repo, ghsa string) ([]github.Comment, error)
	PostComment(ctx context.Context, repo, ghsa, body string) error
}

type Config struct {
	Repo string
	// Since excludes advisories created before it, so a first run does not comment the backlog.
	Since time.Time
	// Advisory targets a single advisory and bypasses Since.
	Advisory string
	RepoPath string
}

// Run never logs report content, GHSA identifiers nor raw errors: logs of public repositories are public.
func Run(ctx context.Context, cfg Config, gh GitHub, eng engine.Engine, log *slog.Logger) error {
	login, err := gh.Login(ctx)
	if err != nil {
		return errors.New("identifying the token owner: " + describe(err))
	}

	all, err := gh.ListAdvisories(ctx, cfg.Repo, "")
	if err != nil {
		return errors.New("listing advisories: " + describe(err))
	}

	var triaged, skipped, failed int
	for _, a := range all {
		if !selected(cfg, a) {
			continue
		}

		comments, err := gh.ListComments(ctx, cfg.Repo, a.GHSAID)
		if err != nil {
			log.Error("listing comments failed", "reason", describe(err))
			failed++
			continue
		}
		if commented(comments, login) {
			skipped++
			continue
		}

		if err := triage(ctx, cfg, gh, eng, a, all); err != nil {
			log.Error("triage failed", "reason", describe(err))
			failed++
			continue
		}
		triaged++
	}

	log.Info("done", "triaged", triaged, "already_triaged", skipped, "failed", failed)
	if failed > 0 {
		return fmt.Errorf("%d advisory(ies) failed", failed)
	}

	return nil
}

// describe turns an error into text that is safe to log, keeping only status codes and known reasons.
func describe(err error) string {
	var (
		gh      *github.HTTPError
		api     *engine.APIError
		refusal *engine.RefusalError
	)
	switch {
	case errors.As(err, &gh):
		return gh.Error()
	case errors.As(err, &api):
		return api.Error()
	case errors.As(err, &refusal):
		return refusal.Error()
	case errors.Is(err, engine.ErrNoReport):
		return engine.ErrNoReport.Error()
	case errors.Is(err, errInvalidReport):
		return errInvalidReport.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	default:
		return "unexpected error"
	}
}

func selected(cfg Config, a github.Advisory) bool {
	if cfg.Advisory != "" {
		return strings.EqualFold(a.GHSAID, cfg.Advisory)
	}

	return a.State == "triage" && a.CreatedAt.After(cfg.Since)
}

// commented only trusts the marker in comments of the token owner, a reporter could post it to skip the triage.
func commented(comments []github.Comment, login string) bool {
	for _, c := range comments {
		if c.User.Login == login && strings.Contains(c.Body, report.Marker) {
			return true
		}
	}

	return false
}

// triage runs two models so that no context holds both the untrusted report and the embargoed
// advisories: the reader sees the report with public tools only, the comparator sees the other
// advisories but only gets validated code locations from the reader and can only answer with
// GHSA identifiers and enums.
func triage(ctx context.Context, cfg Config, gh GitHub, eng engine.Engine, a github.Advisory, all []github.Advisory) error {
	code := repo.Repo{Dir: cfg.RepoPath}
	others := make([]github.Advisory, 0, len(all))
	byID := make(map[string]github.Advisory, len(all))
	for _, o := range all {
		if o.GHSAID == a.GHSAID {
			continue
		}
		others = append(others, o)
		byID[o.GHSAID] = o
	}
	policy := securityPolicy(code)

	system, err := systemPrompt(cfg.RepoPath)
	if err != nil {
		return err
	}
	properties, required := report.ReaderProperties()
	readerTools := append(append(tools.Code(code), tools.Issues(gh, cfg.Repo)...), submit("Submit the triage report", properties, required))
	raw, err := eng.Run(ctx, system, readerPrompt(cfg.Repo, a, policy), readerTools)
	if err != nil {
		return err
	}
	r := report.Report{Policy: policy}
	if err := json.Unmarshal(raw, &r); err != nil {
		return errInvalidReport
	}

	if clues := report.Clues(r); len(others) > 0 && len(clues.Locations) > 0 {
		properties, required := report.ComparatorProperties()
		comparatorTools := append(append(tools.Code(code), tools.Advisories(others)...), submit("Submit the duplicates", properties, required))
		raw, err := eng.Run(ctx, skill.Compare, comparatorPrompt(clues), comparatorTools)
		if err != nil {
			return err
		}
		var c struct {
			Duplicates []report.Duplicate `json:"duplicates"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return errInvalidReport
		}
		r.Duplicates = c.Duplicates
	}

	checker := report.Checker{Repo: cfg.Repo, Issues: gh, Code: code, Advisories: byID}
	if err := checker.Verify(ctx, &r); err != nil {
		return fmt.Errorf("verifying the report: %w", err)
	}

	return gh.PostComment(ctx, cfg.Repo, a.GHSAID, report.Render(r))
}

func submit(description string, properties map[string]any, required []string) tools.Tool {
	return tools.Tool{
		Name:        tools.Submit,
		Description: description + ". Call it exactly once, when the investigation is done.",
		Properties:  properties,
		Required:    required,
	}
}

func systemPrompt(repoPath string) (string, error) {
	profile, err := os.ReadFile(filepath.Join(repoPath, ProfilePath))
	if errors.Is(err, os.ErrNotExist) {
		return skill.Text, nil
	}
	if err != nil {
		return "", err
	}

	return skill.Text + "\n## Project guidance\n\n" + string(profile), nil
}

// securityPolicy returns the path of the security policy in one of the locations GitHub recognises, or "".
func securityPolicy(code repo.Repo) string {
	for _, path := range []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"} {
		if code.Exists(path) {
			return path
		}
	}

	return ""
}

func readerPrompt(repoName string, a github.Advisory, policy string) string {
	policyHint := "The repository has no security policy file, leave policy_exclusions empty."
	if policy != "" {
		policyHint = fmt.Sprintf("The repository security policy is in %s. Read it and list the points that may exclude this report.", policy)
	}

	return fmt.Sprintf(`Triage the security report below, filed on %s as %s.

Use the tools to investigate the repository code, its issues and pull requests. %s When you are done, call %s with your findings.

<report>
Title: %s

%s
</report>`, repoName, a.GHSAID, policyHint, tools.Submit, a.Summary, a.Description)
}

func comparatorPrompt(c report.Comparison) string {
	clues, _ := json.Marshal(c)

	return fmt.Sprintf(`A new security report was filed on this repository. You will not see it. Here is where its bug lives (files, symbols and lines, 0 when unknown), the PHP entry points it goes through and its CWE, as JSON:

%s

Find the other advisories that describe the same bug, then call %s.`, clues, tools.Submit)
}
