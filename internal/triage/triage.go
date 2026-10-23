// Package triage selects the advisories to triage, runs the model on each and publishes the result.
package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexandre-daubois/securibot/internal/engine"
	"github.com/alexandre-daubois/securibot/internal/github"
	"github.com/alexandre-daubois/securibot/internal/repo"
	"github.com/alexandre-daubois/securibot/internal/report"
	"github.com/alexandre-daubois/securibot/internal/tools"
	"github.com/alexandre-daubois/securibot/skill"
)

// ProfilePath holds project-specific guidance, relative to the repository root.
const ProfilePath = ".github/securibot.md"

var errInvalidReport = errors.New("the model submitted an invalid report")

type GitHub interface {
	tools.GitHub
	report.IssueGetter
	ListAdvisories(ctx context.Context, repo, state string) ([]github.Advisory, error)
	ListComments(ctx context.Context, repo, ghsa string) ([]github.Comment, error)
	PostComment(ctx context.Context, repo, ghsa, body string) error
}

type Config struct {
	Repo string
	// Since excludes advisories created before it, so a first run does not comment the backlog.
	Since time.Time
	// Advisory targets a single advisory and bypasses Since.
	Advisory string
	DryRun   bool
	RepoPath string
	// Output receives the comments in dry-run mode.
	Output io.Writer
}

// Run never logs report content, GHSA identifiers nor raw errors: logs of public repositories are public.
func Run(ctx context.Context, cfg Config, gh GitHub, eng engine.Engine, log *slog.Logger) error {
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
		if commented(comments) {
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

func commented(comments []github.Comment) bool {
	for _, c := range comments {
		if strings.Contains(c.Body, report.Marker) {
			return true
		}
	}

	return false
}

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

	properties, required := report.Properties()
	ts := append(tools.Build(gh, cfg.Repo, code, others), tools.Tool{
		Name:        tools.Submit,
		Description: "Submit the final triage report. Call it exactly once, when the investigation is done.",
		Properties:  properties,
		Required:    required,
	})

	system, err := systemPrompt(cfg.RepoPath)
	if err != nil {
		return err
	}

	raw, err := eng.Run(ctx, system, prompt(cfg.Repo, a, policy), ts)
	if err != nil {
		return err
	}

	r := report.Report{Policy: policy}
	if err := json.Unmarshal(raw, &r); err != nil {
		return errInvalidReport
	}

	checker := report.Checker{Repo: cfg.Repo, Issues: gh, Code: code, Advisories: byID}
	if err := checker.Verify(ctx, &r); err != nil {
		return fmt.Errorf("verifying the report: %w", err)
	}

	body := report.Render(r)
	if cfg.DryRun {
		_, err := fmt.Fprintf(cfg.Output, "## %s\n\n%s\n", a.GHSAID, body)

		return err
	}

	return gh.PostComment(ctx, cfg.Repo, a.GHSAID, body)
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

func prompt(repoName string, a github.Advisory, policy string) string {
	policyHint := "The repository has no security policy file, leave policy_exclusions empty."
	if policy != "" {
		policyHint = fmt.Sprintf("The repository security policy is in %s. Read it and list the points that may exclude this report.", policy)
	}

	return fmt.Sprintf(`Triage the security report below, filed on %s as %s.

Use the tools to investigate the repository, its other advisories, issues and pull requests. %s When you are done, call %s with your findings.

<report>
Title: %s

%s
</report>`, repoName, a.GHSAID, policyHint, tools.Submit, a.Summary, a.Description)
}
