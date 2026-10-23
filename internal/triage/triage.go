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

func Run(ctx context.Context, cfg Config, gh GitHub, eng engine.Engine, log *slog.Logger) error {
	all, err := gh.ListAdvisories(ctx, cfg.Repo, "")
	if err != nil {
		return err
	}

	var failed int
	for _, a := range all {
		if !selected(cfg, a) {
			continue
		}

		comments, err := gh.ListComments(ctx, cfg.Repo, a.GHSAID)
		if err != nil {
			log.Error("listing comments", "advisory", a.GHSAID, "error", err)
			failed++
			continue
		}
		if commented(comments) {
			log.Info("already triaged", "advisory", a.GHSAID)
			continue
		}

		log.Info("triaging", "advisory", a.GHSAID)
		if err := triage(ctx, cfg, gh, eng, a, all); err != nil {
			log.Error("triage failed", "advisory", a.GHSAID, "error", err)
			failed++
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d advisory(ies) failed", failed)
	}

	return nil
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
	urls := make(map[string]string, len(all))
	for _, o := range all {
		if o.GHSAID == a.GHSAID {
			continue
		}
		others = append(others, o)
		urls[o.GHSAID] = o.HTMLURL
	}

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

	raw, err := eng.Run(ctx, system, prompt(cfg.Repo, a), ts)
	if err != nil {
		return err
	}

	var r report.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("decoding the report: %w", err)
	}

	checker := report.Checker{Repo: cfg.Repo, Issues: gh, Code: code, Advisories: urls}
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

func prompt(repoName string, a github.Advisory) string {
	return fmt.Sprintf(`Triage the security report below, filed on %s as %s.

Use the tools to investigate the repository, its other advisories, issues and pull requests. When you are done, call %s with your findings.

<report>
Title: %s

%s
</report>`, repoName, a.GHSAID, tools.Submit, a.Summary, a.Description)
}
