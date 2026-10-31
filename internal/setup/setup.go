// Package setup installs tamis for a project: GitHub App, private workflow repository, secrets and workflow.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/php/tamis/internal/board"
	"github.com/php/tamis/internal/github"
)

type GitHub interface {
	board.Creator
	GetRepository(ctx context.Context, repo string) (github.Repository, error)
	LatestRelease(ctx context.Context, repo string) (string, string, error)
	AppExists(ctx context.Context, slug string) (bool, error)
	ConvertManifest(ctx context.Context, code string) (github.App, error)
	CreateRepository(ctx context.Context, org, name string) (github.Repository, error)
	CreateEnvironment(ctx context.Context, repo, env, branch string) error
	SetEnvironmentVariable(ctx context.Context, repo, env, name, value string) error
	SetEnvironmentSecret(ctx context.Context, repo, env, name, value string) error
	CreateFile(ctx context.Context, repo, path, message string, content []byte) error
}

type Config struct {
	// Repository is the project, as "org/name", and Runner the name of the private repository created next to it.
	Repository, Runner string
	References         []string
	// Engine is "claude" or "openai", APIKey its key.
	Engine, APIKey string
	AppName        string
	// Since is the date the workflow starts from, as YYYY-MM-DD.
	Since string
	Board bool
}

// AppFlow registers a GitHub App from a manifest and returns the code to convert, as AppCode does.
type AppFlow func(ctx context.Context, org string, manifest map[string]any) (string, error)

// Run creates the App, the runner repository with its tamis environment, and the workflow, then returns the
// address the App is installed from. The App reaches no repository until a maintainer installs it.
func Run(ctx context.Context, cfg Config, gh GitHub, app AppFlow, out io.Writer) (string, error) {
	org, name, _ := strings.Cut(cfg.Repository, "/")
	if org == "" || name == "" {
		return "", errors.New(`the repository must be given as "org/name"`)
	}
	repo, err := gh.GetRepository(ctx, cfg.Repository)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", cfg.Repository, err)
	}
	// GitHub serves repository security advisories for public repositories only.
	if repo.Private {
		return "", fmt.Errorf("%s is private, and only public repositories have security advisories", cfg.Repository)
	}
	runner := org + "/" + cfg.Runner
	if _, err := gh.GetRepository(ctx, runner); err == nil {
		return "", fmt.Errorf("%s already exists", runner)
	} else if !errors.Is(err, github.ErrNotFound) {
		return "", fmt.Errorf("reading %s: %w", runner, err)
	}
	// GitHub only tells a taken App name on its creation page, once the browser is open. The name is looked up as
	// the slug, so a name GitHub turns into another slug is still left to that page.
	taken, err := gh.AppExists(ctx, cfg.AppName)
	if err != nil {
		return "", fmt.Errorf("reading the GitHub App %s: %w", cfg.AppName, err)
	}
	if taken {
		return "", fmt.Errorf("the GitHub App %s already exists", cfg.AppName)
	}
	tag, sha, err := gh.LatestRelease(ctx, "php/tamis")
	if err != nil {
		return "", fmt.Errorf("reading the latest tamis release: %w", err)
	}

	permissions := map[string]string{"repository_advisories": "write"}
	if cfg.Board {
		permissions["organization_projects"] = "write"
	}
	code, err := app(ctx, org, map[string]any{
		"name":                cfg.AppName,
		"url":                 "https://github.com/php/tamis",
		"description":         "First-pass triage of new security advisories",
		"public":              false,
		"hook_attributes":     map[string]any{"url": "https://github.com/php/tamis", "active": false},
		"default_permissions": permissions,
	})
	if err != nil {
		return "", err
	}
	a, err := gh.ConvertManifest(ctx, code)
	if err != nil {
		return "", fmt.Errorf("reading the credentials of the GitHub App: %w", err)
	}
	fmt.Fprintf(out, "Created the GitHub App %s\n", a.Slug)

	r, err := gh.CreateRepository(ctx, org, cfg.Runner)
	if err != nil {
		return "", fmt.Errorf("creating %s: %w", runner, err)
	}
	if err := gh.CreateEnvironment(ctx, runner, "tamis", r.DefaultBranch); err != nil {
		return "", fmt.Errorf("creating the tamis environment of %s: %w", runner, err)
	}
	secret := "ANTHROPIC_API_KEY"
	if cfg.Engine == "openai" {
		secret = "OPENAI_API_KEY"
	}
	if err := gh.SetEnvironmentVariable(ctx, runner, "tamis", "TAMIS_CLIENT_ID", a.ClientID); err != nil {
		return "", fmt.Errorf("setting TAMIS_CLIENT_ID: %w", err)
	}
	for _, s := range [][2]string{{"TAMIS_PRIVATE_KEY", a.PEM}, {secret, cfg.APIKey}} {
		if err := gh.SetEnvironmentSecret(ctx, runner, "tamis", s[0], s[1]); err != nil {
			return "", fmt.Errorf("setting %s: %w", s[0], err)
		}
	}
	fmt.Fprintf(out, "Created the private repository %s and its tamis environment\n", runner)

	project := ""
	if cfg.Board {
		if project, err = board.Create(ctx, gh, org, "tamis"); err != nil {
			return "", err
		}
		fmt.Fprintf(out, "Created the project board %s\n", project)
	}
	var w strings.Builder
	if err := workflow.Execute(&w, map[string]any{
		"Org": org, "Name": name, "Repository": cfg.Repository, "SHA": sha, "Tag": tag, "Since": cfg.Since,
		"Engine": cfg.Engine, "Secret": secret, "Slug": a.Slug, "References": strings.Join(cfg.References, " "), "Project": project,
	}); err != nil {
		return "", err
	}
	if err := gh.CreateFile(ctx, runner, ".github/workflows/tamis.yml", "Add the tamis workflow", []byte(w.String())); err != nil {
		return "", fmt.Errorf("adding the workflow to %s: %w", runner, err)
	}
	fmt.Fprintf(out, "Added the workflow, pinned to tamis %s\n", tag)

	return fmt.Sprintf("https://github.com/apps/%s/installations/new", a.Slug), nil
}

// workflow is the workflow of the README quick start, filled in.
var workflow = template.Must(template.New("workflow").Delims("[[", "]]").Parse(`name: tamis

on:
  schedule:
    - cron: "*/15 * * * *"
  workflow_dispatch:
    inputs:
      advisory:
        description: GHSA to triage
        required: false

concurrency:
  group: tamis

jobs:
  triage:
    runs-on: ubuntu-latest
    timeout-minutes: 240
    environment: tamis
    permissions:
      contents: read
    steps:
      - uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0
        id: app
        with:
          client-id: ${{ vars.TAMIS_CLIENT_ID }}
          private-key: ${{ secrets.TAMIS_PRIVATE_KEY }}
          owner: [[.Org]]
          repositories: [[.Name]]
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: [[.Repository]]
          fetch-depth: 0
          persist-credentials: false
      - uses: php/tamis@[[.SHA]] # [[.Tag]]
        with:
          repository: [[.Repository]]
          since: "[[.Since]]"
          advisory: ${{ inputs.advisory }}
[[- if eq .Engine "openai"]]
          engine: openai
[[- end]]
          api-key: ${{ secrets.[[.Secret]] }}
          github-token: ${{ steps.app.outputs.token }}
          bot-login: [[.Slug]][bot]
          references: [[.References]]
[[- if .Project]]
          project: [[.Project]]
[[- else]]
          comment: true
[[- end]]
`))
