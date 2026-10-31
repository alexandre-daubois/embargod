package setup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/php/tamis/internal/board/boardtest"
	"github.com/php/tamis/internal/github"
)

type fakeGitHub struct {
	*boardtest.Project
	// repos says which repositories exist and whether they are private.
	repos     map[string]bool
	apps      map[string]bool
	created   []string
	branch    string
	variables map[string]string
	secrets   map[string]string
	files     map[string]string
	secretErr error
}

func newFake() *fakeGitHub {
	p := boardtest.New()
	p.Fields = p.Fields[:1]

	return &fakeGitHub{Project: p, repos: map[string]bool{"acme/project": false}, variables: map[string]string{}, secrets: map[string]string{}, files: map[string]string{}}
}

func (f *fakeGitHub) GetRepository(_ context.Context, repo string) (github.Repository, error) {
	private, ok := f.repos[repo]
	if !ok {
		return github.Repository{}, &github.HTTPError{Status: http.StatusNotFound}
	}

	return github.Repository{Private: private}, nil
}

func (f *fakeGitHub) AppExists(_ context.Context, slug string) (bool, error) {
	return f.apps[slug], nil
}

func (f *fakeGitHub) LatestRelease(context.Context, string) (string, string, error) {
	return "v2026.10.30.1", "0123456789abcdef0123456789abcdef01234567", nil
}

func (f *fakeGitHub) ConvertManifest(_ context.Context, code string) (github.App, error) {
	if code != "c0de" {
		return github.App{}, errors.New("unknown code")
	}

	return github.App{Slug: "acme-tamis", ClientID: "Iv1", PEM: "PEM"}, nil
}

func (f *fakeGitHub) CreateRepository(_ context.Context, org, name string) (github.Repository, error) {
	f.created = append(f.created, org+"/"+name)

	return github.Repository{Private: true, DefaultBranch: "main"}, nil
}

func (f *fakeGitHub) CreateEnvironment(_ context.Context, _, _, branch string) error {
	f.branch = branch

	return nil
}

func (f *fakeGitHub) SetEnvironmentVariable(_ context.Context, _, _, name, value string) error {
	f.variables[name] = value

	return nil
}

func (f *fakeGitHub) SetEnvironmentSecret(_ context.Context, _, _, name, value string) error {
	f.secrets[name] = value

	return f.secretErr
}

func (f *fakeGitHub) CreateFile(_ context.Context, repo, path, _ string, content []byte) error {
	f.files[repo+"/"+path] = string(content)

	return nil
}

func config() Config {
	return Config{Repository: "acme/project", Runner: "tamis-runner", References: []string{"main", "origin/release-1"}, Engine: "claude", APIKey: "sk-test", AppName: "acme-tamis", Since: "2026-10-31"}
}

type flow struct {
	org      string
	manifest map[string]any
	err      error
}

func (fl *flow) run(_ context.Context, org string, manifest map[string]any) (string, error) {
	fl.org, fl.manifest = org, manifest

	return "c0de", fl.err
}

// step reads the with: inputs of the tamis step of a workflow.
func step(t *testing.T, workflow string) map[string]string {
	t.Helper()
	var w struct {
		Jobs map[string]struct {
			Environment string `yaml:"environment"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(workflow), &w))
	require.Equal(t, "tamis", w.Jobs["triage"].Environment)
	for _, s := range w.Jobs["triage"].Steps {
		if strings.HasPrefix(s.Uses, "php/tamis@") {
			require.Equal(t, "php/tamis@0123456789abcdef0123456789abcdef01234567", s.Uses)
			return s.With
		}
	}
	t.Fatal("no tamis step")

	return nil
}

func TestRunInstallsTamisWithComments(t *testing.T) {
	gh, fl := newFake(), &flow{}

	install, err := Run(t.Context(), config(), gh, fl.run, io.Discard)

	require.NoError(t, err)
	require.Equal(t, "https://github.com/apps/acme-tamis/installations/new", install)
	require.Equal(t, "acme", fl.org)
	require.Equal(t, map[string]string{"repository_advisories": "write"}, fl.manifest["default_permissions"])
	require.Equal(t, []string{"acme/tamis-runner"}, gh.created)
	require.Equal(t, "main", gh.branch)
	require.Equal(t, map[string]string{"TAMIS_CLIENT_ID": "Iv1"}, gh.variables)
	require.Equal(t, map[string]string{"TAMIS_PRIVATE_KEY": "PEM", "ANTHROPIC_API_KEY": "sk-test"}, gh.secrets)
	with := step(t, gh.files["acme/tamis-runner/.github/workflows/tamis.yml"])
	require.Equal(t, map[string]string{
		"repository":   "acme/project",
		"since":        "2026-10-31",
		"advisory":     "${{ inputs.advisory }}",
		"api-key":      "${{ secrets.ANTHROPIC_API_KEY }}",
		"github-token": "${{ steps.app.outputs.token }}",
		"bot-login":    "acme-tamis[bot]",
		"references":   "main origin/release-1",
		"comment":      "true",
	}, with)
	require.Empty(t, gh.Views, "no board without -board")
}

func TestRunInstallsTamisWithABoardAndOpenAI(t *testing.T) {
	gh, fl := newFake(), &flow{}
	cfg := config()
	cfg.Board, cfg.Engine = true, "openai"

	_, err := Run(t.Context(), cfg, gh, fl.run, io.Discard)

	require.NoError(t, err)
	require.Equal(t, map[string]string{"repository_advisories": "write", "organization_projects": "write"}, fl.manifest["default_permissions"])
	require.Equal(t, map[string]string{"TAMIS_PRIVATE_KEY": "PEM", "OPENAI_API_KEY": "sk-test"}, gh.secrets)
	with := step(t, gh.files["acme/tamis-runner/.github/workflows/tamis.yml"])
	require.Equal(t, "acme/16", with["project"])
	require.Equal(t, "openai", with["engine"])
	require.Equal(t, "${{ secrets.OPENAI_API_KEY }}", with["api-key"])
	require.NotContains(t, with, "comment")
	require.Len(t, gh.Views, 1)
}

func TestRunStopsBeforeCreatingAnything(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*Config, *fakeGitHub, *flow)
		err    string
	}{
		"no org":          {func(c *Config, _ *fakeGitHub, _ *flow) { c.Repository = "project" }, `the repository must be given as "org/name"`},
		"no project":      {func(c *Config, _ *fakeGitHub, _ *flow) { c.Repository = "acme/missing" }, "reading acme/missing: github: HTTP 404"},
		"private project": {func(_ *Config, gh *fakeGitHub, _ *flow) { gh.repos["acme/project"] = true }, "acme/project is private, and only public repositories have security advisories"},
		"app exists":      {func(_ *Config, gh *fakeGitHub, _ *flow) { gh.apps = map[string]bool{"acme-tamis": true} }, "the GitHub App acme-tamis already exists"},
		"runner exists":   {func(_ *Config, gh *fakeGitHub, _ *flow) { gh.repos["acme/tamis-runner"] = true }, "acme/tamis-runner already exists"},
		"app not created": {func(_ *Config, _ *fakeGitHub, fl *flow) { fl.err = errors.New("the GitHub App was not created") }, "the GitHub App was not created"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, gh, fl := config(), newFake(), &flow{}
			tc.change(&cfg, gh, fl)

			_, err := Run(t.Context(), cfg, gh, fl.run, io.Discard)

			require.EqualError(t, err, tc.err)
			require.Empty(t, gh.created)
		})
	}
}

func TestRunReportsAFailedSecret(t *testing.T) {
	gh := newFake()
	gh.secretErr = errors.New("boom")

	_, err := Run(t.Context(), config(), gh, (&flow{}).run, io.Discard)

	require.EqualError(t, err, "setting TAMIS_PRIVATE_KEY: boom")
	require.Empty(t, gh.files)
}

// The README workflow and the generated one pin the same actions, which Renovate updates in neither.
func TestWorkflowPinsTheActionsOfTheREADME(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	var w strings.Builder
	require.NoError(t, workflow.Execute(&w, map[string]any{"Engine": "claude"}))
	pins := regexp.MustCompile(`uses: (actions/\S+ # \S+)`)

	want := pins.FindAllStringSubmatch(string(readme), -1)
	require.NotEmpty(t, want)
	require.Equal(t, want, pins.FindAllStringSubmatch(w.String(), -1))
}
