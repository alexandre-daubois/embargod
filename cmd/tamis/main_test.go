package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Time{
		"":                     {},
		"2026-10-22":           time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
		"2026-10-22T14:00:00Z": time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC),
	} {
		got, err := parseSince(in)
		assert.NoError(t, err, "%q", in)
		assert.WithinDuration(t, want, got, 0, "%q", in)
	}

	_, err := parseSince("yesterday")
	assert.Error(t, err, "an invalid date should fail")
}

func TestNewEngine(t *testing.T) {
	for name, want := range map[string]string{"": "claude", "claude": "claude", "openai": "codex"} {
		_, agent, model, err := newEngine(name, "", "key")
		assert.NoError(t, err, "%q", name)
		assert.Equal(t, want, agent, "%q", name)
		assert.NotEmpty(t, model, "%q", name)
	}

	eng, agent, model, err := newEngine("openai", "", "at-token")
	assert.NoError(t, err, "a Codex access token")
	assert.Nil(t, eng, "a Codex access token")
	assert.Equal(t, "codex-token", agent, "a Codex access token")
	assert.Equal(t, defaultCodexTokenModel, model, "a Codex access token")

	eng, agent, _, _ = newEngine("claude", "", "at-key")
	assert.NotNil(t, eng, "only the openai engine reads a Codex access token")
	assert.Equal(t, "claude", agent, "only the openai engine reads a Codex access token")

	_, _, model, _ = newEngine("claude", "claude-sonnet-5-5", "key")
	assert.Equal(t, "claude-sonnet-5-5", model, "an explicit model should be kept")

	_, _, _, err = newEngine("gemini", "", "key")
	assert.Error(t, err, "an unknown engine should fail")
	_, _, _, err = newEngine("claude", "", "")
	assert.Error(t, err, "a missing API key should fail")
}

func TestRunValidatesConfiguration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"since required":        {map[string]string{"REPOSITORY": "o/r", "GH_TOKEN": "t", "LLM_API_KEY": "k", "COMMENT": "true"}, "SINCE is required with COMMENT"},
		"since optional":        {map[string]string{"REPOSITORY": "o/r", "GH_TOKEN": "t", "LLM_API_KEY": "k"}, "OUTPUT_DIR is required"},
		"token required":        {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "LLM_API_KEY": "k"}, "GH_TOKEN is required"},
		"api key required":      {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t"}, "LLM_API_KEY is required"},
		"invalid daybreak":      {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "DAYBREAK": "maybe"}, "DAYBREAK"},
		"daybreak needs openai": {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "DAYBREAK": "true"}, "DAYBREAK requires ENGINE=openai"},
		"output required":       {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k"}, "OUTPUT_DIR is required"},
		"issues token required": {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "ISSUES_REPOSITORY": "o/r-security"}, "ISSUES_REPOSITORY needs an ISSUES_TOKEN of its own"},
		"issues token reused":   {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "ISSUES_REPOSITORY": "o/r-security", "ISSUES_TOKEN": "t"}, "ISSUES_REPOSITORY needs an ISSUES_TOKEN of its own"},
		"invalid comment":       {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "COMMENT": "maybe"}, "COMMENT"},
		"references required":   {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "OUTPUT_DIR": t.TempDir()}, "REFERENCES must list"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"REPOSITORY", "GITHUB_REPOSITORY", "ADVISORY", "REPO_PATH", "BOT_LOGIN", "DAYBREAK", "SINCE", "GH_TOKEN", "ENGINE", "MODEL", "LLM_API_KEY", "OUTPUT_DIR", "REFERENCES", "PROJECT", "ISSUES_REPOSITORY", "ISSUES_TOKEN", "COMMENT"} {
				t.Setenv(k, tc.env[k])
			}

			require.ErrorContains(t, run(context.Background(), log), tc.want)
		})
	}
}

func TestCreateBoardValidatesArguments(t *testing.T) {
	for name, tc := range map[string]struct {
		args  []string
		token string
		want  string
	}{
		"no organisation": {nil, "t", "usage: tamis create-board ORG"},
		"two arguments":   {[]string{"acme", "extra"}, "t", "usage: tamis create-board ORG"},
		"token required":  {[]string{"acme"}, "", "GH_TOKEN is required"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GH_TOKEN", tc.token)

			require.EqualError(t, createBoard(context.Background(), tc.args), tc.want)
		})
	}
}

func TestInitValidatesArguments(t *testing.T) {
	for name, tc := range map[string]struct {
		args       []string
		token, key string
		want       string
	}{
		"no repository":  {[]string{"-references", "main"}, "t", "k", "usage: tamis init"},
		"no org":         {[]string{"-repository", "/project", "-references", "main"}, "t", "k", "usage: tamis init"},
		"no references":  {[]string{"-repository", "acme/project"}, "t", "k", "usage: tamis init"},
		"11 references":  {[]string{"-repository", "acme/project", "-references", "a b c d e f g h i j k"}, "t", "k", "-references must list at most ten references"},
		"unknown engine": {[]string{"-repository", "acme/project", "-references", "main", "-engine", "gemini"}, "t", "k", `unknown engine "gemini"`},
		"no token":       {[]string{"-repository", "acme/project", "-references", "main"}, "", "k", "GH_TOKEN and LLM_API_KEY are required"},
		"no key":         {[]string{"-repository", "acme/project", "-references", "main"}, "t", "", "GH_TOKEN and LLM_API_KEY are required"},
		"unknown flag":   {[]string{"-repo", "acme/project"}, "t", "k", "flag provided but not defined: -repo"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GH_TOKEN", tc.token)
			t.Setenv("LLM_API_KEY", tc.key)

			require.ErrorContains(t, initProject(context.Background(), tc.args, io.Discard), tc.want)
		})
	}
}

func TestInitHelpIsNotAnError(t *testing.T) {
	require.NoError(t, initProject(context.Background(), []string{"-h"}, io.Discard))
}

// GitHub refuses to run an action whose manifest does not parse, with no test of its own to tell.
func TestActionManifestParses(t *testing.T) {
	data, err := os.ReadFile("../../action.yml")
	require.NoError(t, err)
	var manifest struct {
		Inputs map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"inputs"`
	}

	require.NoError(t, yaml.Unmarshal(data, &manifest))

	require.NotEmpty(t, manifest.Inputs)
	for name, input := range manifest.Inputs {
		require.NotEmpty(t, input.Description, "the %s input lost its description", name)
	}
	require.Error(t, yaml.Unmarshal([]byte("inputs:\n  since:\n    description: Required with `comment: true` unless set.\n"), &manifest), "the test would not catch the colon that broke the manifest")
}
