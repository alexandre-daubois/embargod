package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		"since required":        {map[string]string{"REPOSITORY": "o/r", "GH_TOKEN": "t", "LLM_API_KEY": "k"}, "SINCE is required"},
		"token required":        {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "LLM_API_KEY": "k"}, "GH_TOKEN is required"},
		"api key required":      {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t"}, "LLM_API_KEY is required"},
		"invalid daybreak":      {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "DAYBREAK": "maybe"}, "DAYBREAK"},
		"daybreak needs openai": {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "DAYBREAK": "true"}, "DAYBREAK requires ENGINE=openai"},
		"output required":       {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k"}, "OUTPUT_DIR is required"},
		"issues token required": {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "ISSUES_REPOSITORY": "o/r-security"}, "ISSUES_REPOSITORY needs an ISSUES_TOKEN of its own"},
		"issues token reused":   {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "ISSUES_REPOSITORY": "o/r-security", "ISSUES_TOKEN": "t"}, "ISSUES_REPOSITORY needs an ISSUES_TOKEN of its own"},
		"references required":   {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "OUTPUT_DIR": t.TempDir()}, "REFERENCES must list"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"REPOSITORY", "GITHUB_REPOSITORY", "ADVISORY", "REPO_PATH", "BOT_LOGIN", "DAYBREAK", "SINCE", "GH_TOKEN", "ENGINE", "MODEL", "LLM_API_KEY", "OUTPUT_DIR", "REFERENCES", "PROJECT", "ISSUES_REPOSITORY", "ISSUES_TOKEN"} {
				t.Setenv(k, tc.env[k])
			}

			require.ErrorContains(t, run(context.Background(), log), tc.want)
		})
	}
}
