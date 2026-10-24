package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Time{
		"":                     {},
		"2026-10-22":           time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
		"2026-10-22T14:00:00Z": time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC),
	} {
		got, err := parseSince(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: got %v, %v", in, got, err)
		}
	}

	if _, err := parseSince("yesterday"); err == nil {
		t.Error("an invalid date should fail")
	}
}

func TestNewEngine(t *testing.T) {
	for name, want := range map[string]string{"": "claude", "claude": "claude", "openai": "codex"} {
		if _, agent, model, err := newEngine(name, "", "key"); err != nil || agent != want || model == "" {
			t.Errorf("%q: agent %q, model %q, %v", name, agent, model, err)
		}
	}
	if eng, agent, model, err := newEngine("openai", "", "at-token"); err != nil || eng != nil || agent != "codex-token" || model != defaultCodexTokenModel {
		t.Errorf("a Codex access token: engine %v, agent %q, model %q, %v", eng, agent, model, err)
	}
	if eng, agent, _, _ := newEngine("claude", "", "at-key"); eng == nil || agent != "claude" {
		t.Errorf("only the openai engine reads a Codex access token, got agent %q", agent)
	}
	if _, _, model, _ := newEngine("claude", "claude-sonnet-5-5", "key"); model != "claude-sonnet-5-5" {
		t.Errorf("an explicit model should be kept, got %q", model)
	}

	if _, _, _, err := newEngine("gemini", "", "key"); err == nil {
		t.Error("an unknown engine should fail")
	}
	if _, _, _, err := newEngine("claude", "", ""); err == nil {
		t.Error("a missing API key should fail")
	}
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
		"references required":   {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t", "LLM_API_KEY": "k", "OUTPUT_DIR": t.TempDir()}, "REFERENCES must list"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"REPOSITORY", "GITHUB_REPOSITORY", "ADVISORY", "REPO_PATH", "BOT_LOGIN", "DAYBREAK", "SINCE", "GH_TOKEN", "ENGINE", "MODEL", "LLM_API_KEY", "OUTPUT_DIR", "REFERENCES"} {
				t.Setenv(k, tc.env[k])
			}

			err := run(context.Background(), log)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
