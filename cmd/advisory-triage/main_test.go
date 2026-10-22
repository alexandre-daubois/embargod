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
	for _, name := range []string{"", "claude", "openai"} {
		if _, err := newEngine(name, "", "key"); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}

	if _, err := newEngine("gemini", "", "key"); err == nil {
		t.Error("an unknown engine should fail")
	}
	if _, err := newEngine("claude", "", ""); err == nil {
		t.Error("a missing API key should fail")
	}
}

func TestRunValidatesConfiguration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"since required":   {map[string]string{"REPOSITORY": "o/r", "GH_TOKEN": "t", "LLM_API_KEY": "k"}, "SINCE is required"},
		"invalid dry run":  {map[string]string{"DRY_RUN": "maybe"}, "DRY_RUN"},
		"token required":   {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "LLM_API_KEY": "k"}, "GH_TOKEN is required"},
		"api key required": {map[string]string{"REPOSITORY": "o/r", "SINCE": "2026-10-22", "GH_TOKEN": "t"}, "LLM_API_KEY is required"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"REPOSITORY", "GITHUB_REPOSITORY", "ADVISORY", "REPO_PATH", "DRY_RUN", "SINCE", "GH_TOKEN", "ENGINE", "MODEL", "LLM_API_KEY", "GITHUB_STEP_SUMMARY"} {
				t.Setenv(k, tc.env[k])
			}

			err := run(context.Background(), log)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
