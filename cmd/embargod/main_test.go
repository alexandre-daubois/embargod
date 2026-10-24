package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandre-daubois/embargod/internal/report"
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

func TestSigningKey(t *testing.T) {
	for _, value := range []string{"", "not base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		t.Setenv("SIGNING_KEY", value)
		if _, err := signingKey(); err == nil {
			t.Fatal("invalid signing seed accepted")
		}
	}
	t.Setenv("SIGNING_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)))
	if key, err := signingKey(); err != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal("valid seed rejected")
	}
}

func TestVerifyCommand(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	file := filepath.Join(t.TempDir(), "report.md")
	body := report.Sign("verdict\n", "o/r", "GHSA-test", strings.Repeat("a", 64), key)
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--public-key", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), "--repository", "o/r", "--advisory", "GHSA-test", "--file", file}
	if err := verify(args); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body+"forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify(args); err == nil {
		t.Fatal("forged report accepted")
	}
	if err := verify(nil); err == nil {
		t.Fatal("missing verification options accepted")
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
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"REPOSITORY", "GITHUB_REPOSITORY", "ADVISORY", "REPO_PATH", "BOT_LOGIN", "DAYBREAK", "SINCE", "GH_TOKEN", "ENGINE", "MODEL", "LLM_API_KEY"} {
				t.Setenv(k, tc.env[k])
			}

			err := run(context.Background(), log)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
