package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/alexandre-daubois/tamis/internal/engine"
	"github.com/alexandre-daubois/tamis/internal/github"
	"github.com/alexandre-daubois/tamis/internal/sandbox"
	"github.com/alexandre-daubois/tamis/internal/triage"
)

// defaultCodexTokenModel is Codex's default with a ChatGPT account, which does not serve the API models.
const defaultCodexTokenModel = "gpt-6.1-sol"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// A panic value may hold report content, and logs of public repositories are public.
	// The triage runs on this goroutine only, so this recover sees every panic of ours.
	defer func() {
		if recover() != nil {
			log.Error("internal error")
			os.Exit(2)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, log); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	cfg := triage.Config{
		Repo:     os.Getenv("REPOSITORY"),
		Advisory: os.Getenv("ADVISORY"),
		RepoPath: os.Getenv("REPO_PATH"),
		BotLogin: os.Getenv("BOT_LOGIN"),
	}
	if cfg.Repo == "" {
		cfg.Repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if cfg.RepoPath == "" {
		cfg.RepoPath = "."
	}

	since, err := parseSince(os.Getenv("SINCE"))
	if err != nil {
		return err
	}
	if since.IsZero() && cfg.Advisory == "" {
		return errors.New("SINCE is required unless ADVISORY is set, so that existing advisories are left alone")
	}
	cfg.Since = since

	if cfg.Repo == "" {
		return errors.New("REPOSITORY is required")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return errors.New("GH_TOKEN is required")
	}
	eng, agent, model, err := newEngine(os.Getenv("ENGINE"), os.Getenv("MODEL"), os.Getenv("LLM_API_KEY"))
	if err != nil {
		return err
	}
	daybreak := false
	if v := os.Getenv("DAYBREAK"); v != "" {
		if daybreak, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("DAYBREAK: %w", err)
		}
	}
	if daybreak && !strings.HasPrefix(agent, "codex") {
		return errors.New("DAYBREAK requires ENGINE=openai")
	}
	cfg.OutputDir = os.Getenv("OUTPUT_DIR")
	if cfg.OutputDir == "" {
		return errors.New("OUTPUT_DIR is required and must be private")
	}
	cfg.References = strings.Fields(os.Getenv("REFERENCES"))
	if len(cfg.References) == 0 || len(cfg.References) > 10 {
		return errors.New("REFERENCES must list between one and ten local source references")
	}
	reader, err := sandbox.New(agent, model, os.Getenv("LLM_API_KEY"), os.Getenv("RUNNER_IMAGE"))
	if err != nil {
		return err
	}
	defer reader.Close()
	reader.Daybreak = daybreak

	return triage.Run(ctx, cfg, github.New(token), reader, eng, log)
}

func parseSince(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.DateOnly, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("SINCE must be a date (2026-10-22) or an RFC 3339 timestamp: %w", err)
	}

	return t, nil
}

// newEngine returns the comparator engine, and the sandboxed agent and model the reader runs with. A Codex
// access token cannot call the OpenAI API, so the comparator runs as a sandboxed agent too: no engine.
func newEngine(name, model, apiKey string) (engine.Engine, string, string, error) {
	if apiKey == "" {
		return nil, "", "", errors.New("LLM_API_KEY is required")
	}

	switch name {
	case "", "claude":
		if model == "" {
			model = engine.DefaultClaudeModel
		}
		return engine.NewClaude(apiKey, model), "claude", model, nil
	case "openai":
		if strings.HasPrefix(apiKey, "at-") {
			return nil, "codex-token", cmp.Or(model, defaultCodexTokenModel), nil
		}
		if model == "" {
			model = engine.DefaultOpenAIModel
		}
		return engine.NewOpenAI(apiKey, model), "codex", model, nil
	default:
		return nil, "", "", fmt.Errorf("unknown ENGINE %q, expected claude or openai", name)
	}
}
