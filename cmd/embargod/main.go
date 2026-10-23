package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/alexandre-daubois/embargod/internal/engine"
	"github.com/alexandre-daubois/embargod/internal/github"
	"github.com/alexandre-daubois/embargod/internal/triage"
)

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
	eng, err := newEngine(os.Getenv("ENGINE"), os.Getenv("MODEL"), os.Getenv("LLM_API_KEY"))
	if err != nil {
		return err
	}

	return triage.Run(ctx, cfg, github.New(token), eng, log)
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

func newEngine(name, model, apiKey string) (engine.Engine, error) {
	if apiKey == "" {
		return nil, errors.New("LLM_API_KEY is required")
	}

	switch name {
	case "", "claude":
		if model == "" {
			model = engine.DefaultClaudeModel
		}
		return engine.NewClaude(apiKey, model), nil
	case "openai":
		if model == "" {
			model = engine.DefaultOpenAIModel
		}
		return engine.NewOpenAI(apiKey, model), nil
	default:
		return nil, fmt.Errorf("unknown ENGINE %q, expected claude or openai", name)
	}
}
