package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/php/tamis/internal/board"
	"github.com/php/tamis/internal/engine"
	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/sandbox"
	"github.com/php/tamis/internal/setup"
	"github.com/php/tamis/internal/triage"
)

// defaultCodexTokenModel is Codex's default with a ChatGPT account, which does not serve the API models.
const defaultCodexTokenModel = "gpt-6.1-sol"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

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

	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "create-board":
		err = createBoard(ctx, os.Args[2:])
	case len(os.Args) > 1 && os.Args[1] == "init":
		err = initProject(ctx, os.Args[2:], os.Stdout)
	default:
		err = run(ctx, log)
	}
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

// createBoard creates the project board of an organisation and prints the value of the project input.
func createBoard(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tamis create-board ORG")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return errors.New("GH_TOKEN is required")
	}
	project, err := board.Create(ctx, github.New(token), args[0], "tamis")
	if err != nil {
		return err
	}
	fmt.Println(project)

	return nil
}

// initProject installs tamis for a project, then prints what is left to do by hand.
func initProject(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	repository := fs.String("repository", "", `project whose advisories are triaged, as "org/name"`)
	runner := fs.String("runner", "tamis-runner", "private repository created in the same organisation to run the workflow")
	references := fs.String("references", "", "whitespace-separated git references of every supported branch, the analysed one first")
	provider := fs.String("engine", "claude", "LLM provider, claude or openai")
	appName := fs.String("app-name", "", `name of the GitHub App, "<org>-tamis" by default`)
	withBoard := fs.Bool("board", false, "also create a private project board and fill it instead of commenting")
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	org, _, _ := strings.Cut(*repository, "/")
	refs := strings.Fields(*references)
	if org == "" || len(refs) == 0 {
		return errors.New("usage: tamis init -repository org/name -references \"main ...\" [-runner name] [-engine claude|openai] [-app-name name] [-board]")
	}
	if len(refs) > 10 {
		return errors.New("-references must list at most ten references")
	}
	if *provider != "claude" && *provider != "openai" {
		return fmt.Errorf("unknown engine %q, expected claude or openai", *provider)
	}
	token, apiKey := os.Getenv("GH_TOKEN"), os.Getenv("LLM_API_KEY")
	if token == "" || apiKey == "" {
		return errors.New("GH_TOKEN and LLM_API_KEY are required")
	}
	cfg := setup.Config{
		Repository: *repository,
		Runner:     *runner,
		References: refs,
		Engine:     *provider,
		APIKey:     apiKey,
		AppName:    cmp.Or(*appName, org+"-tamis"),
		Since:      time.Now().UTC().Format(time.DateOnly),
		Board:      *withBoard,
	}
	app := func(ctx context.Context, org string, manifest map[string]any) (string, error) {
		return setup.AppCode(ctx, org, manifest, func(u string) {
			fmt.Fprintf(out, "Confirm the GitHub App in your browser, or open %s\n", u)
			openBrowser(u)
		})
	}
	install, err := setup.Run(ctx, cfg, github.New(token), app, out)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nInstall the App on %s only, with \"Only select repositories\": %s\n", *repository, install)
	fmt.Fprintf(out, "Then trigger a first run on a test advisory: gh workflow run tamis.yml -R %s/%s -f advisory=GHSA-xxxx-xxxx-xxxx\n", org, *runner)
	openBrowser(install)

	return nil
}

// openBrowser does its best, the address is printed anyway.
func openBrowser(u string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", u).Start()
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		exec.Command("xdg-open", u).Start()
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	cfg := triage.Config{
		Repo:             os.Getenv("REPOSITORY"),
		Advisory:         os.Getenv("ADVISORY"),
		RepoPath:         os.Getenv("REPO_PATH"),
		BotLogin:         os.Getenv("BOT_LOGIN"),
		Project:          os.Getenv("PROJECT"),
		IssuesRepository: os.Getenv("ISSUES_REPOSITORY"),
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
	comment := false
	if v := os.Getenv("COMMENT"); v != "" {
		if comment, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("COMMENT: %w", err)
		}
	}
	cfg.NoComment = !comment
	// Without comments, triaging the backlog only fills the private board, so every advisory in triage goes.
	if since.IsZero() && cfg.Advisory == "" && comment {
		return errors.New("SINCE is required with COMMENT unless ADVISORY is set, so that existing advisories are left alone")
	}
	cfg.Since = since

	if cfg.Repo == "" {
		return errors.New("REPOSITORY is required")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return errors.New("GH_TOKEN is required")
	}
	if cfg.IssuesRepository != "" {
		issues := os.Getenv("ISSUES_TOKEN")
		if issues == "" || issues == token {
			return errors.New("ISSUES_REPOSITORY needs an ISSUES_TOKEN of its own, which only reaches that repository")
		}
		cfg.Issues = github.New(issues)
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
