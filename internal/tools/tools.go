// Package tools defines the read-only tools the model can call while triaging.
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alexandre-daubois/securibot/internal/github"
	"github.com/alexandre-daubois/securibot/internal/repo"
)

// Submit is the tool the model calls with its final report, which ends the run.
const Submit = "submit_report"

type Tool struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
	Run         func(ctx context.Context, input json.RawMessage) (string, error)
}

type GitHub interface {
	GetAdvisory(ctx context.Context, repo, ghsa string) (github.Advisory, error)
	SearchIssues(ctx context.Context, repo, query string) ([]github.Issue, error)
}

type advisoryBrief struct {
	GHSAID    string   `json:"ghsa_id"`
	State     string   `json:"state"`
	Summary   string   `json:"summary"`
	CWEIDs    []string `json:"cwe_ids"`
	CreatedAt string   `json:"created_at"`
}

// Build returns the investigation tools for one advisory. others lists every other advisory of the repository.
func Build(gh GitHub, repoName string, r repo.Repo, others []github.Advisory) []Tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	integer := func(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

	return []Tool{
		{
			Name:        "list_advisories",
			Description: "List every other security advisory of the repository, in any state (triage, draft, published, closed), with its summary and CWEs.",
			Run: func(context.Context, json.RawMessage) (string, error) {
				briefs := make([]advisoryBrief, 0, len(others))
				for _, a := range others {
					briefs = append(briefs, advisoryBrief{a.GHSAID, a.State, a.Summary, a.CWEIDs, a.CreatedAt.Format("2006-01-02")})
				}

				return marshal(briefs)
			},
		},
		{
			Name:        "get_advisory",
			Description: "Get the full description of another security advisory of the repository.",
			Properties:  map[string]any{"ghsa_id": str("GHSA identifier, e.g. GHSA-xxxx-xxxx-xxxx")},
			Required:    []string{"ghsa_id"},
			Run: func(ctx context.Context, input json.RawMessage) (string, error) {
				in, err := decode[struct {
					GHSAID string `json:"ghsa_id"`
				}](input)
				if err != nil {
					return "", err
				}
				a, err := gh.GetAdvisory(ctx, repoName, in.GHSAID)
				if err != nil {
					return "", err
				}

				return marshal(a)
			},
		},
		{
			Name:        "search_issues",
			Description: "Search public issues and pull requests of the repository with GitHub search syntax, e.g. `ext/standard overflow is:pr`.",
			Properties:  map[string]any{"query": str("GitHub search query, the repository qualifier is added automatically")},
			Required:    []string{"query"},
			Run: func(ctx context.Context, input json.RawMessage) (string, error) {
				in, err := decode[struct {
					Query string `json:"query"`
				}](input)
				if err != nil {
					return "", err
				}
				issues, err := gh.SearchIssues(ctx, repoName, in.Query)
				if err != nil {
					return "", err
				}

				return marshal(issues)
			},
		},
		{
			Name:        "grep_code",
			Description: "Search the repository source with an extended regular expression (git grep -E). Returns file:line:content.",
			Properties:  map[string]any{"pattern": str("extended regular expression"), "path": str("optional file or directory to narrow the search")},
			Required:    []string{"pattern"},
			Run: func(_ context.Context, input json.RawMessage) (string, error) {
				in, err := decode[struct {
					Pattern string `json:"pattern"`
					Path    string `json:"path"`
				}](input)
				if err != nil {
					return "", err
				}

				return r.Grep(in.Pattern, in.Path)
			},
		},
		{
			Name:        "read_file",
			Description: "Read a file of the repository with line numbers, at most 400 lines per call.",
			Properties:  map[string]any{"path": str("path relative to the repository root"), "start": integer("first line, defaults to 1"), "end": integer("last line")},
			Required:    []string{"path"},
			Run: func(_ context.Context, input json.RawMessage) (string, error) {
				in, err := decode[struct {
					Path  string `json:"path"`
					Start int    `json:"start"`
					End   int    `json:"end"`
				}](input)
				if err != nil {
					return "", err
				}

				return r.ReadFile(in.Path, in.Start, in.End)
			},
		},
		{
			Name:        "git_log",
			Description: "Show the 30 latest commits, optionally touching a path and/or whose message matches a pattern. Useful to spot fixes and hardenings already merged.",
			Properties:  map[string]any{"path": str("optional file or directory"), "grep": str("optional case-insensitive pattern on commit messages")},
			Run: func(_ context.Context, input json.RawMessage) (string, error) {
				in, err := decode[struct {
					Path string `json:"path"`
					Grep string `json:"grep"`
				}](input)
				if err != nil {
					return "", err
				}

				return r.Log(in.Path, in.Grep)
			},
		},
	}
}

// Call runs the named tool. Failures are returned as text for the model, with isError set.
func Call(ctx context.Context, ts []Tool, name string, input json.RawMessage) (string, bool) {
	for _, t := range ts {
		if t.Name != name {
			continue
		}
		out, err := t.Run(ctx, input)
		if err != nil {
			return "error: " + err.Error(), true
		}

		return out, false
	}

	return fmt.Sprintf("error: unknown tool %q", name), true
}

func decode[T any](input json.RawMessage) (T, error) {
	var v T
	if len(input) == 0 {
		return v, nil
	}

	return v, json.Unmarshal(input, &v)
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)

	return string(b), err
}
