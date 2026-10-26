// Package tools defines the read-only tools the models can call while triaging.
//
// The comparator, which reads one embargoed advisory but never the report, gets Code and Advisory.
// The reader runs in the sandbox package with its own tools.
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/repo"
)

// Submit is the tool the model calls with its final answer, which ends the run.
const Submit = "submit"

type Tool struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
	Run         func(ctx context.Context, input json.RawMessage) (string, error)
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// Code returns the tools reading the repository checkout.
func Code(r repo.Repo) []Tool {
	return []Tool{
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

// Advisory returns one candidate without exposing another report in the same model context.
func Advisory(a github.Advisory) Tool {
	return Tool{
		Name:        "get_advisory",
		Description: "Get the full description of the one candidate advisory.",
		Run: func(context.Context, json.RawMessage) (string, error) {
			return marshal(a)
		},
	}
}

// Validate checks a submission with the Run of the submit tool, when it has one. The error is meant
// for the model, so it can fix its answer.
func Validate(ctx context.Context, ts []Tool, input json.RawMessage) error {
	for _, t := range ts {
		if t.Name == Submit && t.Run != nil {
			_, err := t.Run(ctx, input)

			return err
		}
	}

	return nil
}

// Call runs the named tool. Failures are returned as text for the model, with isError set.
func Call(ctx context.Context, ts []Tool, name string, input json.RawMessage) (string, bool) {
	for _, t := range ts {
		if t.Name != name || t.Run == nil {
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
