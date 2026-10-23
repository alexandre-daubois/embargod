package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexandre-daubois/securibot/internal/github"
	"github.com/alexandre-daubois/securibot/internal/repo"
)

type fakeGitHub struct{}

func (fakeGitHub) SearchIssues(_ context.Context, _, query string) ([]github.Issue, error) {
	if query == "fail" {
		return nil, errors.New("rate limited")
	}

	return []github.Issue{{Number: 7, Title: query}}, nil
}

func build() []Tool {
	others := []github.Advisory{{GHSAID: "GHSA-1", State: "published", Summary: "UAF", Description: "details", CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}}

	return append(append(Code(repo.Repo{Dir: "."}), Issues(fakeGitHub{}, "o/r")...), Advisories(others)...)
}

func TestCall(t *testing.T) {
	ts := build()
	for _, tc := range []struct {
		name, input, want string
	}{
		{"list_advisories", `{}`, `"ghsa_id":"GHSA-1","state":"published","summary":"UAF"`},
		{"list_advisories", ``, `"created_at":"2026-01-02"`},
		{"get_advisory", `{"ghsa_id":"GHSA-1"}`, `"description":"details"`},
		{"search_issues", `{"query":"overflow"}`, `"title":"overflow"`},
		{"read_file", `{"path":"tools.go","start":1,"end":1}`, "1\t// Package tools"},
	} {
		out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input))
		if isError || !strings.Contains(out, tc.want) {
			t.Errorf("%s(%s) = %q, %v", tc.name, tc.input, out, isError)
		}
	}
}

func TestCallErrors(t *testing.T) {
	ts := build()
	for _, tc := range []struct{ name, input string }{
		{"unknown", `{}`},
		{"get_advisory", `{"ghsa_id":"GHSA-missing"}`},
		{"get_advisory", `{}`},
		{"search_issues", `{"query":"fail"}`},
		{"read_file", `{"path":"../../go.mod"}`},
		{"read_file", `not json`},
	} {
		out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input))
		if !isError || !strings.HasPrefix(out, "error: ") {
			t.Errorf("%s(%s) = %q, %v, want an error", tc.name, tc.input, out, isError)
		}
	}
}

func TestToolSetsKeepPublicAndPrivateApart(t *testing.T) {
	names := func(ts []Tool) []string {
		var n []string
		for _, t := range ts {
			n = append(n, t.Name)
		}

		return n
	}

	public := strings.Join(append(names(Code(repo.Repo{})), names(Issues(fakeGitHub{}, "o/r"))...), ",")
	if public != "grep_code,read_file,git_log,search_issues" {
		t.Errorf("public tools = %s", public)
	}
	if private := strings.Join(names(Advisories(nil)), ","); private != "list_advisories,get_advisory" {
		t.Errorf("advisory tools = %s", private)
	}
}

func TestCallSkipsToolsWithoutRun(t *testing.T) {
	out, isError := Call(context.Background(), []Tool{{Name: Submit}}, Submit, nil)
	if !isError || !strings.Contains(out, "unknown tool") {
		t.Fatalf("got %q, %v", out, isError)
	}
}
