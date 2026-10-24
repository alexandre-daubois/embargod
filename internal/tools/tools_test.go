package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/alexandre-daubois/tamis/internal/github"
	"github.com/alexandre-daubois/tamis/internal/repo"
)

func build() []Tool {
	return append(Code(repo.Repo{Dir: "."}), Advisory(github.Advisory{GHSAID: "GHSA-1", Description: "details"}))
}

func TestCall(t *testing.T) {
	ts := build()
	for _, tc := range []struct {
		name, input, want string
	}{
		{"get_advisory", `{}`, `"description":"details"`},
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
		{"read_file", `{"path":"../../go.mod"}`},
		{"read_file", `not json`},
	} {
		out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input))
		if !isError || !strings.HasPrefix(out, "error: ") {
			t.Errorf("%s(%s) = %q, %v, want an error", tc.name, tc.input, out, isError)
		}
	}
}

func TestToolSets(t *testing.T) {
	names := func(ts []Tool) []string {
		var n []string
		for _, t := range ts {
			n = append(n, t.Name)
		}

		return n
	}

	if public := strings.Join(names(Code(repo.Repo{})), ","); public != "grep_code,read_file,git_log" {
		t.Errorf("code tools = %s", public)
	}
	if private := strings.Join(names([]Tool{Advisory(github.Advisory{})}), ","); private != "get_advisory" {
		t.Errorf("advisory tools = %s", private)
	}
}

func TestCallSkipsToolsWithoutRun(t *testing.T) {
	out, isError := Call(context.Background(), []Tool{{Name: Submit}}, Submit, nil)
	if !isError || !strings.Contains(out, "unknown tool") {
		t.Fatalf("got %q, %v", out, isError)
	}
}

func TestCodeTools(t *testing.T) {
	ts := Code(repo.Repo{Dir: "."})
	for _, tc := range []struct{ name, input, want string }{
		{"grep_code", `{"pattern":"func Code\\(","path":"tools.go"}`, "tools.go:"},
		{"grep_code", `{"pattern":"no_such_symbol_anywhere_42"}`, "no match"},
		{"git_log", `{"path":"tools.go"}`, ""},
	} {
		out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input))
		if isError || !strings.Contains(out, tc.want) {
			t.Errorf("%s(%s) = %q, %v", tc.name, tc.input, out, isError)
		}
	}

	for _, tc := range []struct{ name, input string }{
		{"grep_code", `{"pattern":"("}`},
		{"grep_code", `[]`},
		{"git_log", `{"path":1}`},
		{"read_file", `{"path":".git/config"}`},
	} {
		if out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input)); !isError {
			t.Errorf("%s(%s) = %q, want an error", tc.name, tc.input, out)
		}
	}
}

func TestDecodeEmptyInput(t *testing.T) {
	v, err := decode[struct {
		Path string `json:"path"`
	}](nil)
	if err != nil || v.Path != "" {
		t.Fatalf("got %+v, %v", v, err)
	}
}

func TestValidate(t *testing.T) {
	strict := []Tool{{Name: Submit, Run: func(_ context.Context, in json.RawMessage) (string, error) {
		if string(in) != `{}` {
			return "", errors.New("bad")
		}

		return "", nil
	}}}

	if err := Validate(context.Background(), strict, json.RawMessage(`{}`)); err != nil {
		t.Errorf("valid input rejected: %v", err)
	}
	if err := Validate(context.Background(), strict, json.RawMessage(`[]`)); err == nil {
		t.Error("invalid input accepted")
	}
	if err := Validate(context.Background(), []Tool{{Name: Submit}}, json.RawMessage(`[]`)); err != nil {
		t.Errorf("a submit tool without Run accepts anything: %v", err)
	}
}
