package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		assert.False(t, isError, "%s(%s) = %q", tc.name, tc.input, out)
		assert.Contains(t, out, tc.want, "%s(%s)", tc.name, tc.input)
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
		assert.True(t, isError, "%s(%s) = %q, want an error", tc.name, tc.input, out)
		assert.True(t, strings.HasPrefix(out, "error: "), "%s(%s) = %q, want an error", tc.name, tc.input, out)
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

	assert.Equal(t, []string{"grep_code", "read_file", "git_log"}, names(Code(repo.Repo{})), "code tools")
	assert.Equal(t, []string{"get_advisory"}, names([]Tool{Advisory(github.Advisory{})}), "advisory tools")
}

func TestCallSkipsToolsWithoutRun(t *testing.T) {
	out, isError := Call(context.Background(), []Tool{{Name: Submit}}, Submit, nil)
	require.True(t, isError, "got %q", out)
	require.Contains(t, out, "unknown tool")
}

func TestCodeTools(t *testing.T) {
	ts := Code(repo.Repo{Dir: "."})
	for _, tc := range []struct{ name, input, want string }{
		{"grep_code", `{"pattern":"func Code\\(","path":"tools.go"}`, "tools.go:"},
		{"grep_code", `{"pattern":"no_such_symbol_anywhere_42"}`, "no match"},
		{"git_log", `{"path":"tools.go"}`, ""},
	} {
		out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input))
		assert.False(t, isError, "%s(%s) = %q", tc.name, tc.input, out)
		assert.Contains(t, out, tc.want, "%s(%s)", tc.name, tc.input)
	}

	for _, tc := range []struct{ name, input string }{
		{"grep_code", `{"pattern":"("}`},
		{"grep_code", `[]`},
		{"git_log", `{"path":1}`},
		{"read_file", `{"path":".git/config"}`},
	} {
		out, isError := Call(context.Background(), ts, tc.name, json.RawMessage(tc.input))
		assert.True(t, isError, "%s(%s) = %q, want an error", tc.name, tc.input, out)
	}
}

func TestDecodeEmptyInput(t *testing.T) {
	v, err := decode[struct {
		Path string `json:"path"`
	}](nil)
	require.NoError(t, err)
	require.Empty(t, v.Path)
}

func TestValidate(t *testing.T) {
	strict := []Tool{{Name: Submit, Run: func(_ context.Context, in json.RawMessage) (string, error) {
		if string(in) != `{}` {
			return "", errors.New("bad")
		}

		return "", nil
	}}}

	assert.NoError(t, Validate(context.Background(), strict, json.RawMessage(`{}`)), "valid input rejected")
	assert.Error(t, Validate(context.Background(), strict, json.RawMessage(`[]`)), "invalid input accepted")
	assert.NoError(t, Validate(context.Background(), []Tool{{Name: Submit}}, json.RawMessage(`[]`)), "a submit tool without Run accepts anything")
}
