package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	anthropicoption "github.com/anthropics/anthropic-sdk-go/option"
	openaioption "github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/tamis/internal/tools"
	"github.com/alexandre-daubois/tamis/internal/usage"
)

// scripted serves the given responses in order and records the request bodies.
func scripted(t *testing.T, responses ...string) (*httptest.Server, *[]string) {
	t.Helper()
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, r.Header.Get("anthropic-beta")+" "+string(body))
		if len(requests) > len(responses) {
			assert.Failf(t, "unexpected request", "%d: %s", len(requests), body)
			http.Error(w, "no more responses", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, responses[len(requests)-1])
	}))
	t.Cleanup(srv.Close)

	return srv, &requests
}

func testTools(calls *[]string) []tools.Tool {
	return []tools.Tool{
		{Name: "lookup", Description: "look", Run: func(_ context.Context, in json.RawMessage) (string, error) {
			*calls = append(*calls, string(in))
			return "lookup result", nil
		}},
		{Name: tools.Submit, Description: "submit", Properties: map[string]any{"summary": map[string]any{"type": "string"}}, Required: []string{"summary"}},
	}
}

func claudeMessage(stop, content string) string {
	return `{"id":"msg","type":"message","role":"assistant","model":"m","stop_reason":"` + stop + `","content":[` + content + `],"usage":{"input_tokens":1,"cache_creation_input_tokens":2,"cache_read_input_tokens":3,"output_tokens":4}}`
}

func TestClaudeRunsToolsUntilSubmit(t *testing.T) {
	srv, requests := scripted(t,
		claudeMessage("tool_use", `{"type":"tool_use","id":"tu1","name":"lookup","input":{"q":"x"}}`),
		claudeMessage("end_turn", `{"type":"text","text":"Done."}`),
		claudeMessage("tool_use", `{"type":"tool_use","id":"tu2","name":"submit","input":{"summary":"ok"}}`),
	)
	var calls []string
	ctx, spent := usage.Track(context.Background())

	got, err := NewClaude("key", "claude-opus-5-5", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(ctx, "system", "prompt", testTools(&calls))
	require.NoError(t, err)
	assert.Equal(t, usage.Usage{Requests: 3, InputTokens: 18, OutputTokens: 12}, spent())

	require.Equal(t, `{"summary":"ok"}`, string(got))
	require.Len(t, calls, 1)
	require.Equal(t, `{"q":"x"}`, calls[0])
	first, second, third := (*requests)[0], (*requests)[1], (*requests)[2]
	for _, want := range []string{`"effort":"high"`, `"name":"submit"`, `"cache_control":{"type":"ephemeral"}`, `"input_schema":{"properties":{},`} {
		assert.Contains(t, first, want)
	}
	require.NotContains(t, first, "fallback", "an unapproved fallback was enabled")
	assert.Contains(t, second, `"tool_use_id":"tu1"`, "second request misses the tool result")
	assert.Contains(t, second, "lookup result", "second request misses the tool result")
	assert.Contains(t, third, nudge, "third request misses the nudge")
}

func TestClaudeRefusal(t *testing.T) {
	srv, _ := scripted(t, `{"id":"msg","type":"message","role":"assistant","model":"m","stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"The report describes SECRET-PAYLOAD"},"content":[],"usage":{"input_tokens":1,"output_tokens":1}}`)

	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var refusal *RefusalError
	require.ErrorAs(t, err, &refusal, "want a cyber refusal")
	require.Equal(t, "cyber", refusal.Category, "want a cyber refusal")
	require.NotContains(t, err.Error(), "SECRET-PAYLOAD", "the explanation leaked")
}

func TestClaudeGivesUpWithoutReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, claudeMessage("end_turn", `{"type":"text","text":"Thinking aloud."}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	require.ErrorIs(t, err, ErrNoReport)
}

func TestRequestLimitStopsTheModelLoop(t *testing.T) {
	srv, requests := scripted(t, claudeMessage("end_turn", `{"type":"text","text":"keep going"}`))
	ctx := WithRequestLimit(context.Background(), 1)
	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(ctx, "s", "p", testTools(new([]string)))
	require.ErrorIs(t, err, ErrNoReport)
	require.Len(t, *requests, 1)
}

func TestClaudeAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"prompt mentions SECRET-PAYLOAD"}}`, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	ctx, spent := usage.Track(context.Background())

	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(ctx, "s", "p", testTools(new([]string)))
	assert.Zero(t, spent(), "a failed request was counted")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "want an anthropic HTTP 400")
	require.Equal(t, http.StatusBadRequest, apiErr.Status, "want an anthropic HTTP 400")
	require.Equal(t, "anthropic", apiErr.Provider, "want an anthropic HTTP 400")
	require.NotContains(t, err.Error(), "SECRET-PAYLOAD", "the response body or URL leaked")
	require.NotContains(t, err.Error(), srv.URL, "the response body or URL leaked")
}

func openaiCompletion(message string) string {
	return `{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":` + message + `}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`
}

func TestOpenAIRunsToolsUntilSubmit(t *testing.T) {
	srv, requests := scripted(t,
		openaiCompletion(`{"role":"assistant","content":null,"tool_calls":[{"id":"call1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}"}}]}`),
		openaiCompletion(`{"role":"assistant","content":"Done."}`),
		openaiCompletion(`{"role":"assistant","content":null,"tool_calls":[{"id":"call2","type":"function","function":{"name":"submit","arguments":"{\"summary\":\"ok\"}"}}]}`),
	)
	var calls []string
	ctx, spent := usage.Track(context.Background())

	got, err := NewOpenAI("key", "gpt-5.5", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(ctx, "system", "prompt", testTools(&calls))
	require.NoError(t, err)
	assert.Equal(t, usage.Usage{Requests: 3, InputTokens: 15, OutputTokens: 6}, spent())

	require.Equal(t, `{"summary":"ok"}`, string(got))
	require.Len(t, calls, 1)
	require.Equal(t, `{"q":"x"}`, calls[0])
	first, second, third := (*requests)[0], (*requests)[1], (*requests)[2]
	assert.Contains(t, first, `"reasoning_effort":"high"`, "unexpected first request")
	assert.Contains(t, first, `"required":[]`, "unexpected first request")
	assert.Contains(t, second, `"tool_call_id":"call1"`, "second request misses the tool result")
	assert.Contains(t, second, "lookup result", "second request misses the tool result")
	assert.Contains(t, third, nudge, "third request misses the nudge")
}

func TestOpenAIRefusal(t *testing.T) {
	srv, _ := scripted(t, openaiCompletion(`{"role":"assistant","content":null,"refusal":"I can't help with SECRET-PAYLOAD"}`))

	_, err := NewOpenAI("key", "m", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var refusal *RefusalError
	require.ErrorAs(t, err, &refusal, "want a refusal error without its text")
	require.NotContains(t, err.Error(), "SECRET-PAYLOAD", "want a refusal error without its text")
}

func TestOpenAIAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"bad input SECRET-PAYLOAD","type":"invalid_request_error"}}`, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	_, err := NewOpenAI("key", "m", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "want an openai HTTP 400")
	require.Equal(t, http.StatusBadRequest, apiErr.Status, "want an openai HTTP 400")
	require.Equal(t, "openai", apiErr.Provider, "want an openai HTTP 400")
	require.NotContains(t, err.Error(), "SECRET-PAYLOAD", "the response body leaked")
}

func TestNetworkErrorsKeepNoDetail(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	for name, eng := range map[string]Engine{
		"anthropic": NewClaude("key", "m", anthropicoption.WithBaseURL(url), anthropicoption.WithMaxRetries(0)),
		"openai":    NewOpenAI("key", "m", openaioption.WithBaseURL(url), openaioption.WithMaxRetries(0)),
	} {
		_, err := eng.Run(context.Background(), "s", "SECRET-PAYLOAD", testTools(new([]string)))
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr, "%s", name)
		assert.Equal(t, name, apiErr.Provider, "%s", name)
		assert.Zero(t, apiErr.Status, "%s", name)
		assert.EqualError(t, err, name+": request failed", "%s", name)
	}
}

func TestOpenAIEmptyCompletion(t *testing.T) {
	srv, _ := scripted(t, `{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[]}`)

	_, err := NewOpenAI("key", "m", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	require.EqualError(t, err, "empty completion")
}

func TestErrorMessages(t *testing.T) {
	for err, want := range map[error]string{
		&APIError{Provider: "anthropic", Status: 529}: "anthropic: HTTP 529",
		&APIError{Provider: "openai"}:                 "openai: request failed",
		&RefusalError{}:                               "the model refused",
		&RefusalError{Category: "bio"}:                `the model refused (category "bio")`,
	} {
		assert.EqualError(t, err, want)
	}
}

// validatingTools rejects a summary that is not a string, like the real submit tool does.
func validatingTools() []tools.Tool {
	ts := testTools(new([]string))
	ts[1].Run = func(_ context.Context, in json.RawMessage) (string, error) {
		var v struct {
			Summary string `json:"summary"`
		}

		return "", json.Unmarshal(in, &v)
	}

	return ts
}

func TestClaudeRetriesAnInvalidSubmission(t *testing.T) {
	srv, requests := scripted(t,
		claudeMessage("tool_use", `{"type":"tool_use","id":"tu1","name":"submit","input":{"summary":42}}`),
		claudeMessage("tool_use", `{"type":"tool_use","id":"tu2","name":"submit","input":{"summary":"ok"}}`),
	)

	got, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", validatingTools())
	require.NoError(t, err)
	require.Equal(t, `{"summary":"ok"}`, string(got))
	second := (*requests)[1]
	assert.Contains(t, second, `"tool_use_id":"tu1"`, "the model should get the validation error")
	assert.Contains(t, second, `"is_error":true`, "the model should get the validation error")
	assert.Contains(t, second, "does not match the schema", "the model should get the validation error")
}

func TestOpenAIRetriesAnInvalidSubmission(t *testing.T) {
	srv, requests := scripted(t,
		openaiCompletion(`{"role":"assistant","content":null,"tool_calls":[{"id":"call1","type":"function","function":{"name":"submit","arguments":"{\"summary\":42}"}}]}`),
		openaiCompletion(`{"role":"assistant","content":null,"tool_calls":[{"id":"call2","type":"function","function":{"name":"submit","arguments":"{\"summary\":\"ok\"}"}}]}`),
	)

	got, err := NewOpenAI("key", "m", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", validatingTools())
	require.NoError(t, err)
	require.Equal(t, `{"summary":"ok"}`, string(got))
	second := (*requests)[1]
	assert.Contains(t, second, `"tool_call_id":"call1"`, "the model should get the validation error")
	assert.Contains(t, second, "does not match the schema", "the model should get the validation error")
}
