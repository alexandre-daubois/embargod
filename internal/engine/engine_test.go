package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anthropicoption "github.com/anthropics/anthropic-sdk-go/option"
	openaioption "github.com/openai/openai-go/v3/option"

	"github.com/alexandre-daubois/embargod/internal/tools"
)

// scripted serves the given responses in order and records the request bodies.
func scripted(t *testing.T, responses ...string) (*httptest.Server, *[]string) {
	t.Helper()
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, r.Header.Get("anthropic-beta")+" "+string(body))
		if len(requests) > len(responses) {
			t.Errorf("unexpected request %d: %s", len(requests), body)
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
	return `{"id":"msg","type":"message","role":"assistant","model":"m","stop_reason":"` + stop + `","content":[` + content + `],"usage":{"input_tokens":1,"output_tokens":1}}`
}

func TestClaudeRunsToolsUntilSubmit(t *testing.T) {
	srv, requests := scripted(t,
		claudeMessage("tool_use", `{"type":"tool_use","id":"tu1","name":"lookup","input":{"q":"x"}}`),
		claudeMessage("end_turn", `{"type":"text","text":"Done."}`),
		claudeMessage("tool_use", `{"type":"tool_use","id":"tu2","name":"submit","input":{"summary":"ok"}}`),
	)
	var calls []string

	got, err := NewClaude("key", "claude-opus-5-5", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "system", "prompt", testTools(&calls))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != `{"summary":"ok"}` {
		t.Fatalf("report = %s", got)
	}
	if len(calls) != 1 || calls[0] != `{"q":"x"}` {
		t.Fatalf("tool calls = %v", calls)
	}
	first, second, third := (*requests)[0], (*requests)[1], (*requests)[2]
	for _, want := range []string{"server-side-fallback-2026-07-01", `"fallbacks":"default"`, `"effort":"high"`, `"name":"submit"`} {
		if !strings.Contains(first, want) {
			t.Errorf("first request misses %s: %s", want, first)
		}
	}
	if !strings.Contains(second, `"tool_use_id":"tu1"`) || !strings.Contains(second, "lookup result") {
		t.Errorf("second request misses the tool result: %s", second)
	}
	if !strings.Contains(third, nudge) {
		t.Errorf("third request misses the nudge: %s", third)
	}
}

func TestClaudeRefusal(t *testing.T) {
	srv, _ := scripted(t, `{"id":"msg","type":"message","role":"assistant","model":"m","stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"The report describes SECRET-PAYLOAD"},"content":[],"usage":{"input_tokens":1,"output_tokens":1}}`)

	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var refusal *RefusalError
	if !errors.As(err, &refusal) || refusal.Category != "cyber" {
		t.Fatalf("want a cyber refusal, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-PAYLOAD") {
		t.Fatalf("the explanation leaked: %v", err)
	}
}

func TestClaudeGivesUpWithoutReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, claudeMessage("end_turn", `{"type":"text","text":"Thinking aloud."}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	if !errors.Is(err, ErrNoReport) {
		t.Fatalf("want ErrNoReport, got %v", err)
	}
}

func TestClaudeAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"prompt mentions SECRET-PAYLOAD"}}`, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	_, err := NewClaude("key", "m", anthropicoption.WithBaseURL(srv.URL), anthropicoption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest || apiErr.Provider != "anthropic" {
		t.Fatalf("want an anthropic HTTP 400, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-PAYLOAD") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("the response body or URL leaked: %v", err)
	}
}

func openaiCompletion(message string) string {
	return `{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":` + message + `}]}`
}

func TestOpenAIRunsToolsUntilSubmit(t *testing.T) {
	srv, requests := scripted(t,
		openaiCompletion(`{"role":"assistant","content":null,"tool_calls":[{"id":"call1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}"}}]}`),
		openaiCompletion(`{"role":"assistant","content":"Done."}`),
		openaiCompletion(`{"role":"assistant","content":null,"tool_calls":[{"id":"call2","type":"function","function":{"name":"submit","arguments":"{\"summary\":\"ok\"}"}}]}`),
	)
	var calls []string

	got, err := NewOpenAI("key", "gpt-5.5", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "system", "prompt", testTools(&calls))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != `{"summary":"ok"}` {
		t.Fatalf("report = %s", got)
	}
	if len(calls) != 1 || calls[0] != `{"q":"x"}` {
		t.Fatalf("tool calls = %v", calls)
	}
	first, second, third := (*requests)[0], (*requests)[1], (*requests)[2]
	if !strings.Contains(first, `"reasoning_effort":"high"`) || !strings.Contains(first, `"required":[]`) {
		t.Errorf("unexpected first request: %s", first)
	}
	if !strings.Contains(second, `"tool_call_id":"call1"`) || !strings.Contains(second, "lookup result") {
		t.Errorf("second request misses the tool result: %s", second)
	}
	if !strings.Contains(third, nudge) {
		t.Errorf("third request misses the nudge: %s", third)
	}
}

func TestOpenAIRefusal(t *testing.T) {
	srv, _ := scripted(t, openaiCompletion(`{"role":"assistant","content":null,"refusal":"I can't help with SECRET-PAYLOAD"}`))

	_, err := NewOpenAI("key", "m", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var refusal *RefusalError
	if !errors.As(err, &refusal) || strings.Contains(err.Error(), "SECRET-PAYLOAD") {
		t.Fatalf("want a refusal error without its text, got %v", err)
	}
}

func TestOpenAIAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"bad input SECRET-PAYLOAD","type":"invalid_request_error"}}`, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	_, err := NewOpenAI("key", "m", openaioption.WithBaseURL(srv.URL), openaioption.WithMaxRetries(0)).
		Run(context.Background(), "s", "p", testTools(new([]string)))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest || apiErr.Provider != "openai" {
		t.Fatalf("want an openai HTTP 400, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-PAYLOAD") {
		t.Fatalf("the response body leaked: %v", err)
	}
}
