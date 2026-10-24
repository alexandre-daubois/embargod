package modelproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexandre-daubois/embargod/internal/usage"
)

// spend relays one request to an upstream answering with body, and returns what the run spent once revoked.
func spend(t *testing.T, p Provider, route string, status int, contentType, body string) usage.Usage {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	p.Upstream = up.URL
	mp, err := New(p, "real-key", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	token, revoke := mp.Issue()
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)

	resp := call(t, srv, http.MethodPost, PathPrefix+route, withKey("Authorization", "Bearer "+token))
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return revoke()
}

func TestUsageOfAResponse(t *testing.T) {
	for name, tc := range map[string]struct {
		provider    Provider
		route       string
		contentType string
		body        string
		want        usage.Usage
	}{
		"anthropic message": {Anthropic, "/v1/messages", "application/json",
			`{"type":"message","usage":{"input_tokens":10,"cache_creation_input_tokens":20,"cache_read_input_tokens":30,"output_tokens":5}}`,
			usage.Usage{Requests: 1, InputTokens: 60, OutputTokens: 5}},
		"anthropic stream": {Anthropic, "/v1/messages", "text/event-stream; charset=utf-8",
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":30,\"output_tokens\":1}}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"usage\"}}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n",
			usage.Usage{Requests: 1, InputTokens: 40, OutputTokens: 42}},
		"responses stream": {OpenAI, "/v1/responses", "text/event-stream",
			"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":100,\"output_tokens\":7}}}\n\n",
			usage.Usage{Requests: 1, InputTokens: 100, OutputTokens: 7}},
		"stream without usage": {OpenAI, "/v1/responses", "text/event-stream",
			"data: not json\n\ndata: {\"usage\":\"many\"}\n\ndata: [DONE]\n\n",
			usage.Usage{Requests: 1}},
		"token count": {Anthropic, "/v1/messages/count_tokens", "application/json", `{"input_tokens":10}`, usage.Usage{}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := spend(t, tc.provider, tc.route, http.StatusOK, tc.contentType, tc.body); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestUsageReaderKeepsAnUnterminatedLastEvent(t *testing.T) {
	var got usage.Usage
	r := &usageReader{
		ReadCloser: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}")),
		stream:     true,
		done:       func(u usage.Usage) { got = u },
	}

	io.Copy(io.Discard, r)

	if got != (usage.Usage{Requests: 1, InputTokens: 3, OutputTokens: 2}) {
		t.Fatalf("got %+v", got)
	}
}

func TestUsageReaderCountsAStreamClosedEarly(t *testing.T) {
	var calls []usage.Usage
	body := "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"partial"
	r := &usageReader{
		ReadCloser: io.NopCloser(strings.NewReader(body)),
		stream:     true,
		done:       func(u usage.Usage) { calls = append(calls, u) },
	}

	io.ReadFull(r, make([]byte, len(body)-5))
	r.Close()
	r.Close()

	if len(calls) != 1 || calls[0] != (usage.Usage{Requests: 1, InputTokens: 10, OutputTokens: 1}) {
		t.Fatalf("got %+v", calls)
	}
}

func TestUsageSkipsFailedRequests(t *testing.T) {
	got := spend(t, Anthropic, "/v1/messages", http.StatusTooManyRequests, "application/json", `{"usage":{"input_tokens":10,"output_tokens":5}}`)

	if got != (usage.Usage{}) {
		t.Fatalf("a failed request was counted: %+v", got)
	}
}

func TestUsageIsCountedPerToken(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"usage":{"input_tokens":10,"output_tokens":5}}`)
	}))
	t.Cleanup(up.Close)
	p := Anthropic
	p.Upstream = up.URL
	mp, err := New(p, "real-key", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mp)
	t.Cleanup(srv.Close)
	first, revokeFirst := mp.Issue()
	_, revokeSecond := mp.Issue()

	for range 2 {
		resp := call(t, srv, http.MethodPost, PathPrefix+"/v1/messages", withKey("X-Api-Key", first))
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := revokeSecond(); got != (usage.Usage{}) {
		t.Fatalf("the second run was charged: %+v", got)
	}
	if got := revokeFirst(); got != (usage.Usage{Requests: 2, InputTokens: 20, OutputTokens: 10}) {
		t.Fatalf("got %+v", got)
	}
	if got := revokeFirst(); got != (usage.Usage{}) {
		t.Fatalf("a revoked token still reports usage: %+v", got)
	}
}
