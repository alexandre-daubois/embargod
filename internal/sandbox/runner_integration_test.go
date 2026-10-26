//go:build integration

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness/container"
	"github.com/alpha-omega-security/harness/egress"
	"github.com/stretchr/testify/require"
)

func TestIsolatedNetworkReachesTheModelButNotOtherHostServices(t *testing.T) {
	require.NotEmpty(t, os.Getenv("TAMIS_TEST_IMAGE"), "TAMIS_TEST_IMAGE is required")
	runtime, ok := container.DetectRuntime("")
	require.True(t, ok, "Docker is unavailable")
	model, modelPort := testServer(t, "model")
	secret, secretPort := testServer(t, "SECRET-PAYLOAD")
	t.Cleanup(func() { _ = model.Close() })
	t.Cleanup(func() { _ = secret.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run, err := startIsolatedRun(ctx, runtime, os.Getenv("TAMIS_TEST_IMAGE"), modelPort, false, allow)
	require.NoError(t, err)
	t.Cleanup(run.Close)
	out, err := exec.CommandContext(ctx, runtime.Bin, "exec", "--", run.proxy, "getent", "hosts", egress.HostGatewayAlias).Output()
	require.NoError(t, err, "resolving the real host gateway")
	require.NotEmpty(t, strings.Fields(string(out)), "resolving the real host gateway")
	hostIP := strings.Fields(string(out))[0]
	out, err = exec.CommandContext(ctx, runtime.Bin, "network", "inspect", "--format", `{{.Internal}} {{.EnableIPv6}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv6"}}`, "--", run.network).Output()
	require.NoError(t, err)
	require.Equal(t, "true false isolated isolated", strings.TrimSpace(string(out)))
	proxyURL := egress.EndpointURL(run.token, net.JoinHostPort(run.proxyIP, proxyPort))
	cmd := exec.CommandContext(ctx, runtime.Bin, "run", "--rm", "--network", run.network, "--add-host", egress.HostGatewayAlias+":"+run.proxyIP, "-e", "http_proxy", "-e", "NO_PROXY", "-e", "MODEL_URL", "-e", "SECRET_URL", "-e", "PROXIED_SECRET_URL", "--", os.Getenv("TAMIS_TEST_IMAGE"), "sh", "-c", `test "$(curl -fsS --connect-timeout 5 "$MODEL_URL")" = model && ! curl -fsS --noproxy '*' --connect-timeout 2 "$SECRET_URL" && ! curl -fsS --connect-timeout 2 "$PROXIED_SECRET_URL" && ! curl -fsS --noproxy '*' --connect-timeout 2 'https://1.1.1.1' && ! curl -gfsS --noproxy '*' --connect-timeout 2 'https://[2606:4700:4700::1111]' && ! getent hosts example.com`)
	cmd.Env = append(os.Environ(), "http_proxy="+proxyURL, "NO_PROXY=", "MODEL_URL=http://"+egress.HostGatewayAlias+":"+modelPort, "SECRET_URL=http://"+net.JoinHostPort(hostIP, secretPort), "PROXIED_SECRET_URL=http://"+egress.HostGatewayAlias+":"+secretPort)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "isolation probe: %s", strings.TrimSpace(string(out)))
}

func TestClaudeCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "claude", "claude-opus-5-5", ":claude")
}

func TestCodexCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "codex", "gpt-5.5", ":codex")
}

func TestCodexWithAnAccessTokenCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "codex-token", "gpt-6.1-sol", ":codex")
}

func testAgentCanReachTheFilteredModelProxy(t *testing.T, name, model, imageSuffix string) {
	t.Helper()
	image := os.Getenv("TAMIS_TEST_IMAGE")
	if !strings.HasSuffix(image, imageSuffix) {
		t.Skip("TAMIS_TEST_IMAGE must end in " + imageSuffix)
	}
	var calls atomic.Int32
	var first atomic.Value
	upstream, port := testServerHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/user-auth-credential/whoami"):
			_, _ = io.WriteString(w, `{"email":"private@example.com","chatgpt_user_id":"private-user","chatgpt_account_id":"private-account","chatgpt_plan_type":"enterprise","chatgpt_account_is_fedramp":false}`)
		case strings.HasSuffix(r.URL.Path, "/wham/config/bundle"):
			_, _ = io.WriteString(w, `{}`)
		case strings.HasSuffix(r.URL.Path, "/codex/models"):
			_, _ = io.WriteString(w, `{"models":[]}`)
		default:
			if calls.Add(1) == 1 {
				body, _ := io.ReadAll(r.Body)
				first.Store(string(body))
				w.Header().Set("Content-Type", "text/event-stream")
				event := func(kind string, data any) {
					raw, _ := json.Marshal(data)
					_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, raw)
				}
				if name == "claude" {
					event("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_fixture", "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "usage": map[string]int{"input_tokens": 1, "output_tokens": 0}}})
					event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "tool_use", "id": "tool_fixture", "name": "Bash", "input": map[string]any{}}})
					event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": `{"command":"printf fixture"}`}})
					event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
					event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "tool_use", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 1}})
					event("message_stop", map[string]any{"type": "message_stop"})
				} else {
					tool := map[string]any{"type": "function_call", "id": "fc_fixture", "call_id": "call_fixture", "name": "exec_command", "arguments": `{"cmd":"printf fixture"}`}
					event("response.created", map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_fixture", "status": "in_progress", "output": []any{}}})
					event("response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": 0, "item": tool})
					event("response.completed", map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_fixture", "status": "completed", "model": model, "output": []any{tool}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}})
				}
				return
			}
			http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"stop"}}`, http.StatusBadRequest)
		}
	})
	t.Cleanup(func() { _ = upstream.Close() })
	reader := testReader(t, name, model, image, port)
	reader.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		reader.models.ServeHTTP(recorder, r)
		if recorder.Code == http.StatusForbidden {
			var value map[string]any
			_ = json.Unmarshal(body, &value)
			keys := func(m map[string]any) []string {
				var keys []string
				for key := range m {
					keys = append(keys, key)
				}
				return keys
			}
			t.Logf("rejected fixture request fields: %v; context: %v; beta: %v; reason: %s", keys(value), value["context_management"], r.Header.Get("Anthropic-Beta"), recorder.Body.String())
			if blocks, ok := value["system"].([]any); ok {
				for _, block := range blocks {
					if block, ok := block.(map[string]any); ok {
						t.Logf("system block %v: %v", block["type"], keys(block))
					}
				}
			}
			if messages, ok := value["messages"].([]any); ok {
				for _, message := range messages {
					if message, ok := message.(map[string]any); ok {
						t.Logf("message fields: %v", keys(message))
						if blocks, ok := message["content"].([]any); ok {
							for _, block := range blocks {
								if block, ok := block.(map[string]any); ok {
									t.Logf("message block %v: %v", block["type"], keys(block))
								}
							}
						}
					}
				}
			}
			if ts, ok := value["tools"].([]any); ok {
				for _, tool := range ts {
					if tool, ok := tool.(map[string]any); ok {
						t.Logf("tool type %v fields: %v", tool["type"], keys(tool))
					}
				}
			}
		}
		for name, values := range recorder.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	_, readErr := reader.Read(t.Context(), Request{RepoPath: gitRepo(t), Prompt: "Answer", System: "System", Report: "Report", Schema: []byte(`{}`), Validate: func(json.RawMessage) error { return nil }})
	require.GreaterOrEqual(t, calls.Load(), int32(2), "the legitimate %s request was blocked before the model provider: %v", name, errors.Unwrap(readErr))
	if name != "claude" {
		require.Contains(t, first.Load(), `"effort":"medium"`, "Codex does not request medium reasoning")
	}
}

func TestReaderGetsOneCorrectionRound(t *testing.T) {
	image := os.Getenv("TAMIS_TEST_IMAGE")
	if !strings.HasSuffix(image, ":claude") {
		t.Skip("TAMIS_TEST_IMAGE must end in :claude")
	}
	t.Run("corrected", func(t *testing.T) {
		raw, seen, err := readWithCorrection(t, image, `{"ok":true}`)
		require.NoError(t, err)
		require.JSONEq(t, `{"ok":true}`, string(raw))
		require.Equal(t, []string{"not json", `{"ok":true}`}, seen)
	})
	t.Run("still invalid", func(t *testing.T) {
		_, seen, err := readWithCorrection(t, image, "still not json")
		require.ErrorIs(t, err, ErrNoReport)
		require.Equal(t, []string{"not json", "still not json"}, seen)
	})
}

// readWithCorrection runs Claude Code against a model that writes invalid JSON, then corrected once the
// prompt carries the validation error, and returns what the validator saw.
func readWithCorrection(t *testing.T, image, corrected string) (json.RawMessage, []string, error) {
	t.Helper()
	_, port := testServerHandler(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		event := func(kind string, data any) {
			raw, _ := json.Marshal(data)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, raw)
		}
		event("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_fixture", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": []any{}, "stop_reason": nil, "usage": map[string]int{"input_tokens": 1, "output_tokens": 0}}})
		stop := "end_turn"
		if bytes.Contains(body, []byte(`"tool_result"`)) {
			event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
			event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": "Done."}})
		} else {
			output := "not json"
			if bytes.Contains(body, []byte("did not produce valid output")) {
				output = corrected
			}
			command, _ := json.Marshal(map[string]string{"command": "printf '%s' '" + output + "' > /work/" + outputFile})
			stop = "tool_use"
			event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "tool_use", "id": "tool_fixture", "name": "Bash", "input": map[string]any{}}})
			event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(command)}})
		}
		event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
		event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 1}})
		event("message_stop", map[string]any{"type": "message_stop"})
	})
	reader := testReader(t, "claude", "claude-opus-5-5", image, port)

	var seen []string
	validate := func(raw json.RawMessage) error {
		seen = append(seen, string(raw))
		if !json.Valid(raw) {
			return errors.New("not JSON")
		}
		return nil
	}
	raw, err := reader.Read(t.Context(), Request{RepoPath: gitRepo(t), Prompt: "Answer", System: "System", Report: "Report", Schema: []byte(`{}`), Validate: validate})

	return raw, seen, err
}

func testReader(t *testing.T, name, model, image, port string) *Reader {
	t.Helper()
	original := backends[name]
	changed := original
	changed.provider.Upstream = "http://127.0.0.1:" + port
	if changed.provider.Upstreams != nil {
		changed.provider.Upstreams = map[string]string{}
		for prefix := range original.provider.Upstreams {
			changed.provider.Upstreams[prefix] = changed.provider.Upstream
		}
	}
	backends[name] = changed
	t.Cleanup(func() { backends[name] = original })

	reader, err := New(name, model, "test-key", image)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	return reader
}

func testServer(t *testing.T, response string) (*http.Server, string) {
	t.Helper()
	return testServerHandler(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, response) })
}

func testServerHandler(t *testing.T, handler http.HandlerFunc) (*http.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", ":0")
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()

	return server, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}
