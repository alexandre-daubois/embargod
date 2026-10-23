//go:build integration

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness/container"
	"github.com/alpha-omega-security/harness/egress"
)

func TestIsolatedNetworkReachesTheModelButNotOtherHostServices(t *testing.T) {
	if os.Getenv("EMBARGOD_TEST_IMAGE") == "" {
		t.Skip("EMBARGOD_TEST_IMAGE is required")
	}
	runtime, ok := container.DetectRuntime("")
	if !ok {
		t.Skip("Docker is unavailable")
	}
	model, modelPort := testServer(t, "model")
	secret, secretPort := testServer(t, "SECRET-PAYLOAD")
	t.Cleanup(func() { _ = model.Close() })
	t.Cleanup(func() { _ = secret.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run, err := startIsolatedRun(ctx, runtime, os.Getenv("EMBARGOD_TEST_IMAGE"), modelPort, false, allow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(run.Close)
	proxyURL := egress.EndpointURL(run.token, net.JoinHostPort(run.proxyIP, proxyPort))
	cmd := exec.CommandContext(ctx, runtime.Bin, "run", "--rm", "--network", run.network, "--add-host", egress.HostGatewayAlias+":"+run.proxyIP, "-e", "http_proxy", "-e", "NO_PROXY", "-e", "MODEL_URL", "-e", "SECRET_URL", "--", os.Getenv("EMBARGOD_TEST_IMAGE"), "sh", "-c", `test "$(curl -sS --connect-timeout 5 "$MODEL_URL")" = model && ! curl -sS --noproxy '*' --connect-timeout 2 "$SECRET_URL" && ! getent hosts example.com`)
	cmd.Env = append(os.Environ(), "http_proxy="+proxyURL, "NO_PROXY=", "MODEL_URL=http://"+egress.HostGatewayAlias+":"+modelPort, "SECRET_URL=http://"+egress.HostGatewayAlias+":"+secretPort)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolation probe: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

func TestClaudeCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "claude", "claude-opus-5-5", ":claude")
}

func TestCodexCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "codex", "gpt-5.5", ":codex")
}

func TestCodexWithAnAccessTokenCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "codex-token", "gpt-5.5", ":codex")
}

func testAgentCanReachTheFilteredModelProxy(t *testing.T, name, model, imageSuffix string) {
	t.Helper()
	image := os.Getenv("EMBARGOD_TEST_IMAGE")
	if !strings.HasSuffix(image, imageSuffix) {
		t.Skip("EMBARGOD_TEST_IMAGE must end in " + imageSuffix)
	}
	var calls atomic.Int32
	upstream, port := testServerHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/user-auth-credential/whoami"):
			_, _ = io.WriteString(w, `{"email":"private@example.com","chatgpt_user_id":"private-user","chatgpt_account_id":"private-account","chatgpt_plan_type":"enterprise","chatgpt_account_is_fedramp":false}`)
		case strings.HasSuffix(r.URL.Path, "/wham/config/bundle"):
			_, _ = io.WriteString(w, `{}`)
		default:
			calls.Add(1)
			http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"stop"}}`, http.StatusBadRequest)
		}
	})
	t.Cleanup(func() { _ = upstream.Close() })
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
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	_, readErr := reader.Read(t.Context(), Request{RepoPath: gitRepo(t), Prompt: "Answer", System: "System", Report: "Report", Schema: []byte(`{}`), Validate: func(json.RawMessage) error { return nil }})
	if calls.Load() == 0 {
		t.Fatalf("the legitimate %s request was blocked before the model provider: %v", name, errors.Unwrap(readErr))
	}
}

func testServer(t *testing.T, response string) (*http.Server, string) {
	t.Helper()
	return testServerHandler(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, response) })
}

func testServerHandler(t *testing.T, handler http.HandlerFunc) (*http.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()

	return server, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}
