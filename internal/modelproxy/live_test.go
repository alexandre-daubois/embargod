//go:build live

package modelproxy

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/tamis/internal/usage"
)

// These tests pin that the usage the proxy counts for a real agent CLI run equals the one the CLI reports:
// TAMIS_LIVE_ANTHROPIC_KEY_FILE=path/to/key go test -tags live -run Live -v ./internal/modelproxy
// TAMIS_LIVE_OPENAI_KEY_FILE=path/to/key go test -tags live -run Live -v ./internal/modelproxy

const livePrompt = "Read go.mod in the current directory with a tool, then reply with the module path only."

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	s.ResponseWriter.(http.Flusher).Flush()
}

// liveRun serves a proxy for provider with the key in the file named by env, and runs cmd in the repository root
// with the URL and the token issued for it. It returns the CLI output and what the proxy counted.
func liveRun(t *testing.T, provider Provider, env, model string, cmd func(url, token string) *exec.Cmd) ([]byte, usage.Usage) {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		t.Skip(env + " is not set")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	mp, err := New(provider, strings.TrimSpace(string(raw)), model)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		mp.ServeHTTP(rec, r)
		t.Logf("%s %s -> %d", r.Method, r.URL.Path, rec.status)
	}))
	t.Cleanup(srv.Close)
	token, revoke := mp.Issue(t.Context())

	c := cmd(srv.URL+PathPrefix, token)
	c.Dir = "../.."
	out, err := c.Output()
	spent := revoke()
	require.NoError(t, err, "the CLI failed: %s", out)
	t.Logf("proxy: %+v", spent)

	return out, spent
}

func TestLiveClaudeCodeUsage(t *testing.T) {
	model := cmp.Or(os.Getenv("TAMIS_LIVE_MODEL"), "claude-haiku-5-5")
	out, spent := liveRun(t, Anthropic, "TAMIS_LIVE_ANTHROPIC_KEY_FILE", model, func(url, token string) *exec.Cmd {
		c := exec.Command("claude", "-p", livePrompt, "--model", model, "--output-format", "json", "--allowedTools", "Read")
		c.Env = append(os.Environ(), "ANTHROPIC_BASE_URL="+url, "ANTHROPIC_API_KEY="+token, "CLAUDE_CONFIG_DIR="+t.TempDir(), "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
		return c
	})

	var result struct {
		Usage struct {
			InputTokens   int64 `json:"input_tokens"`
			CacheCreation int64 `json:"cache_creation_input_tokens"`
			CacheRead     int64 `json:"cache_read_input_tokens"`
			OutputTokens  int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(out, &result), "%s", out)
	cli := usage.Usage{InputTokens: result.Usage.InputTokens + result.Usage.CacheCreation + result.Usage.CacheRead, OutputTokens: result.Usage.OutputTokens}
	t.Logf("cli: %+v", cli)
	require.GreaterOrEqual(t, spent.Requests, int64(2))
	require.Equal(t, cli.InputTokens, spent.InputTokens)
	require.Equal(t, cli.OutputTokens, spent.OutputTokens)
}

func TestLiveCodexUsage(t *testing.T) {
	model := cmp.Or(os.Getenv("TAMIS_LIVE_MODEL"), "gpt-5.5")
	out, spent := liveRun(t, OpenAI, "TAMIS_LIVE_OPENAI_KEY_FILE", model, func(url, token string) *exec.Cmd {
		home := t.TempDir()
		// The same features as in sandbox.writeConfig are off, the proxy refuses the requests they make.
		config := fmt.Sprintf("model_provider = \"tamis\"\nweb_search = \"disabled\"\n\n[analytics]\nenabled = false\n\n[features]\napps = false\nplugins = false\nremote_plugin = false\nplugin_sharing = false\ngoals = false\nimage_generation = false\nskill_mcp_dependency_install = false\n\n[model_providers.tamis]\nname = \"Tamis\"\nbase_url = %q\nenv_key = \"CODEX_API_KEY\"\nwire_api = \"responses\"\nsupports_websockets = false\nrequest_max_retries = 0\nstream_max_retries = 0\n", url+"/v1")
		require.NoError(t, os.WriteFile(filepath.Join(home, "config.toml"), []byte(config), 0o600))
		c := exec.Command("codex", "exec", "--json", "--ephemeral", "--skip-git-repo-check", "-s", "read-only", "-m", model, livePrompt)
		c.Env = append(os.Environ(), "CODEX_HOME="+home, "CODEX_API_KEY="+token)
		return c
	})

	var cli usage.Usage
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(nil, 1<<20)
	for scanner.Scan() {
		var event struct {
			Type  string `json:"type"`
			Usage struct {
				InputTokens  int64 `json:"input_tokens"`
				OutputTokens int64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Type == "turn.completed" {
			cli.InputTokens += event.Usage.InputTokens
			cli.OutputTokens += event.Usage.OutputTokens
		}
	}
	t.Logf("cli: %+v", cli)
	require.GreaterOrEqual(t, spent.Requests, int64(2), "%s", out)
	require.Equal(t, cli.InputTokens, spent.InputTokens, "%s", out)
	require.Equal(t, cli.OutputTokens, spent.OutputTokens, "%s", out)
}
