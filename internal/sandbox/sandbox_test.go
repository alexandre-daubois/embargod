package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotSourceCopiesOnlyTrackedContentAndHistory(t *testing.T) {
	repo := gitRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("tracked"), 0o600))
	git(t, repo, "add", "--", "tracked.txt")
	git(t, repo, "commit", "--quiet", "--no-gpg-sign", "-m", "tracked")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("SECRET"), 0o600))
	configPath := filepath.Join(repo, ".git", "config")
	config, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, append(config, []byte("\n[http]\nextraheader = AUTHORIZATION: basic SECRET\n")...), 0o600))

	target := filepath.Join(t.TempDir(), "src")
	require.NoError(t, SnapshotSource(t.Context(), repo, target, "HEAD"))
	got, err := os.ReadFile(filepath.Join(target, "tracked.txt"))
	assert.NoError(t, err)
	assert.Equal(t, "tracked", string(got))
	for _, path := range []string{"untracked.txt", filepath.Join(".git", "modules")} {
		_, err := os.Stat(filepath.Join(target, path))
		assert.ErrorIs(t, err, os.ErrNotExist, "untracked path %q reached the snapshot", path)
	}
	config, err = os.ReadFile(filepath.Join(target, ".git", "config"))
	assert.NoError(t, err)
	assert.Empty(t, config)
	git(t, target, "log", "-1", "--format=%s")
}

func TestSnapshotSourceRejectsADirectoryWithoutGit(t *testing.T) {
	require.Error(t, SnapshotSource(t.Context(), t.TempDir(), filepath.Join(t.TempDir(), "src"), "HEAD"), "a source without git must be refused")
}

func TestSnapshotSourceStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.Error(t, SnapshotSource(ctx, gitRepo(t), filepath.Join(t.TempDir(), "src"), "HEAD"), "a canceled snapshot must fail")
}

func TestSnapshotSourceUsesTheConfiguredBranch(t *testing.T) {
	source := gitRepo(t)
	git(t, source, "branch", "stable")
	require.NoError(t, os.WriteFile(filepath.Join(source, "new.txt"), []byte("HEAD-only"), 0o600))
	git(t, source, "add", "--", "new.txt")
	git(t, source, "commit", "--quiet", "--no-gpg-sign", "-m", "new branch code")
	target := filepath.Join(t.TempDir(), "src")
	require.NoError(t, SnapshotSource(t.Context(), source, target, "stable"))
	_, err := os.Stat(filepath.Join(target, "new.txt"))
	require.ErrorIs(t, err, os.ErrNotExist, "HEAD code reached the stable snapshot")
	for _, ref := range []string{"missing", "--upload-pack=malicious"} {
		require.Error(t, SnapshotSource(t.Context(), source, filepath.Join(t.TempDir(), "src"), ref), "invalid reference accepted")
	}
}

func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "--quiet")
	git(t, dir, "config", "user.name", "Test")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "commit", "--quiet", "--allow-empty", "--no-gpg-sign", "-m", "initial")

	return dir
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

func TestNewRejectsUnknownAgents(t *testing.T) {
	_, err := New("gemini", "m", "key", "")
	require.ErrorContains(t, err, "unknown agent")
}

func TestErrorHidesTheAgentOutput(t *testing.T) {
	err := &Error{Err: errors.New("exit status 1: stderr quoting SECRET-PAYLOAD")}

	require.EqualError(t, err, "the agent run failed")
	require.ErrorContains(t, errors.Unwrap(err), "SECRET-PAYLOAD")
}

func TestBoundedWriterRetainsOnlyTheOutputLimit(t *testing.T) {
	var w boundedWriter
	want := strings.Repeat("a", maxAgentOutput)
	n, err := w.Write([]byte(want))
	require.NoError(t, err)
	require.Equal(t, len(want), n)
	require.Equal(t, want, w.String())
}

func TestBoundedWriterDiscardsOutputPastTheLimit(t *testing.T) {
	var w boundedWriter
	overflow := strings.Repeat("a", maxAgentOutput+1)
	n, err := w.Write([]byte(overflow))
	require.NoError(t, err)
	require.Equal(t, len(overflow), n)
	require.Len(t, w.String(), maxAgentOutput)
}

func TestAgentRunsIsolatedWithLimitedResources(t *testing.T) {
	h, err := harness.ByName("claude")
	require.NoError(t, err)
	reader := &Reader{backend: backends["claude"], harness: h, image: "agent", modelPort: "1234"}

	runner := reader.runner("/host/state", "/host/snapshot", "proxy-token", allow, nil)

	assert.True(t, runner.Hardened, "the agent shares a network with other containers")
	assert.True(t, runner.IsolateHost, "the agent can reach host services")
	assert.True(t, runner.ReadOnlyWorkspace, "the agent can change its own instructions")
	assert.Equal(t, container.SidecarConfig{Allow: allow, APIPort: "1234"}, runner.Sidecar)
	assert.Equal(t, []container.Mount{{Host: "/host/snapshot", Container: "/work/src", ReadOnly: true}}, runner.Mounts)
	assert.Equal(t, []any{"2g", "2", 256, int64(64 << 20)}, []any{runner.Memory, runner.CPUs, runner.PIDsLimit, runner.FileSizeLimit})
}

func TestOfflineAgentReachesOnlyTheModelProxy(t *testing.T) {
	h, err := harness.ByName("claude")
	require.NoError(t, err)
	reader := &Reader{backend: backends["claude"], harness: h, modelPort: "1234"}

	runner := reader.runner("/host/state", "/host/snapshot", "proxy-token", nil, nil)

	assert.Empty(t, runner.Sidecar.Allow)
	assert.Empty(t, (&agent{Harness: h}).EgressHosts(), "the agent can reach the provider around the model proxy")
}

func TestAccessTokenContainerGetsNoAmbientAPIKey(t *testing.T) {
	h, err := harness.ByName("codex")
	require.NoError(t, err)
	reader := &Reader{backend: backends["codex-token"], harness: h, modelPort: "1234"}

	runner := reader.runner("/host/state", "/host/snapshot", "proxy-token", allow, nil)

	assert.Contains(t, runner.OmitEnv, "CODEX_API_KEY", "the ambient API key reaches the container")
	assert.Contains(t, runner.Env, "CODEX_ACCESS_TOKEN", "the access token key is not injected")
	assert.Equal(t, []string{"CODEX_ACCESS_TOKEN=proxy-token"}, runner.ProcessEnv)
	assert.Equal(t, container.SidecarConfig{Allow: allow, HostPorts: []string{"1234"}}, runner.Sidecar)
}

func TestOnlyDockerCanRunTheAgent(t *testing.T) {
	h, err := harness.ByName("claude")
	require.NoError(t, err)
	reader := &Reader{backend: backends["claude"], harness: h, runtime: container.Runtime{Bin: "podman"}, image: "agent", modelPort: "1234"}

	_, err = reader.runner(t.TempDir(), t.TempDir(), "proxy-token", allow, nil).Open(t.Context(), &agent{Harness: h})

	require.Error(t, err, "an unsupported runtime must fail closed")
}

func TestAgentKeepsOnlyTheFailuresAndTheSessionOfItsOutput(t *testing.T) {
	h, err := harness.ByName("codex")
	require.NoError(t, err)
	a := &agent{Harness: h}
	var events []harness.Event

	a.ParseStream(strings.NewReader(`{"type":"thread.started","thread_id":"thread-1"}`+"\n"+`{"type":"item.completed","item":{"type":"agent_message","text":"report content"}}`+"\n"+`{"type":"turn.failed","error":{"message":"usage limit"}}`), func(e harness.Event) { events = append(events, e) })

	require.Equal(t, `{"type":"turn.failed","error":{"message":"usage limit"}}`, a.failures.String())
	require.Equal(t, []harness.Event{{Kind: harness.KindSession, SessionID: "thread-1"}}, events)
}

func TestAgentForwardsNoEventWithoutASession(t *testing.T) {
	h, err := harness.ByName("claude")
	require.NoError(t, err)
	a := &agent{Harness: h}
	var events []harness.Event

	a.ParseStream(strings.NewReader("No conversation found with session ID: dead\n"), func(e harness.Event) { events = append(events, e) })

	require.Empty(t, events)
	require.Empty(t, a.failures.String())
}

func TestReadOutputIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	for name, size := range map[string]int{"valid": 1 << 20, "too large": 1<<20 + 1} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(path, make([]byte, size), 0o600))
			_, err := readOutput(path)
			if name == "too large" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestBackends(t *testing.T) {
	for name, want := range map[string]struct{ harness, keyEnv, basePath string }{
		"claude":      {"claude", "ANTHROPIC_API_KEY", "/model-proxy"},
		"codex":       {"codex", "CODEX_API_KEY", "/model-proxy/v1"},
		"codex-token": {"codex", "CODEX_ACCESS_TOKEN", "/model-proxy/backend-api/codex"},
	} {
		b, ok := backends[name]
		assert.True(t, ok, name)
		assert.Equal(t, want.harness, b.harness, name)
		assert.Equal(t, want.keyEnv, b.keyEnv, name)
		assert.Equal(t, want.basePath, b.basePath, name)
		assert.Equal(t, name == "codex-token", b.accessToken, name)
	}
}

func TestWriteConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		backend    string
		daybreak   bool
		wantConfig bool
		wantErr    bool
	}{
		"codex with daybreak":  {"codex", true, true, false},
		"codex without":        {"codex", false, true, false},
		"codex access token":   {"codex-token", false, true, false},
		"claude without":       {"claude", false, false, false},
		"claude with daybreak": {"claude", true, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			r := &Reader{backend: backends[tc.backend], Daybreak: tc.daybreak, ca: []byte("CA")}

			err := r.writeConfig(state, "https://proxy:1")

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			got, _ := os.ReadFile(filepath.Join(state, "config.toml"))
			if tc.wantConfig {
				require.NotEmpty(t, got)
			} else {
				require.Empty(t, got)
			}
			for _, want := range []string{"model_provider = \"tamis\"", "model_reasoning_effort = \"medium\"", "supports_websockets = false", "chatgpt_base_url = \"https://proxy:1/model-proxy/backend-api\"", "base_url = \"https://proxy:1" + backends[tc.backend].basePath + "\""} {
				if tc.wantConfig {
					require.Contains(t, string(got), want)
				}
			}
			ca, _ := os.ReadFile(filepath.Join(state, caFile))
			tokenAuth := strings.Contains(string(got), "requires_openai_auth = true") && !strings.Contains(string(got), "env_key")
			require.Equal(t, tc.backend == "codex-token", tokenAuth, "access token config = %q, CA = %q", got, ca)
			require.Equal(t, tokenAuth, string(ca) == "CA", "access token config = %q, CA = %q", got, ca)
		})
	}
}

func TestCodexRunsWithTheChatGPTFeaturesOff(t *testing.T) {
	h, err := harness.ByName("codex")
	require.NoError(t, err)

	args := strings.Join(h.Args(harness.Job{Workspace: container.WorkMount}), " ")

	for _, want := range []string{"-c analytics.enabled=false", "-c features.apps=false", "-c features.plugins=false"} {
		assert.Contains(t, args, want)
	}
}

func TestImagesArePinnedByDigest(t *testing.T) {
	pinned := regexp.MustCompile(`^ghcr\.io/php/tamis-agent@sha256:[0-9a-f]{64}$`)
	agents := map[string]bool{}
	for _, b := range backends {
		agents[b.harness] = true
		image := Images[b.harness]
		assert.Regexp(t, pinned, image, "%s: %q is not pinned by digest", b.harness, image)
	}
	assert.Len(t, Images, len(agents))
}

func TestKeepFailuresKeepsOnlyCodexErrorEvents(t *testing.T) {
	failed := `{"type":"turn.failed","error":{"message":"usage limit reached"}}`
	stream := strings.Join([]string{
		`{"type":"thread.started","thread_id":"t"}`,
		`{"type":"item.completed","item":{"type":"agent_message","text":"report content"}}`,
		`{"type":"item.completed","item":{"type":"error","message":"tool failed"}}`,
		`not json`,
		`{"type":"error","message":"stream disconnected"}`,
		failed,
	}, "\n")
	var kept strings.Builder

	keepFailures(strings.NewReader(stream), &kept)

	require.Equal(t, `{"type":"item.completed","item":{"type":"error","message":"tool failed"}}`+"\n"+`{"type":"error","message":"stream disconnected"}`+"\n"+failed, kept.String())
}

func TestKeepFailuresSkipsALineLongerThanTheOutputLimit(t *testing.T) {
	failed := `{"type":"turn.failed","error":{"message":"usage limit"}}`
	stream := `{"type":"error","message":"` + strings.Repeat("a", 2*maxAgentOutput) + `"}` + "\n" + failed
	var kept strings.Builder

	keepFailures(strings.NewReader(stream), &kept)

	require.Equal(t, failed, kept.String())
}

func TestKeepFailuresKeepsNothingFromASuccessfulRun(t *testing.T) {
	var kept strings.Builder

	keepFailures(strings.NewReader(`{"type":"turn.completed","usage":{"input_tokens":1}}`+"\nnot json\n"), &kept)

	require.Empty(t, kept.String())
}

func TestSalvageKeepsAValidReportFromAFailedRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"ok":true}`), 0o600))
	failure := errors.New("exit status 1")

	raw, err := salvage(path, func(json.RawMessage) error { return nil }, failure)

	require.JSONEq(t, `{"ok":true}`, string(raw))
	var incomplete *Incomplete
	require.ErrorAs(t, err, &incomplete)
	require.ErrorIs(t, err, failure, "the agent error was lost")
}

func TestSalvageFailsWithoutAValidReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"ok":false}`), 0o600))
	invalid := func(json.RawMessage) error { return errors.New("invalid") }

	for name, path := range map[string]string{"invalid": path, "missing": filepath.Join(dir, "missing.json")} {
		raw, err := salvage(path, invalid, errors.New("exit status 1"))
		require.Nil(t, raw, name)
		var agent *Error
		require.ErrorAs(t, err, &agent, name)
		var incomplete *Incomplete
		require.False(t, errors.As(err, &incomplete), name)
	}
}

func TestWriteWorkspaceWritesTheRequestFiles(t *testing.T) {
	workspace := t.TempDir()

	require.NoError(t, writeWorkspace(workspace, Request{Report: "report", Schema: []byte(`{}`), Files: map[string][]byte{"advisories/GHSA-a.md": []byte("advisory")}}))

	got, err := os.ReadFile(filepath.Join(workspace, "advisories", "GHSA-a.md"))
	require.NoError(t, err)
	require.Equal(t, "advisory", string(got))
	got, err = os.ReadFile(filepath.Join(workspace, "report.md"))
	require.NoError(t, err)
	require.Equal(t, "report", string(got))
}

func TestWriteWorkspaceRefusesFilesOutsideIt(t *testing.T) {
	for _, name := range []string{"../escape.md", "/tmp/escape.md", ""} {
		workspace := t.TempDir()
		require.Error(t, writeWorkspace(workspace, Request{Files: map[string][]byte{name: []byte("x")}}), name)
		_, err := os.Stat(filepath.Join(filepath.Dir(workspace), "escape.md"))
		require.True(t, os.IsNotExist(err), name)
	}
}
