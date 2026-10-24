package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

func TestSnapshotSourceCopiesOnlyTrackedContentAndHistory(t *testing.T) {
	repo := gitRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("tracked"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "--", "tracked.txt")
	git(t, repo, "commit", "--quiet", "--no-gpg-sign", "-m", "tracked")
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(repo, ".git", "config")
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(config, []byte("\n[http]\nextraheader = AUTHORIZATION: basic SECRET\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "src")
	if err := snapshotSource(t.Context(), repo, target); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(target, "tracked.txt")); err != nil || string(got) != "tracked" {
		t.Errorf("tracked file = %q, %v", got, err)
	}
	for _, path := range []string{"untracked.txt", filepath.Join(".git", "modules")} {
		if _, err := os.Stat(filepath.Join(target, path)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("untracked path %q reached the snapshot", path)
		}
	}
	if config, err := os.ReadFile(filepath.Join(target, ".git", "config")); err != nil || len(config) != 0 {
		t.Errorf("snapshot config = %q, %v", config, err)
	}
	git(t, target, "log", "-1", "--format=%s")
}

func TestSnapshotSourceRejectsADirectoryWithoutGit(t *testing.T) {
	if err := snapshotSource(t.Context(), t.TempDir(), filepath.Join(t.TempDir(), "src")); err == nil {
		t.Fatal("a source without git must be refused")
	}
}

func TestSnapshotSourceStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := snapshotSource(ctx, gitRepo(t), filepath.Join(t.TempDir(), "src")); err == nil {
		t.Fatal("a canceled snapshot must fail")
	}
}

func TestSnapshotSourceUsesTheConfiguredBranch(t *testing.T) {
	source := gitRepo(t)
	git(t, source, "branch", "stable")
	if err := os.WriteFile(filepath.Join(source, "new.txt"), []byte("HEAD-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, source, "add", "--", "new.txt")
	git(t, source, "commit", "--quiet", "--no-gpg-sign", "-m", "new branch code")
	target := filepath.Join(t.TempDir(), "src")
	if err := SnapshotSource(t.Context(), source, target, "stable"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("HEAD code reached the stable snapshot")
	}
	for _, ref := range []string{"missing", "--upload-pack=malicious"} {
		if err := SnapshotSource(t.Context(), source, filepath.Join(t.TempDir(), "src"), ref); err == nil {
			t.Fatal("invalid reference accepted")
		}
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
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestNewRejectsUnknownAgents(t *testing.T) {
	if _, err := New("gemini", "m", "key", ""); err == nil || !strings.Contains(err.Error(), "unknown agent") {
		t.Fatalf("got %v", err)
	}
}

func TestErrorHidesTheAgentOutput(t *testing.T) {
	err := &Error{err: errors.New("exit status 1: stderr quoting SECRET-PAYLOAD")}

	if err.Error() != "the agent run failed" || !strings.Contains(errors.Unwrap(err).Error(), "SECRET-PAYLOAD") {
		t.Fatalf("got %q", err.Error())
	}
}

func TestBoundedWriterRetainsOnlyTheOutputLimit(t *testing.T) {
	var w boundedWriter
	want := strings.Repeat("a", maxAgentOutput)
	if n, err := w.Write([]byte(want)); err != nil || n != len(want) || w.String() != want {
		t.Fatalf("bounded output: %d, %v, %d bytes", n, err, len(w.String()))
	}
}

func TestBoundedWriterDiscardsOutputPastTheLimit(t *testing.T) {
	var w boundedWriter
	overflow := strings.Repeat("a", maxAgentOutput+1)
	if n, err := w.Write([]byte(overflow)); err != nil || n != len(overflow) || len(w.String()) != maxAgentOutput {
		t.Fatalf("bounded output: %d, %v, %d bytes", n, err, len(w.String()))
	}
}

func TestAgentContainerUsesOnlyThePrivateProxyAndLimitsResources(t *testing.T) {
	h, err := harness.ByName("claude")
	if err != nil {
		t.Fatal(err)
	}
	run := &isolatedRun{runtime: container.Runtime{Bin: "docker"}, image: "agent", network: "private", proxyIP: "172.20.0.2", agent: "work"}
	args := run.agentArgs(h, harness.Job{Workspace: container.WorkMount}, "/host/work", "/host/state", "/host/work/report.json", "ANTHROPIC_API_KEY")
	joined := strings.Join(args, " ")
	for _, want := range []string{"host.docker.internal:172.20.0.2", "--network private", "--pids-limit 256", "--memory 2g", "--cpus 2", "src=/host/work,dst=/work,readonly", "--name work", "--log-driver none"} {
		if !strings.Contains(joined, want) {
			t.Errorf("container args miss %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "host.docker.internal:host-gateway") {
		t.Fatalf("the hostile container can reach the host gateway: %s", joined)
	}
}

func TestAccessTokenContainerGetsNoAmbientAPIKey(t *testing.T) {
	t.Setenv("CODEX_API_KEY", "ambient-secret")
	h, err := harness.ByName("codex")
	if err != nil {
		t.Fatal(err)
	}
	run := &isolatedRun{image: "agent", network: "private", proxyIP: "172.20.0.2", agent: "work"}
	args := run.agentArgs(h, harness.Job{Workspace: container.WorkMount}, "/host/work", "/host/state", "/host/work/report.json", "CODEX_ACCESS_TOKEN")
	for i, arg := range args {
		if arg == "CODEX_API_KEY" || strings.HasPrefix(arg, "CODEX_API_KEY=") {
			t.Fatalf("ambient API key reached argument %d: %s", i, arg)
		}
	}
	if !slices.Contains(args, "CODEX_ACCESS_TOKEN") {
		t.Fatal("access token key was not injected")
	}
}

func TestOnlyDockerCanStartAnIsolatedRun(t *testing.T) {
	if _, err := startIsolatedRun(t.Context(), container.Runtime{Bin: "podman"}, "agent", "1234", false, allow); err == nil {
		t.Fatal("an unsupported runtime must fail closed")
	}
}

func TestReadOutputIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	for name, size := range map[string]int{"valid": 1 << 20, "too large": 1<<20 + 1} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readOutput(path)
			if (err != nil) != (name == "too large") {
				t.Fatalf("error = %v", err)
			}
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
		if !ok || b.harness != want.harness || b.keyEnv != want.keyEnv || b.basePath != want.basePath || b.accessToken != (name == "codex-token") {
			t.Errorf("%s: %+v", name, b)
		}
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

			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			got, _ := os.ReadFile(filepath.Join(state, "config.toml"))
			if (len(got) > 0) != tc.wantConfig {
				t.Fatalf("config.toml = %q", got)
			}
			for _, want := range []string{"model_provider = \"embargod\"", "supports_websockets = false", "plugins = false", "[analytics]\nenabled = false", "chatgpt_base_url = \"https://proxy:1/model-proxy/backend-api\"", "base_url = \"https://proxy:1" + backends[tc.backend].basePath + "\""} {
				if tc.wantConfig && !strings.Contains(string(got), want) {
					t.Fatalf("config.toml misses %q: %q", want, got)
				}
			}
			ca, _ := os.ReadFile(filepath.Join(state, caFile))
			tokenAuth := strings.Contains(string(got), "requires_openai_auth = true") && !strings.Contains(string(got), "env_key")
			if tokenAuth != (tc.backend == "codex-token") || (string(ca) == "CA") != tokenAuth {
				t.Fatalf("access token config = %q, CA = %q", got, ca)
			}
		})
	}
}

func TestImagesArePinnedByDigest(t *testing.T) {
	pinned := regexp.MustCompile(`^ghcr\.io/alexandre-daubois/embargod-agent@sha256:[0-9a-f]{64}$`)
	agents := map[string]bool{}
	for _, b := range backends {
		agents[b.harness] = true
		if image := Images[b.harness]; !pinned.MatchString(image) {
			t.Errorf("%s: %q is not pinned by digest", b.harness, image)
		}
	}
	if len(Images) != len(agents) {
		t.Errorf("images.json lists %d images for %d agents", len(Images), len(agents))
	}
}
