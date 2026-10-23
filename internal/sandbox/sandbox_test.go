package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

func TestSourceMountsHideGitConfig(t *testing.T) {
	repo, workspace := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("extraheader = AUTHORIZATION: basic SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}

	mounts, err := sourceMounts(repo, workspace)
	if err != nil {
		t.Fatal(err)
	}

	if len(mounts) != 2 {
		t.Fatalf("mounts = %+v", mounts)
	}
	if want := (container.Mount{Host: repo, Container: "/work/src", ReadOnly: true}); mounts[0] != want {
		t.Errorf("source mount = %+v, want %+v", mounts[0], want)
	}
	mask := mounts[1]
	if mask.Container != "/work/src/.git/config" || !mask.ReadOnly {
		t.Errorf("mask mount = %+v", mask)
	}
	if content, err := os.ReadFile(mask.Host); err != nil || len(content) != 0 {
		t.Errorf("the mask must be an empty file, got %q, %v", content, err)
	}
}

func TestSourceMountsWithoutGit(t *testing.T) {
	mounts, err := sourceMounts(t.TempDir(), t.TempDir())
	if err != nil || len(mounts) != 1 || !mounts[0].ReadOnly {
		t.Fatalf("mounts = %+v, %v", mounts, err)
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

func TestAgentContainerUsesOnlyThePrivateProxyAndLimitsResources(t *testing.T) {
	h, err := harness.ByName("claude")
	if err != nil {
		t.Fatal(err)
	}
	run := &isolatedRun{runtime: container.Runtime{Bin: "docker"}, image: "agent", network: "private", proxyIP: "172.20.0.2"}
	args := run.agentArgs(h, harness.Job{Workspace: container.WorkMount}, "/host/work", "/host/state", "/host/work/report.json", nil, "ANTHROPIC_API_KEY")
	joined := strings.Join(args, " ")
	for _, want := range []string{"host.docker.internal:172.20.0.2", "--network private", "--pids-limit 256", "--memory 2g", "--cpus 2", "src=/host/work,dst=/work,readonly"} {
		if !strings.Contains(joined, want) {
			t.Errorf("container args miss %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "host.docker.internal:host-gateway") {
		t.Fatalf("the hostile container can reach the host gateway: %s", joined)
	}
}

func TestOnlyDockerCanStartAnIsolatedRun(t *testing.T) {
	if _, err := startIsolatedRun(t.Context(), container.Runtime{Bin: "podman"}, "agent", "1234"); err == nil {
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
	for name, wantKey := range map[string]string{"claude": "ANTHROPIC_API_KEY", "codex": "CODEX_API_KEY"} {
		b, ok := backends[name]
		if !ok || b.keyEnv != wantKey || b.harness != name {
			t.Errorf("%s: %+v", name, b)
		}
	}
	if backends["codex"].basePath != "/model-proxy/v1" || backends["claude"].basePath != "/model-proxy" {
		t.Errorf("base paths: %+v", backends)
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
		"claude without":       {"claude", false, false, false},
		"claude with daybreak": {"claude", true, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			r := &Reader{backend: backends[tc.backend], Daybreak: tc.daybreak}

			err := r.writeConfig(state, "http://proxy/model-proxy/v1")

			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			got, _ := os.ReadFile(filepath.Join(state, "config.toml"))
			if (len(got) > 0) != tc.wantConfig {
				t.Fatalf("config.toml = %q", got)
			}
			if tc.wantConfig && (!strings.Contains(string(got), "model_provider = \"embargod\"") || !strings.Contains(string(got), "supports_websockets = false")) {
				t.Fatalf("unsafe config.toml = %q", got)
			}
		})
	}
}

func TestImagesArePinnedByDigest(t *testing.T) {
	pinned := regexp.MustCompile(`^ghcr\.io/alexandre-daubois/embargod-agent@sha256:[0-9a-f]{64}$`)
	for name := range backends {
		if image := Images[name]; !pinned.MatchString(image) {
			t.Errorf("%s: %q is not pinned by digest", name, image)
		}
	}
	if len(Images) != len(backends) {
		t.Errorf("images.json lists %d images for %d agents", len(Images), len(backends))
	}
}
