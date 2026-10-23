package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestBackends(t *testing.T) {
	for name, wantKey := range map[string]string{"claude": "ANTHROPIC_API_KEY", "codex": "CODEX_API_KEY"} {
		b, ok := backends[name]
		if !ok || b.keyEnv != wantKey || b.harness != name || b.image != "ghcr.io/alexandre-daubois/embargod-agent:"+name {
			t.Errorf("%s: %+v", name, b)
		}
	}
	if backends["codex"].basePath != "/model-proxy/v1" || backends["claude"].basePath != "/model-proxy" {
		t.Errorf("base paths: %+v", backends)
	}
}

func TestWriteConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		backend  string
		daybreak bool
		want     string
		wantErr  bool
	}{
		"codex with daybreak":  {"codex", true, "daybreak = true\n", false},
		"codex without":        {"codex", false, "", false},
		"claude without":       {"claude", false, "", false},
		"claude with daybreak": {"claude", true, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			r := &Reader{backend: backends[tc.backend], Daybreak: tc.daybreak}

			err := r.writeConfig(state)

			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			got, _ := os.ReadFile(filepath.Join(state, "config.toml"))
			if string(got) != tc.want {
				t.Fatalf("config.toml = %q, want %q", got, tc.want)
			}
		})
	}
}
