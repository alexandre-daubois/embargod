// Package sandbox runs the reader, the model that sees the untrusted report, as Claude Code or Codex inside a
// hardened container: read-only source, no network but the model and GitHub, and no secret, since the model
// key stays on the host behind modelproxy.
package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
	"github.com/alpha-omega-security/harness/egress"

	"github.com/alexandre-daubois/embargod/internal/modelproxy"
)

const (
	maxTurns   = 80
	outputFile = "report.json"
	// srcDir is where the repository is mounted, relative to the workspace.
	srcDir = "src"
)

// allow is the only external host the agent may reach: public issue and pull request search.
var allow = []string{"api.github.com"}

type backend struct {
	harness  string
	provider modelproxy.Provider
	keyEnv   string
	// basePath completes the model proxy URL the way the CLI expects its API base URL.
	basePath string
	// image is built from docker/agent and published by the agent-image workflow.
	image string
}

var backends = map[string]backend{
	"claude": {"claude", modelproxy.Anthropic, "ANTHROPIC_API_KEY", modelproxy.PathPrefix, "ghcr.io/alexandre-daubois/embargod-agent:claude"},
	"codex":  {"codex", modelproxy.OpenAI, "CODEX_API_KEY", modelproxy.PathPrefix + "/v1", "ghcr.io/alexandre-daubois/embargod-agent:codex"},
}

type Reader struct {
	backend   backend
	harness   harness.Harness
	model     string
	image     string
	runtime   container.Runtime
	models    *modelproxy.Proxy
	modelPort string
	proxyURL  string
	server    *http.Server

	// Daybreak turns on OpenAI's cyber access program in Codex. The API key's org must be approved for it.
	Daybreak bool
}

// Request is one report to read. Validate checks the JSON the agent wrote, its error goes back to the agent.
type Request struct {
	RepoPath string
	System   string
	Prompt   string
	Report   string
	Schema   []byte
	Validate func(json.RawMessage) error
}

// New starts the model proxy and the egress proxy for the whole process. Close stops the model proxy.
func New(name, model, apiKey, image string) (*Reader, error) {
	b, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("unknown agent %q, expected claude or codex", name)
	}
	h, err := harness.ByName(b.harness)
	if err != nil {
		return nil, err
	}
	rt, ok := container.DetectRuntime("")
	if !ok {
		return nil, errors.New("a container runtime (docker or podman) is required to run the agent")
	}
	if image == "" {
		image = b.image
	}

	models, err := modelproxy.New(b.provider, apiKey)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: models, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(ln) }()
	modelPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	ep := hostProxy(modelPort)
	egressPort, err := egress.Start(ep)
	if err != nil {
		_ = server.Close()
		return nil, err
	}

	return &Reader{
		backend:   b,
		harness:   h,
		model:     model,
		image:     image,
		runtime:   rt,
		models:    models,
		modelPort: modelPort,
		proxyURL:  egress.ProxyURL(ep.Token, egress.HostGatewayAlias, egressPort),
		server:    server,
	}, nil
}

// hostProxy is the egress proxy of runtimes without a sidecar. It forwards inspected HTTP to the model proxy, the
// only host service the agent may reach, and checks the allowlist before that, so the host gateway must be on it.
func hostProxy(modelPort string) *egress.Proxy {
	return &egress.Proxy{Allow: append([]string{egress.HostGatewayAlias}, allow...), Token: egress.NewToken(), APIPort: modelPort}
}

func (r *Reader) Close() error {
	return r.server.Close()
}

// Read runs the agent on one report and returns the JSON it wrote, after at most one correction round.
func (r *Reader) Read(ctx context.Context, req Request) (json.RawMessage, error) {
	workspace, err := os.MkdirTemp("", "embargod-work-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workspace)
	state, err := os.MkdirTemp("", "embargod-state-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(state)
	if err := r.writeConfig(state); err != nil {
		return nil, err
	}

	for name, content := range map[string][]byte{"report.md": []byte(req.Report), "schema.json": req.Schema} {
		if err := os.WriteFile(filepath.Join(workspace, name), content, 0o600); err != nil {
			return nil, err
		}
	}
	mounts, err := sourceMounts(req.RepoPath, workspace)
	if err != nil {
		return nil, err
	}

	token, revoke := r.models.Issue()
	defer revoke()
	runner := container.Runner{
		Runtime:  r.runtime,
		Image:    r.image,
		Hardened: true,
		ProxyURL: r.proxyURL,
		StateDir: state,
		Mounts:   mounts,
		// The agent only ever holds the token, under the name its CLI reads the key from.
		Env:        []string{r.backend.keyEnv},
		OmitEnv:    []string{r.backend.keyEnv, "CLAUDE_CODE_OAUTH_TOKEN"},
		ProcessEnv: []string{r.backend.keyEnv + "=" + token},
		Sidecar:    container.SidecarConfig{Allow: allow, APIPort: r.modelPort},
	}
	job := harness.Job{
		Workspace:    workspace,
		SrcDir:       srcDir,
		Prompt:       req.Prompt,
		SystemPrompt: req.System,
		Model:        r.model,
		MaxTurns:     maxTurns,
		OutputFile:   outputFile,
		BaseURL:      "http://" + egress.HostGatewayAlias + ":" + r.modelPort + r.backend.basePath,
	}

	for attempt := 0; ; attempt++ {
		var session string
		// Events are not logged: they hold the report and the agent's reasoning about it.
		err := runner.Run(ctx, r.harness, job, func(e harness.Event) {
			if e.SessionID != "" {
				session = e.SessionID
			}
		})
		if err != nil {
			return nil, &Error{err: err}
		}

		raw, err := os.ReadFile(filepath.Join(workspace, outputFile))
		if err == nil {
			if err = req.Validate(raw); err == nil {
				return raw, nil
			}
		}
		if attempt > 0 || session == "" {
			return nil, ErrNoReport
		}
		job.ResumeSessionID = session
		job.ResumePrompt = fmt.Sprintf("/work/%s is missing or does not match /work/schema.json: %v. Write it again, fixed.", outputFile, err)
	}
}

// writeConfig writes the agent CLI configuration into its state directory, which harness points CODEX_HOME at.
func (r *Reader) writeConfig(state string) error {
	if !r.Daybreak {
		return nil
	}
	if r.backend.harness != "codex" {
		return errors.New("daybreak is only available with codex")
	}

	return os.WriteFile(filepath.Join(state, "config.toml"), []byte("daybreak = true\n"), 0o600)
}

// sourceMounts mounts the repository read-only and hides .git/config, where actions/checkout may persist a token.
func sourceMounts(repoPath, workspace string) ([]container.Mount, error) {
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, err
	}
	target := container.WorkMount + "/" + srcDir
	mounts := []container.Mount{{Host: abs, Container: target, ReadOnly: true}}
	if info, err := os.Stat(filepath.Join(abs, ".git", "config")); err == nil && info.Mode().IsRegular() {
		empty := filepath.Join(workspace, ".empty-git-config")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			return nil, err
		}
		mounts = append(mounts, container.Mount{Host: empty, Container: target + "/.git/config", ReadOnly: true})
	}

	return mounts, nil
}

var ErrNoReport = errors.New("the agent did not write a valid report")

// Error wraps a failed agent run. Its message stays generic: the container's stderr may quote the report.
type Error struct {
	err error
}

func (e *Error) Error() string { return "the agent run failed" }

func (e *Error) Unwrap() error { return e.err }
