// Package sandbox runs the reader, the model that sees the untrusted report, as Claude Code or Codex inside a
// hardened container: read-only source, no network but the model and GitHub, and no secret, since the model
// key stays on the host behind modelproxy.
package sandbox

import (
	"context"
	_ "embed"
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
}

var backends = map[string]backend{
	"claude": {"claude", modelproxy.Anthropic, "ANTHROPIC_API_KEY", modelproxy.PathPrefix},
	"codex":  {"codex", modelproxy.OpenAI, "CODEX_API_KEY", modelproxy.PathPrefix + "/v1"},
}

// imagesJSON pins each agent image by digest, so a version of embargod always runs the images built for it.
// The agent-image workflow updates it through a pull request after publishing new images.
//
//go:embed images.json
var imagesJSON []byte

var Images = func() map[string]string {
	var images map[string]string
	if err := json.Unmarshal(imagesJSON, &images); err != nil {
		panic("sandbox: invalid images.json: " + err.Error())
	}

	return images
}()

type Reader struct {
	backend   backend
	harness   harness.Harness
	model     string
	image     string
	runtime   container.Runtime
	models    *modelproxy.Proxy
	modelPort string
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
		image = Images[name]
	}

	models, err := modelproxy.New(b.provider, apiKey, model)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: models, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(ln) }()
	modelPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	return &Reader{
		backend:   b,
		harness:   h,
		model:     model,
		image:     image,
		runtime:   rt,
		models:    models,
		modelPort: modelPort,
		server:    server,
	}, nil
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
	for name, content := range map[string][]byte{"report.md": []byte(req.Report), "schema.json": req.Schema} {
		if err := os.WriteFile(filepath.Join(workspace, name), content, 0o600); err != nil {
			return nil, err
		}
	}
	if err := os.Mkdir(filepath.Join(workspace, srcDir), 0o700); err != nil {
		return nil, err
	}
	mounts, err := sourceMounts(req.RepoPath, workspace)
	if err != nil {
		return nil, err
	}

	token, revoke := r.models.Issue()
	defer revoke()
	run, err := startIsolatedRun(ctx, r.runtime, r.image, r.modelPort)
	if err != nil {
		return nil, err
	}
	defer run.Close()
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
	if err := r.writeConfig(state, job.BaseURL); err != nil {
		return nil, err
	}

	for attempt := 0; attempt < 2; attempt++ {
		// Events are not logged: they hold the report and the agent's reasoning about it.
		err := run.Run(ctx, r.harness, job, workspace, state, mounts, r.backend.keyEnv, token, func(harness.Event) {})
		if err != nil {
			return nil, &Error{err: err}
		}

		raw, err := readOutput(filepath.Join(workspace, outputFile))
		if err == nil {
			if err = req.Validate(raw); err == nil {
				return raw, nil
			}
		}
		job.Prompt = fmt.Sprintf("%s\n\nYour previous attempt did not produce valid output: %v. Write /work/%s again, fixed.", req.Prompt, err, outputFile)
	}

	return nil, ErrNoReport
}

func readOutput(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("report is too large")
	}

	return data, nil
}

// writeConfig writes the agent CLI configuration into its state directory, which harness points CODEX_HOME at.
func (r *Reader) writeConfig(state, baseURL string) error {
	if r.backend.harness != "codex" {
		if !r.Daybreak {
			return nil
		}
		return errors.New("daybreak is only available with codex")
	}

	config := fmt.Sprintf("model_provider = \"embargod\"\ndaybreak = %t\nweb_search = \"disabled\"\n\n[model_providers.embargod]\nname = \"Embargod\"\nbase_url = %q\nenv_key = \"CODEX_API_KEY\"\nwire_api = \"responses\"\nsupports_websockets = false\nsupports_standalone_web_search = false\nrequest_max_retries = 0\nstream_max_retries = 0\n", r.Daybreak, baseURL)
	return os.WriteFile(filepath.Join(state, "config.toml"), []byte(config), 0o600)
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
