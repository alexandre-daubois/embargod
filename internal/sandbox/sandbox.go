// Package sandbox runs the reader, the model that sees the untrusted report, as Claude Code or Codex inside a
// hardened container: read-only source, no network but the model and GitHub, and no secret, since the model
// key stays on the host behind modelproxy.
package sandbox

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
	"github.com/alpha-omega-security/harness/egress"
	"github.com/alpha-omega-security/harness/modelproxy"

	"github.com/php/tamis/internal/budget"
	"github.com/php/tamis/internal/usage"
)

const (
	maxTurns   = 80
	outputFile = "report.json"
	caFile     = "tamis-ca.pem"
	// srcDir is where the repository snapshot lives, relative to the workspace.
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
	// accessToken signs Codex in with a Codex access token, which it only sends over HTTPS.
	accessToken bool
}

var backends = map[string]backend{
	"claude":      {"claude", modelproxy.Anthropic, "ANTHROPIC_API_KEY", modelproxy.PathPrefix, false},
	"codex":       {"codex", modelproxy.OpenAI, "CODEX_API_KEY", modelproxy.PathPrefix + "/v1", false},
	"codex-token": {"codex", modelproxy.ChatGPT, "CODEX_ACCESS_TOKEN", modelproxy.PathPrefix + "/backend-api/codex", true},
}

// imagesJSON pins each agent image by digest, so a version of tamis always runs the images built for it.
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
	// ca is the PEM certificate the container trusts for the model proxy, with an access token only.
	ca []byte

	// Daybreak turns on OpenAI's cyber access program in Codex. The API key's org must be approved for it.
	Daybreak bool
}

// Request is one report to read. Validate checks the JSON the agent wrote, its error goes back to the agent.
type Request struct {
	// RepoPath is a snapshot from SnapshotSource, mounted read-only and shared by the runs of one source.
	RepoPath string
	System   string
	Prompt   string
	Report   string
	Schema   []byte
	Validate func(json.RawMessage) error
	// Offline cuts the agent off from GitHub, leaving it the model only.
	Offline bool
	// Files are written in the workspace, under their relative path, next to the report.
	Files map[string][]byte
}

// New starts the model proxy and the egress proxy for the whole process. Close stops the model proxy.
// With codex-token, the key is a Codex access token.
func New(name, model, apiKey, image string) (*Reader, error) {
	b, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("unknown agent %q, expected claude, codex or codex-token", name)
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
		image = Images[b.harness]
	}

	models, err := modelproxy.New(b.provider, apiKey, model, modelproxy.Options{Charge: budget.Take, Log: slog.Default()})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: models, ReadHeaderTimeout: 10 * time.Second}
	var ca []byte
	if b.accessToken {
		var cert tls.Certificate
		if ca, cert, err = modelproxy.NewCertificate(egress.HostGatewayAlias); err != nil {
			ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
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
		ca:        ca,
	}, nil
}

func (r *Reader) Close() error {
	return r.server.Close()
}

// Read runs the agent on one report and returns the JSON it wrote, after at most one correction round.
func (r *Reader) Read(ctx context.Context, req Request) (json.RawMessage, error) {
	workspace, err := os.MkdirTemp("", "tamis-work-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workspace)
	state, err := os.MkdirTemp("", "tamis-state-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(state)
	if err := writeWorkspace(workspace, req); err != nil {
		return nil, err
	}
	source, err := filepath.Abs(req.RepoPath)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(workspace, srcDir), 0o700); err != nil {
		return nil, err
	}

	token, revoke := r.models.Issue(ctx)
	defer func() {
		spent := revoke()
		usage.Add(ctx, usage.Usage{Requests: int64(spent.Requests), InputTokens: int64(spent.InputTokens), OutputTokens: int64(spent.OutputTokens)})
	}()
	hosts := allow
	if req.Offline {
		hosts = nil
	}
	origin := "http://" + egress.HostGatewayAlias + ":" + r.modelPort
	var env []string
	if r.backend.accessToken {
		origin = "https://" + egress.HostGatewayAlias + ":" + r.modelPort
		env = []string{"CODEX_CA_CERTIFICATE=" + container.StateMount + "/" + caFile, "CODEX_AUTHAPI_BASE_URL=" + origin + modelproxy.PathPrefix + "/auth"}
	}
	if err := r.writeConfig(state, origin); err != nil {
		return nil, err
	}
	a := &agent{Harness: r.harness}
	scope, err := r.runner(state, source, token, hosts, env).Open(ctx, a)
	if err != nil {
		return nil, err
	}
	defer scope.Close(nil)
	job := harness.Job{
		Workspace:    workspace,
		SrcDir:       srcDir,
		Prompt:       req.Prompt,
		SystemPrompt: req.System,
		Model:        r.model,
		MaxTurns:     maxTurns,
		OutputFile:   outputFile,
		BaseURL:      origin + r.backend.basePath,
	}

	for attempt := 0; attempt < 2; attempt++ {
		a.failures = boundedWriter{}
		err := scope.Run(ctx, job, nil)
		if err != nil {
			if failures := strings.TrimSpace(a.failures.String()); failures != "" {
				err = fmt.Errorf("%w: %s", err, failures)
			}
			return salvage(filepath.Join(workspace, outputFile), req.Validate, err)
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

func writeWorkspace(workspace string, req Request) error {
	files := map[string][]byte{"report.md": []byte(req.Report), "schema.json": req.Schema}
	for name, content := range req.Files {
		if !filepath.IsLocal(name) {
			return errors.New("a request file escapes the workspace")
		}
		files[name] = content
	}
	for name, content := range files {
		path := filepath.Join(workspace, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return err
		}
	}

	return nil
}

// salvage keeps a valid report the agent wrote before failing: Codex has no turn limit to stop on before its budget.
func salvage(path string, validate func(json.RawMessage) error, failure error) (json.RawMessage, error) {
	raw, err := readOutput(path)
	if err != nil || validate(raw) != nil {
		return nil, &Error{Err: failure}
	}

	return raw, &Incomplete{Err: &Error{Err: failure}}
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
func (r *Reader) writeConfig(state, origin string) error {
	if r.backend.harness != "codex" {
		if !r.Daybreak {
			return nil
		}
		return errors.New("daybreak is only available with codex")
	}

	auth := "env_key = \"CODEX_API_KEY\""
	if r.backend.accessToken {
		auth = "requires_openai_auth = true"
		if err := os.WriteFile(filepath.Join(state, caFile), r.ca, 0o600); err != nil {
			return err
		}
	}
	// The ChatGPT features are off: they would call routes the model proxy refuses.
	config := fmt.Sprintf("model_provider = \"tamis\"\nmodel_reasoning_effort = \"medium\"\ndaybreak = %t\nweb_search = \"disabled\"\nchatgpt_base_url = %q\n\n[features]\nremote_plugin = false\nplugin_sharing = false\ngoals = false\nimage_generation = false\nskill_mcp_dependency_install = false\n\n[model_providers.tamis]\nname = \"Tamis\"\nbase_url = %q\n%s\nwire_api = \"responses\"\nsupports_websockets = false\nsupports_standalone_web_search = false\nrequest_max_retries = 0\nstream_max_retries = 0\n", r.Daybreak, origin+modelproxy.PathPrefix+"/backend-api", origin+r.backend.basePath, auth)
	return os.WriteFile(filepath.Join(state, "config.toml"), []byte(config), 0o600)
}

// SnapshotSource keeps the sandbox on tracked content while retaining the current commit's public history.
// SnapshotSource resolves only a configured local reference; it never fetches from the project's origin.
func SnapshotSource(ctx context.Context, repoPath, target, reference string) error {
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "git", "-C", abs, "rev-parse", "--verify", "--end-of-options", reference+"^{commit}").Output()
	if err != nil {
		return errors.New("resolving a configured source reference")
	}
	commit := strings.TrimSpace(string(out))
	if err := exec.CommandContext(ctx, "git", "clone", "--no-local", "--no-hardlinks", "--no-tags", "--single-branch", "--quiet", "--", abs, target).Run(); err != nil {
		return errors.New("snapshotting the source repository")
	}
	if err := exec.CommandContext(ctx, "git", "-C", target, "fetch", "--no-tags", "--quiet", "--", abs, commit).Run(); err != nil {
		return errors.New("snapshotting the configured source reference")
	}
	if err := exec.CommandContext(ctx, "git", "-C", target, "checkout", "--quiet", "--detach", commit, "--").Run(); err != nil {
		return errors.New("checking out the configured source reference")
	}
	// The generated remote contains the host path but is not needed by the read-only agent.
	if err := os.WriteFile(filepath.Join(target, ".git", "config"), nil, 0o600); err != nil {
		return err
	}

	return nil
}

var ErrNoReport = errors.New("the agent did not write a valid report")

// Error wraps a failed agent run. Its message stays generic: the container's stderr may quote the report.
type Error struct {
	Err error
}

func (e *Error) Error() string { return "the agent run failed" }

func (e *Error) Unwrap() error { return e.Err }

// Incomplete comes with the report an agent wrote before its run failed, which may miss what it had left to check.
type Incomplete struct {
	Err error
}

func (e *Incomplete) Error() string { return "the agent stopped before finishing its report" }

func (e *Incomplete) Unwrap() error { return e.Err }
