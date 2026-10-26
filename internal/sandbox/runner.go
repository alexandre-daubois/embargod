package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
	"github.com/alpha-omega-security/harness/egress"
)

const (
	proxyPort      = "3128"
	workMemory     = "2g"
	workCPUs       = "2"
	workPIDs       = "256"
	workFile       = "67108864"
	maxAgentOutput = 1 << 20
)

type isolatedRun struct {
	runtime container.Runtime
	image   string
	network string
	proxy   string
	agent   string
	proxyIP string
	token   string
	// env is set in the agent container on top of the harness environment.
	env []string
}

// startIsolatedRun starts the egress proxy, letting the agent reach the model proxy and hosts. harness
// refuses tunnels to its API port, so a model proxy served over TLS is reached as a separate host port.
func startIsolatedRun(ctx context.Context, runtime container.Runtime, image, modelPort string, tls bool, hosts []string) (*isolatedRun, error) {
	if runtime.Bin != "docker" {
		return nil, errors.New("only Docker is supported")
	}
	run := &isolatedRun{runtime: runtime, image: image}
	var err error
	if run.network, err = isolatedName(); err != nil {
		return nil, err
	}
	run.proxy = "tamis-proxy-" + strings.TrimPrefix(run.network, "tamis-")
	run.agent = "tamis-agent-" + strings.TrimPrefix(run.network, "tamis-")
	run.token = egress.NewToken()

	if out, err := exec.CommandContext(ctx, runtime.Bin, "network", "create", "--driver", "bridge", "--internal", "--ipv6=false", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", "--opt", "com.docker.network.bridge.gateway_mode_ipv6=isolated", "--", run.network).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("creating the isolated network: %w: %s", err, strings.TrimSpace(string(out)))
	}
	failed := true
	defer func() {
		if failed {
			run.Close()
		}
	}()

	sidecar := container.SidecarConfig{
		Token:     run.token,
		Allow:     append([]string{egress.HostGatewayAlias}, hosts...),
		APIPort:   modelPort,
		GatewayIP: egress.HostGatewayAlias,
	}
	if tls {
		sidecar.APIPort, sidecar.HostPorts = "", []string{modelPort}
	}
	proxyEnv := container.SidecarEnv(sidecar, egress.ListenFirstIface+":"+proxyPort)
	args := []string{"run", "-d", "--name", run.proxy, "--network", run.network, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--ulimit", "fsize=16777216:16777216", "--log-driver", "json-file", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--add-host", egress.HostGatewayAlias + ":host-gateway", "-e", container.ProxyTokenEnv}
	for _, entry := range proxyEnv[1:] {
		args = append(args, "-e", entry)
	}
	args = append(args, "--", image, "harness-proxy", "--require-capability="+egress.CapabilityDenyAPIConnect)
	cmd := exec.CommandContext(ctx, runtime.Bin, args...)
	cmd.Env = withEnv(os.Environ(), container.ProxyTokenEnv, run.token)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("starting the egress proxy: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, runtime.Bin, "network", "connect", "--", "bridge", run.proxy).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("connecting the egress proxy: %w: %s", err, strings.TrimSpace(string(out)))
	}
	out, err := exec.CommandContext(ctx, runtime.Bin, "inspect", "--format", fmt.Sprintf(`{{(index .NetworkSettings.Networks %q).IPAddress}}`, run.network), "--", run.proxy).Output()
	if err != nil {
		return nil, errors.New("inspecting the egress proxy")
	}
	ip := strings.TrimSpace(string(out))
	if net.ParseIP(ip) == nil {
		return nil, errors.New("the egress proxy has no private address")
	}
	run.proxyIP = ip
	if err := run.waitReady(ctx); err != nil {
		return nil, err
	}
	failed = false

	return run, nil
}

func isolatedName() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}

	return "tamis-" + strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(raw[:]), nil
}

func (r *isolatedRun) waitReady(ctx context.Context) error {
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		out, err := exec.CommandContext(ctx, r.runtime.Bin, "logs", "--", r.proxy).CombinedOutput()
		logs := strings.TrimSpace(string(out))
		if err == nil && strings.Contains(logs, "egress proxy listening") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("the egress proxy did not become ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (r *isolatedRun) Run(ctx context.Context, h harness.Harness, job harness.Job, workspace, source, state, keyEnv, key string) error {
	if err := harness.WriteSystemPrompt(h, job); err != nil {
		return err
	}
	reportPath := filepath.Join(workspace, outputFile)
	if err := os.WriteFile(reportPath, nil, 0o600); err != nil {
		return err
	}
	job.Workspace = container.WorkMount
	args := r.agentArgs(h, job, workspace, source, state, reportPath, keyEnv)

	cmd := exec.CommandContext(ctx, r.runtime.Bin, args...)
	cmd.Env = withEnv(os.Environ(), keyEnv, key)
	for _, env := range []struct{ key, value string }{
		{"HTTPS_PROXY", egress.EndpointURL(r.token, net.JoinHostPort(r.proxyIP, proxyPort))},
		{"HTTP_PROXY", egress.EndpointURL(r.token, net.JoinHostPort(r.proxyIP, proxyPort))},
		{"ALL_PROXY", egress.EndpointURL(r.token, net.JoinHostPort(r.proxyIP, proxyPort))},
		{"NO_PROXY", ""},
		{"https_proxy", egress.EndpointURL(r.token, net.JoinHostPort(r.proxyIP, proxyPort))},
		{"http_proxy", egress.EndpointURL(r.token, net.JoinHostPort(r.proxyIP, proxyPort))},
		{"all_proxy", egress.EndpointURL(r.token, net.JoinHostPort(r.proxyIP, proxyPort))},
		{"no_proxy", ""},
	} {
		cmd.Env = withEnv(cmd.Env, env.key, env.value)
	}
	var stderr, failures boundedWriter
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	keepFailures(stdout, &failures)
	err = cmd.Wait()
	if out := strings.TrimSpace(stderr.String() + "\n" + failures.String()); err != nil && out != "" {
		return fmt.Errorf("%w: %s", err, out)
	}

	return err
}

// keepFailures copies the error events of a JSONL agent output and discards the rest. Codex exec --json
// reports why it stopped only there, as "error" and "turn.failed" events or "error" items.
func keepFailures(r io.Reader, w io.Writer) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type string `json:"type"`
			} `json:"item"`
		}
		if json.Unmarshal(line, &event) == nil && (event.Type == "error" || event.Type == "turn.failed" || event.Item.Type == "error") {
			_, _ = w.Write(line)
		}
		if err != nil {
			_, _ = io.Copy(io.Discard, r)
			return
		}
	}
}

func (r *isolatedRun) agentArgs(h harness.Harness, job harness.Job, workspace, source, state, reportPath, keyEnv string) []string {
	args := []string{
		"run", "--rm", "--name", r.agent, "--log-driver", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--memory", workMemory, "--cpus", workCPUs, "--pids-limit", workPIDs, "--ulimit", "fsize=" + workFile + ":" + workFile,
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()), "-e", "HOME=/tmp", "--tmpfs", "/tmp:rw,exec,nosuid,size=256m",
		"--mount", "type=bind,src=" + workspace + ",dst=" + container.WorkMount + ",readonly",
		"--mount", "type=bind,src=" + source + ",dst=" + container.WorkMount + "/" + srcDir + ",readonly",
		"--mount", "type=bind,src=" + reportPath + ",dst=" + container.WorkMount + "/" + outputFile,
		"--tmpfs", container.StateMount + ":rw,noexec,nosuid,size=256m",
		"-w", container.WorkMount, "--network", r.network, "--add-host", egress.HostGatewayAlias + ":" + r.proxyIP,
	}
	for _, name := range []string{"config.toml", caFile} {
		if _, err := os.Stat(filepath.Join(state, name)); err == nil {
			args = append(args, "--mount", "type=bind,src="+filepath.Join(state, name)+",dst="+container.StateMount+"/"+name+",readonly")
		}
	}
	for _, entry := range r.env {
		args = append(args, "-e", entry)
	}
	for _, entry := range h.StateEnv(container.StateMount) {
		args = append(args, "-e", entry)
	}
	for _, entry := range h.Env(job.BaseURL) {
		name, _, _ := strings.Cut(entry, "=")
		if name != keyEnv && name != "CLAUDE_CODE_OAUTH_TOKEN" && name != "CODEX_API_KEY" {
			args = append(args, "-e", entry)
		}
	}
	args = append(args, "-e", keyEnv, "-e", "HTTPS_PROXY", "-e", "HTTP_PROXY", "-e", "ALL_PROXY", "-e", "NO_PROXY", "-e", "https_proxy", "-e", "http_proxy", "-e", "all_proxy", "-e", "no_proxy")
	args = append(args, "--", r.image, h.Binary())
	args = append(args, h.Args(job)...)

	return args
}

type boundedWriter struct {
	b bytes.Buffer
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if remaining := maxAgentOutput - w.b.Len(); remaining > 0 {
		w.b.Write(p[:min(remaining, len(p))])
	}

	return len(p), nil
}

func (w *boundedWriter) String() string { return w.b.String() }

func withEnv(env []string, key, value string) []string {
	prefix := key + "="
	filtered := env[:0]
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}

	return append(filtered, prefix+value)
}

func (r *isolatedRun) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if r.agent != "" {
		_ = exec.CommandContext(ctx, r.runtime.Bin, "rm", "-f", "--", r.agent).Run()
	}
	if r.proxy != "" {
		_ = exec.CommandContext(ctx, r.runtime.Bin, "rm", "-f", "--", r.proxy).Run()
	}
	if r.network != "" {
		_ = exec.CommandContext(ctx, r.runtime.Bin, "network", "rm", "--", r.network).Run()
	}
}
