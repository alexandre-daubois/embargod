package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	proxyPort  = "3128"
	workMemory = "2g"
	workCPUs   = "2"
	workPIDs   = "256"
	workFile   = "67108864"
)

type isolatedRun struct {
	runtime container.Runtime
	image   string
	network string
	proxy   string
	proxyIP string
	token   string
}

func startIsolatedRun(ctx context.Context, runtime container.Runtime, image, modelPort string) (*isolatedRun, error) {
	if runtime.Bin != "docker" {
		return nil, errors.New("only Docker is supported")
	}
	run := &isolatedRun{runtime: runtime, image: image}
	var err error
	if run.network, err = isolatedName(); err != nil {
		return nil, err
	}
	run.proxy = "embargod-proxy-" + strings.TrimPrefix(run.network, "embargod-")
	run.token = egress.NewToken()

	if out, err := exec.CommandContext(ctx, runtime.Bin, "network", "create", "--internal", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", "--", run.network).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("creating the isolated network: %w: %s", err, strings.TrimSpace(string(out)))
	}
	failed := true
	defer func() {
		if failed {
			run.Close()
		}
	}()

	proxyEnv := container.SidecarEnv(container.SidecarConfig{
		Token:     run.token,
		Allow:     append([]string{egress.HostGatewayAlias}, allow...),
		APIPort:   modelPort,
		GatewayIP: egress.HostGatewayAlias,
	}, egress.ListenFirstIface+":"+proxyPort)
	args := []string{"run", "-d", "--name", run.proxy, "--network", run.network, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--add-host", egress.HostGatewayAlias + ":host-gateway", "-e", container.ProxyTokenEnv}
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

	return "embargod-" + strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(raw[:]), nil
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

func (r *isolatedRun) Run(ctx context.Context, h harness.Harness, job harness.Job, workspace, state string, mounts []container.Mount, keyEnv, key string, emit func(harness.Event)) error {
	if err := harness.WriteSystemPrompt(h, job); err != nil {
		return err
	}
	reportPath := filepath.Join(workspace, outputFile)
	if err := os.WriteFile(reportPath, nil, 0o600); err != nil {
		return err
	}
	job.Workspace = container.WorkMount
	args := r.agentArgs(h, job, workspace, state, reportPath, mounts, keyEnv)

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
	stderr, err := harness.StreamCmd(cmd, h, emit)
	if err != nil && strings.TrimSpace(stderr) != "" {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr))
	}

	return err
}

func (r *isolatedRun) agentArgs(h harness.Harness, job harness.Job, workspace, state, reportPath string, mounts []container.Mount, keyEnv string) []string {
	args := []string{
		"run", "--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--memory", workMemory, "--cpus", workCPUs, "--pids-limit", workPIDs, "--ulimit", "fsize=" + workFile + ":" + workFile,
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()), "-e", "HOME=/tmp", "--tmpfs", "/tmp:rw,exec,nosuid,size=256m",
		"--mount", "type=bind,src=" + workspace + ",dst=" + container.WorkMount + ",readonly",
		"--mount", "type=bind,src=" + reportPath + ",dst=" + container.WorkMount + "/" + outputFile,
		"--tmpfs", container.StateMount + ":rw,noexec,nosuid,size=256m",
		"-w", container.WorkMount, "--network", r.network, "--add-host", egress.HostGatewayAlias + ":" + r.proxyIP,
	}
	if _, err := os.Stat(filepath.Join(state, "config.toml")); err == nil {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(state, "config.toml")+",dst="+container.StateMount+"/config.toml,readonly")
	}
	for _, entry := range h.StateEnv(container.StateMount) {
		args = append(args, "-e", entry)
	}
	for _, entry := range h.Env(job.BaseURL) {
		name, _, _ := strings.Cut(entry, "=")
		if name != keyEnv && name != "CLAUDE_CODE_OAUTH_TOKEN" {
			args = append(args, "-e", entry)
		}
	}
	args = append(args, "-e", keyEnv, "-e", "HTTPS_PROXY", "-e", "HTTP_PROXY", "-e", "ALL_PROXY", "-e", "NO_PROXY", "-e", "https_proxy", "-e", "http_proxy", "-e", "all_proxy", "-e", "no_proxy")
	for _, mount := range mounts {
		spec := mount.Host + ":" + mount.Container
		if mount.ReadOnly {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
	}
	args = append(args, "--", r.image, h.Binary())
	args = append(args, h.Args(job)...)

	return args
}

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
	if r.proxy != "" {
		_ = exec.CommandContext(ctx, r.runtime.Bin, "rm", "-f", "--", r.proxy).Run()
	}
	if r.network != "" {
		_ = exec.CommandContext(ctx, r.runtime.Bin, "network", "rm", "--", r.network).Run()
	}
}
