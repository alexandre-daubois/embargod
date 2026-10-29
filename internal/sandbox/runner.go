package sandbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

const maxAgentOutput = 1 << 20

// agent keeps the failure events of a run's output, which otherwise holds the report and the agent's
// reasoning about it.
type agent struct {
	harness.Harness
	failures boundedWriter
}

// EgressHosts is empty so the egress proxy allows the model proxy and the request's hosts only, not the
// provider's own API.
func (*agent) EgressHosts() []string { return nil }

func (a *agent) ParseStream(r io.Reader, _ func(harness.Event)) { keepFailures(r, &a.failures) }

// runner keeps the agent on a network whose only way out is the egress proxy, allowing the model proxy and
// hosts. harness refuses tunnels to its API port, so a model proxy served over TLS is reached as a separate
// host port.
func (r *Reader) runner(state, source, token string, hosts, env []string) container.Runner {
	sidecar := container.SidecarConfig{Allow: hosts, APIPort: r.modelPort}
	if r.backend.accessToken {
		sidecar.APIPort, sidecar.HostPorts = "", []string{r.modelPort}
	}

	return container.Runner{
		Runtime:  r.runtime,
		Image:    r.image,
		StateDir: state,
		Mounts:   []container.Mount{{Host: source, Container: container.WorkMount + "/" + srcDir, ReadOnly: true}},
		// Codex's SQLite state crashes it with SIGBUS on a state directory bind-mounted by Docker Desktop.
		Env:               append(env, r.backend.keyEnv, "CODEX_SQLITE_HOME=/tmp/codex-sqlite"),
		OmitEnv:           []string{r.backend.keyEnv, "CLAUDE_CODE_OAUTH_TOKEN", "CODEX_API_KEY"},
		ProcessEnv:        []string{r.backend.keyEnv + "=" + token},
		Hardened:          true,
		IsolateHost:       true,
		Sidecar:           sidecar,
		ReadOnlyWorkspace: true,
		Memory:            "2g",
		CPUs:              "2",
		PIDsLimit:         256,
		FileSizeLimit:     64 << 20,
	}
}

// keepFailures copies the error events of a JSONL agent output and discards the rest, lines longer than
// maxAgentOutput included. Codex exec --json
// reports why it stopped only there, as "error" and "turn.failed" events or "error" items.
func keepFailures(r io.Reader, w io.Writer) {
	br := bufio.NewReaderSize(r, maxAgentOutput)
	for {
		line, err := br.ReadSlice('\n')
		for errors.Is(err, bufio.ErrBufferFull) {
			line = nil
			_, err = br.ReadSlice('\n')
		}
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
