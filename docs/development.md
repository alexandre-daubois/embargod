# Development

Requirements: Go 1.27.3 and Docker.

## Build and test

```bash
go build ./cmd/embargod
```

```bash
go test -race ./...
```

Three fuzz targets cover the comment escaper, the duplicate-search clue filter and file reading:

```bash
go test ./internal/report -run '^$' -fuzz '^FuzzText$' -fuzztime 60s
```

The other two are `FuzzClues` in `./internal/report` and `FuzzReadFileStaysInTrackedFiles` in `./internal/repo`. CI runs formatting, `go mod tidy`, `go vet`, the tests and the three fuzz targets on every push.

## Agent images

The agent images are built from [`docker/agent/Dockerfile`](../docker/agent/Dockerfile), one target per agent:

```bash
docker build --target claude -t embargod-agent:claude docker/agent
```

The `Agent image` workflow publishes both to `ghcr.io/alexandre-daubois/embargod-agent` when that directory changes on `main`. To bump an agent CLI, update its tag and the sha256 of each architecture's asset together.

## Running locally

embargod reads its configuration from environment variables, so it runs on any machine with Docker. From a checkout of the target repository:

```bash
REPOSITORY=your-org/your-project REPO_PATH=. ADVISORY=GHSA-xxxx-xxxx-xxxx ENGINE=claude GH_TOKEN="$(gh auth token)" LLM_API_KEY="$ANTHROPIC_API_KEY" RUNNER_IMAGE=embargod-agent:claude ./embargod
```

The comment is posted for real. The comments API cannot delete it, and a triaged advisory is skipped until its comment is removed by hand.

## Layout

| Path | Role |
|---|---|
| `cmd/embargod` | Configuration and entry point |
| `internal/triage` | Advisory selection and the triage pipeline |
| `internal/sandbox` | The agent container, through harness |
| `internal/modelproxy` | The proxy keeping the model key on the host |
| `internal/engine` | The in-process model loop of the duplicate search |
| `internal/tools` | The duplicate search's read-only tools |
| `internal/report` | Report schema, verification and rendering |
| `internal/repo` | Read-only access to tracked files |
| `internal/github` | GitHub REST client |
| `skill` | Instructions of the agent and of the duplicate search |
