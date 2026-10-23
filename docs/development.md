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

The `Agent image` workflow publishes both to `ghcr.io/alexandre-daubois/embargod-agent` with a build attestation when that directory changes on `main`, then opens a pull request updating the digests in [`internal/sandbox/images.json`](../internal/sandbox/images.json). embargod only runs the images pinned there, so new images reach users once that pull request is merged and released.

To bump an agent CLI, update its tag and the sha256 of each architecture's asset together in the Dockerfile. The workflow needs "Allow GitHub Actions to create and approve pull requests" in the repository settings.

## Dependency updates

[Renovate](https://docs.renovatebot.com/) keeps Go modules, pinned actions, base images and the agent CLIs up to date, following [`renovate.json`](../renovate.json). It updates each CLI's tag and checksums in one pull request, keeps `harness-proxy` in the agent image on the same version as the `harness` module, and waits seven days after a release before proposing it. It needs the [Renovate GitHub App](https://github.com/apps/renovate) installed on the repository.

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
