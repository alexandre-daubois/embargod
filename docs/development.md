# Development

You need Go 1.27.3 and Docker.

## Build and test

```bash
go build ./cmd/tamis
go test -race ./...
```

Three fuzz targets cover the comment escaper, the duplicate-search clues and file reading:

| Target | Package |
|---|---|
| `FuzzText` | `./internal/report` |
| `FuzzClues` | `./internal/report` |
| `FuzzReadFileStaysInTrackedFiles` | `./internal/repo` |

```bash
go test ./internal/report -run '^$' -fuzz '^FuzzText$' -fuzztime 60s
```

The provider protocol filter is fuzzed in harness, with its model proxy.

On each push, CI checks formatting and `go mod tidy`, then runs `go vet`, the tests, the three fuzz targets and the Docker isolation tests of both agent images. Make both isolation jobs required release checks.

## Isolation tests

Build an agent image and run its isolation tests locally, without a real API key:

```bash
docker build --target codex -t tamis-test:codex docker/agent
TAMIS_TEST_IMAGE=tamis-test:codex go test -race -count=1 -tags integration ./internal/sandbox
```

Repeat with `claude`. The tests use fake model servers, check direct host, Internet and DNS access, and confirm the pinned CLI reaches the filtered proxy. The suite fails without Docker or with `TAMIS_TEST_IMAGE` unset.

## Agent images

[`docker/agent/Dockerfile`](../docker/agent/Dockerfile) builds the agent images, one target per agent:

```bash
docker build --target claude -t tamis-agent:claude docker/agent
```

When that directory changes on `main`, the `Agent image` workflow publishes both images to `ghcr.io/php/tamis-agent` with a build attestation. It then opens a pull request that updates the digests in [`internal/sandbox/images.json`](../internal/sandbox/images.json). tamis only runs the images pinned there, so new images reach users once that pull request lands in a release.

To bump an agent CLI, update its tag and the sha256 of each architecture's asset together in the Dockerfile. The workflow needs "Allow GitHub Actions to create and approve pull requests" in the repository settings.

## Releases

A `vYYYY.MM.DD.N` tag such as `v2026.10.25.1` runs the `Release` workflow. It builds tamis for Linux, macOS and Windows on amd64 and arm64, attests the six binaries and publishes them in a GitHub release. The action runs the Linux ones, the others serve local runs.

When the action's pinned commit carries such a tag, the action downloads the binary for the runner and checks its attestation against that commit before running it. For any other commit, the action builds tamis from source.

## Dependency updates

[Renovate](https://docs.renovatebot.com/) keeps the Go modules, pinned actions, base images and agent CLIs up to date, following [`renovate.json`](../renovate.json). It:

- updates each CLI's tag and checksums in one pull request,
- keeps `harness-proxy` in the agent image on the same version as the `harness` module,
- waits seven days after a release before proposing it.

It needs the [Renovate GitHub App](https://github.com/apps/renovate) installed on the repository.

## Running locally

tamis reads its configuration from environment variables, so it runs on any machine with Docker. From a checkout of the target repository:

```bash
REPOSITORY=your-org/your-project REPO_PATH=. ADVISORY=GHSA-xxxx-xxxx-xxxx ENGINE=claude GH_TOKEN="$(gh auth token)" LLM_API_KEY="$ANTHROPIC_API_KEY" RUNNER_IMAGE=tamis-agent:claude REFERENCES=HEAD OUTPUT_DIR=/private/path/to/reports ./tamis
```

tamis posts the comment for real. It skips an advisory that already has a completed comment from the configured bot, even after edits to the report or new followup comments.

## Layout

| Path | Role |
|---|---|
| `cmd/tamis` | Configuration and entry point |
| `internal/triage` | Advisory selection and the triage pipeline |
| `internal/sandbox` | The agent container and the model proxy that keeps the key on the host, through harness |
| `internal/budget` | Request and byte budgets shared by every agent and comparator of a run |
| `internal/usage` | Requests and tokens spent per advisory, for the log |
| `internal/engine` | The in-process model loop of the exact duplicate confirmation |
| `internal/tools` | The read-only tools of the exact duplicate confirmation |
| `internal/report` | Report schema, verification and rendering |
| `internal/repo` | Read-only access to tracked files |
| `internal/github` | GitHub REST client |
| `skill` | Instructions of the agent and of the duplicate search |
