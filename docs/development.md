# Development

Requirements: Go 1.27.3 and Docker.

## Build and test

```bash
go build ./cmd/embargod
```

```bash
go test -race ./...
```

Four fuzz targets cover the comment escaper, duplicate-search clues, file reading and the provider protocol filter:

```bash
go test ./internal/report -run '^$' -fuzz '^FuzzText$' -fuzztime 60s
```

The others are `FuzzClues` in `./internal/report`, `FuzzReadFileStaysInTrackedFiles` in `./internal/repo`, and `FuzzProviderRequest` in `./internal/modelproxy`. CI runs formatting, `go mod tidy`, `go vet`, the tests, the four fuzz targets and Docker isolation tests for both agent images on every push. Make both isolation jobs required release checks.

Build each agent image and run its isolation tests locally without a real API key:

```bash
docker build --target codex -t embargod-test:codex docker/agent
EMBARGOD_TEST_IMAGE=embargod-test:codex go test -race -count=1 -tags integration ./internal/sandbox
```

Repeat for `claude`. The tests use fake model servers, check direct host/Internet/DNS access and validate that the pinned CLI can reach the filtered proxy. Missing Docker or an unset test image fails the suite.

## Agent images

The agent images are built from [`docker/agent/Dockerfile`](../docker/agent/Dockerfile), one target per agent:

```bash
docker build --target claude -t embargod-agent:claude docker/agent
```

The `Agent image` workflow publishes both to `ghcr.io/alexandre-daubois/embargod-agent` with a build attestation when that directory changes on `main`, then opens a pull request updating the digests in [`internal/sandbox/images.json`](../internal/sandbox/images.json). embargod only runs the images pinned there, so new images reach users once that pull request is merged and released.

To bump an agent CLI, update its tag and the sha256 of each architecture's asset together in the Dockerfile. The workflow needs "Allow GitHub Actions to create and approve pull requests" in the repository settings.

## Releases

Pushing a `vX.Y.Z` tag runs the `Release` workflow, which builds embargod for Linux on amd64 and arm64, attests both binaries and publishes them in a GitHub release. When the action's pinned commit has such a release tag, the action downloads the binary for the runner and checks its attestation against that commit before running it. Any other pinned commit is built from source.

## Dependency updates

[Renovate](https://docs.renovatebot.com/) keeps Go modules, pinned actions, base images and the agent CLIs up to date, following [`renovate.json`](../renovate.json). It updates each CLI's tag and checksums in one pull request, keeps `harness-proxy` in the agent image on the same version as the `harness` module, and waits seven days after a release before proposing it. It needs the [Renovate GitHub App](https://github.com/apps/renovate) installed on the repository.

## Running locally

embargod reads its configuration from environment variables, so it runs on any machine with Docker. From a checkout of the target repository:

```bash
REPOSITORY=your-org/your-project REPO_PATH=. ADVISORY=GHSA-xxxx-xxxx-xxxx ENGINE=claude GH_TOKEN="$(gh auth token)" LLM_API_KEY="$ANTHROPIC_API_KEY" RUNNER_IMAGE=embargod-agent:claude REFERENCES=HEAD OUTPUT_DIR=/private/path/to/reports ./embargod
```

The comment is posted for real. An advisory with a completed comment from the configured bot is skipped, including after edits to the report or followup comments.

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
