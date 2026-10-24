# Configuration

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` | | API key of the model provider, or a Codex access token with `openai`. Required. |
| `github-token` | | Token able to read and comment the repository advisories. Required. |
| `bot-login` | owner of the token | Login the comments are posted as, e.g. `my-app[bot]`. Required with a GitHub App token. |
| `repository` | current repository | Repository owning the advisories. |
| `path` | `.` | Path of the repository checkout, relative to the workspace. |
| `since` | | Only advisories created after this date (`2026-10-22` or RFC 3339) are triaged. Required unless `advisory` is set. |
| `advisory` | | Triage this GHSA only, whatever its state and creation date. |
| `engine` | `claude` | `claude` (Claude Code and the Anthropic API) or `openai` (Codex and the OpenAI API). |
| `model` | `claude-opus-5-5` / `gpt-5.5` | Model used by both the agent and the duplicate search. `gpt-6.1-sol` with a Codex access token. |
| `daybreak` | `false` | Turn on OpenAI's Daybreak cyber access program in Codex. `openai` engine only, and the API key's organisation must be approved for it. |
| `runner-image` | embargod agent image, pinned by digest | Image the agent runs in. It must contain the agent CLI, git, curl and `harness-proxy`. A custom image skips the attestation check. |
| `signing-key` | | Base64-encoded 32-byte Ed25519 seed, stored as a secret. Required. |
| `references` | | Whitespace-separated local git references, one for each supported branch. Required, at most ten. A missing reference fails the analysis. |

Outside GitHub Actions, the same settings are read from environment variables: `LLM_API_KEY`, `GH_TOKEN`, `BOT_LOGIN`, `REPOSITORY`, `REPO_PATH`, `SINCE`, `ADVISORY`, `ENGINE`, `MODEL`, `DAYBREAK`, `RUNNER_IMAGE`, `SIGNING_KEY` and `REFERENCES`. `OUTPUT_DIR` must name a private directory for the signed reports. The action creates that directory in the runner's temporary storage and uploads it to the private workflow repository with seven-day retention.

The action requires a private workflow repository and a full commit SHA in `uses:`. Update that SHA through a reviewed pull request. `verification-key` is an action output containing the public signing key; keep a trusted copy outside advisory comments.

## Source branches

Fetch the configured references with `fetch-depth: 0`. For php-src, include the default branch and every PHP branch covered by your disclosure policy, for example `master origin/PHP-8.4` when those are the branches you support. Keep the list current as releases enter or leave support. Embargod analyses each reference separately and includes its exact commit in both copies of the result; it does not infer the maintained branches from a reporter's prose. No source code is executed.

## Signed reports

Generate the signing seed once with `openssl rand -base64 32`, store it as `EMBARGOD_SIGNING_KEY`, then obtain its public key with `SIGNING_KEY` set in the environment:

```bash
embargod public-key
```

The private artifact contains a full signed `.md` report and a signed `.comment.md` copy of the reporter-visible text. Download either file from the private workflow run, or save the raw Markdown of a comment, then verify it against your trusted public key:

```bash
embargod verify --public-key YOUR_TRUSTED_PUBLIC_KEY --repository php/php-src --advisory GHSA-xxxx-xxxx-xxxx --file report.md
```

A collaborator can still change how an ordinary comment looks on GitHub. An edit invalidates its signature; use the private artifact as the reference and verify signatures before relying on comments. The footer covers the entire raw body, repository, advisory and input revision. Copying it to another report cannot authenticate that report. Rotating the key invalidates old signatures for automatic deduplication and can cause reports to be processed again.

## Resource budgets

An execution permits at most 128 provider requests and 32 MiB of cumulative request bodies. Each advisory shares 64 requests and 8 MiB across all branches, reader runs and comparisons; each agent token additionally permits 32 requests. A request body cannot exceed 1 MiB. API responses request at most 16,000 output tokens; the ChatGPT backend has its own output limits. The ten-minute advisory deadline also cancels host-side git commands. At most ten reports and one report per known reporter are attempted per execution. SDK retries are disabled.

These bounds limit each execution, not spending across scheduled runs. Use a dedicated provider account/project with an enforced spending or credit ceiling, restrict models, disable hosted tools and network allowlists there, and configure billing alerts. Provider pricing, tokenisation and ChatGPT credit policies differ, so byte/request limits are not a monetary guarantee. Keep a workflow `timeout-minutes` and a single concurrency group. Budget exhaustion leaves a report retriable rather than marking it permanently complete.

## Project guidance

A `.github/embargod.md` file in the project is appended to the agent's instructions. Use it for what the model cannot guess: what is in scope, what the project's public API is, how the project scores CVSS, which configurations are realistic.

## Security policy

The agent checks the report against the files that describe what the project treats as a security issue. embargod looks for them among the tracked files of the repository root, `.github/` and `docs/`:

- `SECURITY` with a `.md`, `.markdown`, `.rst`, `.txt` or `.adoc` extension, in any case,
- then `AGENTS.md` and `CLAUDE.md`.

The comment lists the files it was checked against. Without any of them, the section is left out.

## Engines

| Engine | Agent CLI | Duplicate search | Model API |
|---|---|---|---|
| `claude` | Claude Code | Anthropic API | `api.anthropic.com` |
| `openai` | Codex | OpenAI Chat Completions | `api.openai.com` |
| `openai` with a Codex access token | Codex | Codex, in a container without GitHub access | `chatgpt.com` |

The agent CLI versions are pinned in [`docker/agent/Dockerfile`](../docker/agent/Dockerfile).

## Codex access token

A ChatGPT workspace without OpenAI API access can create a [Codex access token](https://learn.chatgpt.com/docs/enterprise/access-tokens) in its admin console and pass it as `api-key` with `engine: openai`. It is recognised by its `at-` prefix. The ChatGPT backend does not serve the API models, so the default model becomes `gpt-6.1-sol`. Prefer a token of a service account, with the shortest expiration you can rotate.
