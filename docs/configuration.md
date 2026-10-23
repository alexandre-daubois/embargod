# Configuration

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` | | API key of the model provider. Required. |
| `github-token` | | Token able to read and comment the repository advisories. Required. |
| `bot-login` | owner of the token | Login the comments are posted as, e.g. `my-app[bot]`. Required with a GitHub App token. |
| `repository` | current repository | Repository owning the advisories. |
| `path` | `.` | Path of the repository checkout, relative to the workspace. |
| `since` | | Only advisories created after this date (`2026-10-22` or RFC 3339) are triaged. Required unless `advisory` is set. |
| `advisory` | | Triage this GHSA only, whatever its state and creation date. |
| `engine` | `claude` | `claude` (Claude Code and the Anthropic API) or `openai` (Codex and the OpenAI API). |
| `model` | `claude-opus-5-5` / `gpt-5.5` | Model used by both the agent and the duplicate search. |
| `daybreak` | `false` | Turn on OpenAI's Daybreak cyber access program in Codex. `openai` engine only, and the API key's organisation must be approved for it. |
| `runner-image` | embargod agent image, pinned by digest | Image the agent runs in. It must contain the agent CLI, git, curl and `harness-proxy`. A custom image skips the attestation check. |

Outside GitHub Actions, the same settings are read from environment variables: `LLM_API_KEY`, `GH_TOKEN`, `BOT_LOGIN`, `REPOSITORY`, `REPO_PATH`, `SINCE`, `ADVISORY`, `ENGINE`, `MODEL`, `DAYBREAK` and `RUNNER_IMAGE`.

## Project guidance

A `.github/embargod.md` file in the project is appended to the agent's instructions. Use it for what the model cannot guess: what is in scope, how the project scores CVSS, which configurations are realistic.

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

The agent CLI versions are pinned in [`docker/agent/Dockerfile`](../docker/agent/Dockerfile).
