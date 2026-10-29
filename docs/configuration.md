# Configuration

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` | | Required. API key of the model provider, or a Codex access token with `engine: openai`. |
| `github-token` | | Required. Token able to read and comment the repository advisories. |
| `references` | | Required, at most ten. Whitespace-separated local git references, one per supported branch. tamis analyses the first and locates the cited code on all of them. A missing reference fails the analysis. |
| `since` | | Triage only advisories created after this date, `2026-10-22` or RFC 3339. Required unless `advisory` is set. |
| `advisory` | | Triage this GHSA only, whatever its state and creation date. |
| `bot-login` | Owner of the token | Login tamis posts as, such as `my-app[bot]`. Required with a GitHub App token. |
| `repository` | Current repository | Repository owning the advisories. |
| `path` | `.` | Path of the repository checkout, relative to the workspace. |
| `engine` | `claude` | `claude` for Claude Code and the Anthropic API, `openai` for Codex and the OpenAI API. |
| `model` | `claude-opus-5-5` or `gpt-5.5` | Model of the reader, the duplicate search and the exact confirmation. `gpt-6.1-sol` with a Codex access token. |
| `daybreak` | `false` | Turns on OpenAI's Daybreak cyber access program in Codex. Needs `engine: openai` and an API key whose organisation OpenAI approved for it. |
| `comment` | `false` | Post the triage as a comment on the advisory. Off, every triage only reaches `project`, which must then be set, and the board records the failed attempts in `Attempts`. |
| `project` | | Private organisation project kept in sync with the advisories, as `org/number`. See [the project board](setup.md#5-project-board). |
| `issues-repository` | | Private repository the board items are created in as issues, so duplicates become sub-issues of their original report. Drafts when unset. See [the project board](setup.md#5-project-board). |
| `issues-token` | | Installation token for `issues-repository` only, with the "Issues" and organisation "Projects" permissions in read and write. Required with `issues-repository`. |
| `runner-image` | tamis agent image, pinned by digest | Image the agent runs in. It must contain the agent CLI, git, curl and `harness-proxy`. The action skips the attestation check for a custom image. |

The action refuses to run from a public workflow repository or from a `uses:` that is not a full commit SHA. Update that SHA through a reviewed pull request.

Outside GitHub Actions, tamis reads the same settings from environment variables: `LLM_API_KEY`, `GH_TOKEN`, `BOT_LOGIN`, `REPOSITORY`, `REPO_PATH`, `SINCE`, `ADVISORY`, `ENGINE`, `MODEL`, `DAYBREAK`, `RUNNER_IMAGE`, `REFERENCES`, `PROJECT`, `ISSUES_REPOSITORY`, `ISSUES_TOKEN` and `COMMENT`. `OUTPUT_DIR` must name a private directory for the reports. The action creates it in the runner's temporary storage and uploads it to the workflow repository with a seven-day retention.

## Source branches

Fetch the references with `fetch-depth: 0`. For php-src, list the default branch and each PHP branch your disclosure policy covers, such as `master origin/PHP-8.4`, and update the list as releases enter or leave support.

tamis analyses each reference on its own and records its exact commit in both copies of the result. It does not guess the maintained branches from the reporter's prose, and it never executes the source code.

## Private reports

The private artifact holds, per advisory:

| File | Contents |
|---|---|
| `.md` | The full report, with every duplicate the global search proposed and any duplicate search or confirmation that could not complete |
| `.comment.md` | The text the reporter sees, limited to published duplicates and to the unpublished exact duplicates that passed the [one-candidate confirmation](how-it-works.md#3-duplicate-search) |
| `.agent-error.txt` | Written when an agent run fails. It keeps the agent's error output and the error events of its JSON output, which may quote the report. |

Each report names the source commit and the input revision it covers.

## Resource budgets

| Scope | Limit |
|---|---|
| Execution | 800 provider requests and 256 MiB of request bodies in total, over at most 3 hours 50 minutes |
| Advisory | 200 requests and 64 MiB, shared by its reader run and its comparisons, and a 30-minute deadline that also cancels host-side git commands |
| Agent token | 150 requests, not counting the refused routes Codex calls on each run |
| Request | 1 MiB of body. API responses ask for at most 16,000 output tokens, and the ChatGPT backend applies its own output limits. |
| Reports | One per known reporter and per execution |

tamis starts a report only while the execution still holds a whole advisory budget and thirty minutes of its time. Otherwise the report waits for the next execution. SDK retries are off, but tamis retries an agent run that fails without a valid report once, after a minute. When a budget runs out, the report stays retriable and tamis does not mark it complete.

These bounds cap one execution, not the spending across scheduled runs. Provider pricing, tokenisation and ChatGPT credit policies differ, so request and byte limits give no monetary guarantee. On the provider side:

- use a dedicated account or project with an enforced spending or credit ceiling,
- restrict the models, and disable hosted tools and network allowlists,
- configure billing alerts.

In the workflow, keep a `timeout-minutes` of at least 240 and a single concurrency group.

## Project guidance

tamis appends a `.github/tamis.md` file from the project to the agent's instructions. Use it for what the model cannot guess, such as the scope, the public API, how the project scores CVSS and which configurations are realistic.

## Security policy

The agent checks the report against the files that define what the project treats as a security issue. tamis looks for them among the tracked files of the repository root, `.github/` and `docs/`:

1. `SECURITY` with a `.md`, `.markdown`, `.rst`, `.txt` or `.adoc` extension, in any case,
2. then `AGENTS.md` and `CLAUDE.md`.

The comment lists the files the agent checked. Without any of them, tamis leaves the section out.

## Engines

| Engine | Reader and global search | Exact confirmation | Model API |
|---|---|---|---|
| `claude` | Claude Code | Anthropic API | `api.anthropic.com` |
| `openai` | Codex | OpenAI Chat Completions | `api.openai.com` |
| `openai` with a Codex access token | Codex | Codex, in a container without GitHub access | `chatgpt.com` |

[`docker/agent/Dockerfile`](../docker/agent/Dockerfile) pins the agent CLI versions.

## Codex access token

A ChatGPT workspace without OpenAI API access can create a [Codex access token](https://learn.chatgpt.com/docs/enterprise/access-tokens) in its admin console and pass it as `api-key` with `engine: openai`. tamis recognises it by its `at-` prefix. The ChatGPT backend does not serve the API models, so the default model becomes `gpt-6.1-sol`. Prefer the token of a service account, with the shortest expiration you can rotate.
