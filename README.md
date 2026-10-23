# embargod

A GitHub Action that gives every new private vulnerability report a first, evidence-based read with an LLM, and posts it as a comment on the advisory.

For each new report it:

- looks for duplicates among the other advisories of the repository, in every state,
- looks for public issues and pull requests already fixing or hardening the same code,
- checks that the files and functions the report cites exist in the repository,
- reads the repository `SECURITY.md` and points out what may exclude the report,
- suggests a CWE and a CVSS 4.0 base vector, with a short justification.

It does not decide anything. It helps maintainers sort the flow, with a confidence level on every duplicate and related issue.

## Usage

Run the workflow from a private repository that targets the public one, for example `your-org/embargod-runner` for `your-org/your-project`. See [Run it from a private repository](#run-it-from-a-private-repository) for why.

```yaml
name: Embargod

on:
  schedule:
    - cron: "*/15 * * * *"
  workflow_dispatch:
    inputs:
      advisory:
        description: GHSA to triage
        required: false

jobs:
  triage:
    runs-on: ubuntu-latest
    environment: embargod
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          repository: your-org/your-project
          fetch-depth: 0
          persist-credentials: false
      - uses: alexandre-daubois/embargod@v1
        with:
          repository: your-org/your-project
          since: "2026-10-22"
          advisory: ${{ inputs.advisory }}
          engine: claude
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.EMBARGOD_TOKEN }}
```

GitHub Actions has no trigger for security advisories, hence the schedule. Each run lists the advisories in the `triage` state created after `since` and skips the ones it already commented, so set `since` to the day you install the action and the existing backlog is left alone.

| Input | Default | Description |
|---|---|---|
| `since` | | Only advisories created after this date (`2026-10-22` or RFC 3339) are triaged. Required unless `advisory` is set. |
| `advisory` | | Triage this GHSA only, whatever its state and creation date. |
| `engine` | `claude` | `claude` or `openai`. |
| `model` | `claude-opus-5-5` / `gpt-5.5` | Model id. |
| `api-key` | | API key of the LLM provider. |
| `github-token` | | Token able to read and comment the repository advisories. |
| `repository` | current repository | Repository owning the advisories. |
| `path` | `.` | Path of the repository checkout. |

### Run it from a private repository

Run logs, job summaries and artifacts of a public repository are public, and embargod handles embargoed reports. The run log only ever gets counters and status codes: no report content, no comment, no GHSA identifier, no error message from GitHub or the LLM provider, and a panic is logged as "internal error" without its value. GitHub itself prints the step inputs at the top of the step log, so a GHSA passed through `advisory` shows there. Running the workflow from a private repository keeps those inputs, the timing of the runs and the secrets away from the public project.

### The token

Unpublished advisories are only visible to security managers, administrators and collaborators of each advisory. Use a personal access token of an account that is a security manager or an administrator of the repository, with the repository security advisories scope. embargod recognises its own comments by that account's login, so a dedicated bot account is best. Keep it in a protected environment so pull request workflows cannot reach it.

### Project guidance

Add a `.github/embargod.md` file to tell the model what is specific to your project: what is in scope, how you score CVSS, which configurations are realistic. It is appended to the triage method.

## What to know before installing it

- The reporter sees the comment. GitHub does not yet let the API post confidential comments, nor delete comments.
- The advisory comments API is in public preview since October 2026 and is not documented yet, so it may change.
- The report text is controlled by the reporter, and other advisories may be under embargo, so no model ever holds both. A first model reads the report with public tools only (`git grep`, reading files tracked by git, `git log`, issue search). A second model looks for duplicates among the other advisories without seeing the report: it only gets the affected paths, C identifiers, line numbers, PHP entry points and CWE found by the first one, filtered against strict patterns, and reads the code there itself, and it can only answer with GHSA identifiers, a confidence level and an exact flag. Neither has a shell or network access of its own, and neither can read `.git`, untracked files or symlinks, which is also why `persist-credentials: false` matters.
- Every piece of text in the comment is escaped, so it cannot hold links, images, HTML or mentions.
- Duplicates among published advisories are listed whatever their confidence. Unpublished ones (in triage, draft or closed) are only listed when they are exact duplicates, which tells the reporter nothing they do not know, and partial matches on them are dropped without a trace, not even in the count of removed suggestions.
- A crafted report can still steer the first model, so its summary or its policy check may be misleading. It can also point the duplicate search at a line of its choice, which reveals whether another report describes that exact bug, much like a bug bounty platform answering "duplicate".
- References the model makes to advisories, issues or pull requests are checked against GitHub before posting, and the ones that do not exist are removed.
- Embargoed reports are sent to the LLM provider you pick. Check that your security policy allows it.

## Using the method without the action

The triage method lives in [`skill/SKILL.md`](skill/SKILL.md) in the Agent Skills format, so Claude Code or Codex can apply it by hand on a report.

## License

MIT
