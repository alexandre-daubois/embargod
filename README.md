# securibot

A GitHub Action that gives every new private vulnerability report a first, evidence-based read with an LLM, and posts it as a comment on the advisory.

For each new report it:

- looks for duplicates among the other advisories of the repository, in every state,
- looks for public issues and pull requests already fixing or hardening the same code,
- checks that the files and functions the report cites exist in the repository,
- reads the repository `SECURITY.md` and points out what may exclude the report,
- suggests a CWE and a CVSS 4.0 base vector, with a short justification.

It does not decide anything. It helps maintainers sort the flow, with a confidence level on every duplicate and related issue.

## Usage

```yaml
name: Securibot

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
    environment: securibot
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: alexandre-daubois/securibot@v1
        with:
          since: "2026-10-22"
          advisory: ${{ inputs.advisory }}
          engine: claude
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.SECURIBOT_TOKEN }}
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
| `dry-run` | `false` | Write the comments to the job summary instead of posting them. Nothing marks an advisory as done in this mode, so pair it with `advisory` in a manual run rather than with the schedule, which would pay for the same triage every 15 minutes. |

### The token

Unpublished advisories are only visible to security managers, administrators and collaborators of each advisory. Use a token of an account that is a security manager or an administrator of the repository, with the repository security advisories scope. Keep it in a protected environment so pull request workflows cannot reach it.

### Project guidance

Add a `.github/securibot.md` file to tell the model what is specific to your project: what is in scope, how you score CVSS, which configurations are realistic. It is appended to the triage method.

## What to know before installing it

- The reporter sees the comment. GitHub does not yet let the API post confidential comments, nor delete comments.
- The advisory comments API is in public preview since October 2026 and is not documented yet, so it may change.
- The report text is controlled by the reporter. The model only gets read-only tools (advisories, issue search, `git grep`, file reading confined to the checkout, `git log`) and has no shell nor network access of its own. Comment text is sanitised so it cannot mention people.
- References the model makes to advisories, issues or pull requests are checked against GitHub before posting, and the ones that do not exist are removed.
- Embargoed reports are sent to the LLM provider you pick. Check that your security policy allows it.

## Using the method without the action

The triage method lives in [`skill/SKILL.md`](skill/SKILL.md) in the Agent Skills format, so Claude Code or Codex can apply it by hand on a report.

## License

MIT
