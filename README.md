# embargod

A GitHub Action that gives every new private vulnerability report a first, evidence-based read with an LLM, and posts it as a comment on the advisory.

For each new report it:

- looks for duplicates among the other advisories of the repository,
- looks for public issues and pull requests already fixing or hardening the same code,
- checks that the files and functions the report cites exist in the repository,
- reads the security policy (`SECURITY.md`, `AGENTS.md`, `CLAUDE.md`) and points out what may exclude the report,
- suggests a CWE and a CVSS 4.0 base vector.

It does not decide anything, it helps maintainers sort the flow.

## Usage

Run the workflow from a private repository that targets the public one, so its logs, inputs and secrets stay private.

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

GitHub Actions has no trigger for security advisories, hence the schedule. Set `since` to the day you install the action so the existing backlog is left alone.

| Input | Default | Description |
|---|---|---|
| `since` | | Only advisories created after this date (`2026-10-22` or RFC 3339) are triaged. Required unless `advisory` is set. |
| `advisory` | | Triage this GHSA only, whatever its state and creation date. |
| `engine` | `claude` | `claude` or `openai`. |
| `model` | `claude-opus-5-5` / `gpt-5.5` | Model id. |
| `api-key` | | API key of the LLM provider. |
| `github-token` | | Personal access token of a security manager of the repository, with the repository security advisories scope. A dedicated bot account is best, embargod recognises its own comments by its login. |
| `repository` | current repository | Repository owning the advisories. |
| `path` | `.` | Path of the repository checkout. |

Add a `.github/embargod.md` file to the project to tell the model what is specific to it: scope, CVSS conventions, realistic configurations.

Before installing it, know that the reporter sees the comment, since GitHub does not let the API post confidential comments yet, and that reports are sent to the LLM provider you pick.

## License

MIT
