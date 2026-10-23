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

Create a GitHub App for your organisation with [this pre-filled form](https://github.com/organizations/YOUR-ORG/settings/apps/new?name=YOUR-ORG-embargod&description=First-pass%20triage%20of%20new%20security%20advisories&url=https://github.com/alexandre-daubois/embargod&public=false&webhook_active=false&repository_advisories=write), after replacing `YOUR-ORG` in its address. It only asks for the "Repository security advisories" permission. Then generate a private key in its settings, install it on the project repository only, and store its client ID in an `EMBARGOD_CLIENT_ID` variable and its key in an `EMBARGOD_PRIVATE_KEY` secret.

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

concurrency:
  group: embargod

jobs:
  triage:
    runs-on: ubuntu-latest
    environment: embargod
    permissions:
      contents: read
    steps:
      - uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0
        id: app
        with:
          client-id: ${{ vars.EMBARGOD_CLIENT_ID }}
          private-key: ${{ secrets.EMBARGOD_PRIVATE_KEY }}
          owner: your-org
          repositories: your-project
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
          github-token: ${{ steps.app.outputs.token }}
          bot-login: your-app-slug[bot]
```

GitHub Actions has no trigger for security advisories, hence the schedule. Set `since` to the day you install the action so the existing backlog is left alone.

| Input | Default | Description |
|---|---|---|
| `since` | | Only advisories created after this date (`2026-10-22` or RFC 3339) are triaged. Required unless `advisory` is set. |
| `advisory` | | Triage this GHSA only, whatever its state and creation date. |
| `engine` | `claude` | `claude` or `openai`. |
| `model` | `claude-opus-5-5` / `gpt-5.5` | Model id. |
| `api-key` | | API key of the LLM provider. |
| `github-token` | | Token able to read and comment the advisories. Best is a GitHub App installed on the repository only, with the "Repository security advisories" permission in read and write, so comments are posted as the App. A personal access token of a security manager works too. |
| `bot-login` | owner of the token | Login the comments are posted as, used to recognise them. Required with a GitHub App token, which cannot look it up: `your-app-slug[bot]`. |
| `repository` | current repository | Repository owning the advisories. |
| `path` | `.` | Path of the repository checkout. |

Add a `.github/embargod.md` file to the project to tell the model what is specific to it: scope, CVSS conventions, realistic configurations.

Before installing it, know that the reporter sees the comment, since GitHub does not let the API post confidential comments yet, and that reports are sent to the LLM provider you pick.

## License

MIT
