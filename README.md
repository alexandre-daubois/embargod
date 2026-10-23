# embargod

[![CI](https://github.com/alexandre-daubois/embargod/actions/workflows/ci.yml/badge.svg)](https://github.com/alexandre-daubois/embargod/actions/workflows/ci.yml)

First-pass triage of private vulnerability reports on GitHub. When a new security advisory comes in, embargod has an LLM agent investigate it against the repository and posts its findings as a comment on the advisory.

For each report, embargod:

- lists duplicates among the repository's other advisories,
- finds public issues and pull requests already fixing or hardening the same code,
- checks that the files and functions the report cites exist,
- reads the security policy and flags what may exclude the report,
- suggests a CWE and a CVSS 4.0 base vector.

It informs the maintainers' decision and never makes it.

## Quick start

1. Create a GitHub App for your organisation with the "Repository security advisories" permission in read and write, and install it on the project repository only.
2. In a private repository, store the App's client ID and private key, and an Anthropic or OpenAI API key, or a [Codex access token](docs/configuration.md#codex-access-token).
3. Add this workflow to the private repository:

```yaml
name: embargod

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
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ steps.app.outputs.token }}
          bot-login: your-app-slug[bot]
```

Set `since` to the installation date so existing advisories are left alone. The [setup guide](docs/setup.md) covers each step in detail.

## Documentation

- [Setup](docs/setup.md): GitHub App, private repository, secrets and first run.
- [Configuration](docs/configuration.md): inputs, project guidance and engines.
- [How it works](docs/how-it-works.md): the triage pipeline and the comment it posts.
- [Security](docs/security.md): threat model, isolation and known limits.
- [Development](docs/development.md): building, testing and running locally.

## Before installing

The reporter can read the comment, since the GitHub API cannot post confidential comments yet, and the report is sent to the model provider you choose. Make sure your disclosure policy allows both.

## License

MIT
