# tamis

[![CI](https://github.com/php/tamis/actions/workflows/ci.yml/badge.svg)](https://github.com/php/tamis/actions/workflows/ci.yml)

First-pass triage of private vulnerability reports on GitHub. When a new security advisory comes in, tamis has an LLM agent investigate it against the repository and posts its findings as a comment on the advisory.

For each report, tamis:

- lists public duplicates in the comment, and embargoed advisories only when they are exact duplicates, by identifier,
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
name: tamis

on:
  schedule:
    - cron: "*/15 * * * *"
  workflow_dispatch:
    inputs:
      advisory:
        description: GHSA to triage
        required: false

concurrency:
  group: tamis

jobs:
  triage:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: tamis
    permissions:
      contents: read
    steps:
      - uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0
        id: app
        with:
          client-id: ${{ vars.TAMIS_CLIENT_ID }}
          private-key: ${{ secrets.TAMIS_PRIVATE_KEY }}
          owner: your-org
          repositories: your-project
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: your-org/your-project
          fetch-depth: 0
          persist-credentials: false
      # Replace this placeholder with the full SHA of a reviewed Tamis commit.
      - uses: php/tamis@REPLACE_WITH_REVIEWED_FULL_COMMIT_SHA
        with:
          repository: your-org/your-project
          # A date, or an RFC 3339 time with its offset: "2026-10-22T14:30:00+02:00"
          since: "2026-10-22"
          advisory: ${{ inputs.advisory }}
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ steps.app.outputs.token }}
          bot-login: your-app-slug[bot]
          # List every branch your project supports; these refs must exist in the checkout.
          references: master origin/release-branch
```

Set `since` to the installation date so existing advisories are left alone. Keep the workflow repository private: the action uploads reports there as artifacts, retained for seven days. The [setup guide](docs/setup.md) covers source branches and provider spending limits.

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
