# tamis

[![CI](https://github.com/php/tamis/actions/workflows/ci.yml/badge.svg)](https://github.com/php/tamis/actions/workflows/ci.yml)

tamis does a first-pass triage of private vulnerability reports on GitHub. When a new security advisory arrives, an LLM agent investigates it against the repository and tamis posts the findings as a comment on the advisory.

For each report, tamis:

- lists public duplicates, and names an embargoed advisory only when it is an exact duplicate,
- finds public issues and pull requests that already fix or harden the same code,
- checks that the files and functions the report cites exist,
- reads the security policy and flags what may exclude the report,
- suggests a CWE and a CVSS 4.0 base vector.

The maintainers keep the decision. tamis only prepares it.

A comment looks like this, with the cited code, the policy check and the severity folded in a details block. [How it works](docs/how-it-works.md#the-comment) shows the full layout.

```markdown
### Automated triage

> Suggestions generated with an LLM. They help sort the report and do not replace a maintainer's review.

Scanned on 2026-10-24 at 14:32 UTC on `main` at `21a7561`.

Plausible signed `char` passed to `isxdigit()` in `php_url_decode_ex()`, the given reproducer never reaches it.

#### Possible duplicates

| Advisory | Status | Confidence |
|---|---|---|
| GHSA-xxxx-xxxx-xxxx (oldest report) | Published | High • Exact duplicate |
```

The agent runs in an isolated container driven by [harness](https://github.com/alpha-omega-security/harness), the Alpha-Omega library behind [scrutineer](https://github.com/alpha-omega-security/scrutineer). [Security](docs/security.md) describes what the sandbox allows.

## Before installing

GitHub cannot post confidential advisory comments yet, so the reporter reads the comment. tamis also sends the report to the model provider you choose. Check that your disclosure policy allows both.

## Quick start

1. Create a GitHub App for your organisation with the "Repository security advisories" permission in read and write. Install it on the project repository only.
2. In a private repository, store the App's client ID and private key, and an Anthropic or OpenAI API key or a [Codex access token](docs/configuration.md#codex-access-token).
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
    timeout-minutes: 240
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
      # Replace this placeholder with the full SHA of a reviewed tamis release, and its tag.
      - uses: php/tamis@REPLACE_WITH_REVIEWED_FULL_COMMIT_SHA # vYYYY.MM.DD.N
        with:
          repository: your-org/your-project
          # A date, or an RFC 3339 time with its offset: "2026-10-22T14:30:00+02:00"
          since: "2026-10-22"
          advisory: ${{ inputs.advisory }}
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ steps.app.outputs.token }}
          bot-login: your-app-slug[bot]
          # List every branch your project supports. Each ref must exist in the checkout.
          references: master origin/release-branch
```

Pin the commit of a [release](https://github.com/php/tamis/releases) tag, since the action then runs the attested binary of that release instead of building tamis from source. Set `since` to the installation date so tamis leaves existing advisories alone. Keep the workflow repository private, since the action uploads the reports there as artifacts kept for seven days. The [setup guide](docs/setup.md) covers source branches and provider spending limits.

## Documentation

| Page | Contents |
|---|---|
| [Setup](docs/setup.md) | GitHub App, private repository, secrets and first run |
| [Configuration](docs/configuration.md) | Inputs, budgets, project guidance and engines |
| [How it works](docs/how-it-works.md) | The triage pipeline and the comment it posts |
| [Security](docs/security.md) | Threat model, isolation and known limits |
| [Development](docs/development.md) | Building, testing and running locally |

## License

MIT
