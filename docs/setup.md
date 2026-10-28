# Setup

tamis runs as a scheduled GitHub Actions workflow. You need a GitHub App, a private repository and a model provider key.

## 1. Create the GitHub App

Open this address with `YOUR-ORG` replaced by your organisation name. The form comes pre-filled with the only permission tamis needs, "Repository security advisories" in read and write, and no webhook.

```text
https://github.com/organizations/YOUR-ORG/settings/apps/new?name=YOUR-ORG-tamis&description=First-pass%20triage%20of%20new%20security%20advisories&url=https://github.com/php/tamis&public=false&webhook_active=false&repository_advisories=write
```

Once the App exists:

1. Note its client ID, and its slug from its public page address.
2. Generate a private key.
3. Install it on the project repository only, with "Only select repositories".

tamis posts as `<slug>[bot]` and recognises its own comments by that login.

A personal access token of a repository security manager with the `repository_advisories:write` scope also works. tamis then posts under that account, and you can omit `bot-login`.

## 2. Create a private repository

Run the workflow from a private repository such as `your-org/tamis-runner`, not from the public project. A public repository exposes its workflow logs, step inputs and run times, and tamis handles embargoed reports.

In that repository, create a `tamis` environment and add:

| Kind | Name | Value |
|---|---|---|
| Variable | `TAMIS_CLIENT_ID` | The App client ID |
| Secret | `TAMIS_PRIVATE_KEY` | The App private key |
| Secret | `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | The model provider key, or a [Codex access token](configuration.md#codex-access-token) |

Restrict the environment to the default branch so other workflows cannot read its secrets.

Use a dedicated provider project or account with a hard spending or credit limit, because alerts alone do not stop charges. Approve the configured models and their retention and residency terms. [Resource budgets](configuration.md#resource-budgets) lists the limits tamis enforces itself.

## 3. Add the workflow

Copy the workflow from the [README](../README.md#quick-start), then:

- replace `your-org`, `your-project`, `your-app-slug` and the commit placeholder,
- pin the full SHA of a reviewed commit, since the action refuses a branch or tag, and review later updates in the private repository,
- set `since` to today's date, so tamis only processes advisories in the `triage` state created after it,
- set `references` to every branch your security policy covers, default branch first. tamis analyses the report on the first one and locates the cited code on each.

Keep `persist-credentials: false` on the checkout so no token lands in `.git/config`, and `fetch-depth: 0` so the agent can read the history.

## 4. First run

Trigger the workflow by hand with the `advisory` input set to a test GHSA. tamis triages that advisory whatever its state and date, and posts the comment on it.

Download the private `tamis-reports` artifact and check that the comment names embargoed advisories only as exact duplicates. Then let the schedule take over. Artifact access follows the permissions of the private repository, so grant it to the security team only.

GitHub Actions has no trigger for security advisories, so the schedule polls every 15 minutes. A run with no new advisory neither starts the agent nor calls the model.
