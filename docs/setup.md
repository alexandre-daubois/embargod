# Setup

tamis runs as a scheduled GitHub Actions workflow. Installing it takes a GitHub App, a private repository and two API keys.

## 1. Create the GitHub App

Open this address with `YOUR-ORG` replaced by your organisation name. The form is pre-filled with the only permission tamis needs, "Repository security advisories" in read and write, and no webhook.

```text
https://github.com/organizations/YOUR-ORG/settings/apps/new?name=YOUR-ORG-tamis&description=First-pass%20triage%20of%20new%20security%20advisories&url=https://github.com/alexandre-daubois/tamis&public=false&webhook_active=false&repository_advisories=write
```

After creating it:

1. Note its client ID and its slug, shown in its public page address.
2. Generate a private key.
3. Install it on the project repository only, with "Only select repositories".

Comments are posted as `<slug>[bot]`, and tamis recognises its own comments by that login.

A personal access token of a repository security manager works too, with the `repository_advisories:write` scope, in which case the comments are posted under that account and `bot-login` can be omitted.

## 2. Create a private repository

Run the workflow from a private repository, for example `your-org/tamis-runner`, rather than from the public project. Workflow logs, step inputs and run times of a public repository are public, and tamis handles embargoed reports.

In that repository, create an `tamis` environment and add:

| Kind | Name | Value |
|---|---|---|
| Variable | `TAMIS_CLIENT_ID` | the App client ID |
| Secret | `TAMIS_PRIVATE_KEY` | the App private key |
| Secret | `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | the model provider key, or a [Codex access token](configuration.md#codex-access-token) |

Restrict the environment to the default branch so other workflows cannot read its secrets.

Use a dedicated provider project/account with a hard spending or credit limit. Alerts alone do not stop charges. Approve the configured models and their retention/residency terms; the Anthropic comparator does not switch models on refusal. See [resource budgets](configuration.md#resource-budgets) for the application limits.

## 3. Add the workflow

Copy the workflow from the [README](../README.md#quick-start) and replace `your-org`, `your-project`, `your-app-slug` and the Tamis commit placeholder. Pin the full SHA of a reviewed commit; the action refuses a branch or tag reference. Review updates in the private deployment repository. Set `since` to today's date: only advisories in the `triage` state created after it are processed. Set `references` to every branch covered by your security policy; a report is checked independently against each.

Keep `persist-credentials: false` on the checkout, so no token is written to `.git/config`, and `fetch-depth: 0`, so the agent can read the history.

## 4. First run

Trigger the workflow by hand with the `advisory` input set to a test GHSA. That advisory is triaged whatever its state and date, and the comment is posted on it. Download the private `tamis-reports` artifact and check that embargoed duplicate IDs appear only there, then let the schedule run. Artifact access follows the private runner repository's permissions; grant access only to the security team.

GitHub Actions has no trigger for security advisories, so the schedule polls every 15 minutes. Runs without a new advisory do not start the agent nor call the model.
