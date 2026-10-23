# Setup

embargod runs as a scheduled GitHub Actions workflow. Installing it takes a GitHub App, a private repository and two API keys.

## 1. Create the GitHub App

Open this address with `YOUR-ORG` replaced by your organisation name. The form is pre-filled with the only permission embargod needs, "Repository security advisories" in read and write, and no webhook.

```text
https://github.com/organizations/YOUR-ORG/settings/apps/new?name=YOUR-ORG-embargod&description=First-pass%20triage%20of%20new%20security%20advisories&url=https://github.com/alexandre-daubois/embargod&public=false&webhook_active=false&repository_advisories=write
```

After creating it:

1. Note its client ID and its slug, shown in its public page address.
2. Generate a private key.
3. Install it on the project repository only, with "Only select repositories".

Comments are posted as `<slug>[bot]`, and embargod recognises its own comments by that login.

A personal access token of a repository security manager works too, with the `repository_advisories:write` scope, in which case the comments are posted under that account and `bot-login` can be omitted.

## 2. Create a private repository

Run the workflow from a private repository, for example `your-org/embargod-runner`, rather than from the public project. Workflow logs, step inputs and run times of a public repository are public, and embargod handles embargoed reports.

In that repository, create an `embargod` environment and add:

| Kind | Name | Value |
|---|---|---|
| Variable | `EMBARGOD_CLIENT_ID` | the App client ID |
| Secret | `EMBARGOD_PRIVATE_KEY` | the App private key |
| Secret | `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | the model provider key |

Restrict the environment to the default branch so other workflows cannot read its secrets.

## 3. Add the workflow

Copy the workflow from the [README](../README.md#quick-start) and replace `your-org`, `your-project` and `your-app-slug`. Set `since` to today's date: only advisories in the `triage` state created after it are processed.

Keep `persist-credentials: false` on the checkout, so no token is written to `.git/config`, and `fetch-depth: 0`, so the agent can read the history.

## 4. First run

Trigger the workflow by hand with the `advisory` input set to one GHSA. That advisory is triaged whatever its state and date, and the comment is posted on it. Check the comment, then let the schedule run.

GitHub Actions has no trigger for security advisories, so the schedule polls every 15 minutes. Runs without a new advisory do not start the agent nor call the model.
