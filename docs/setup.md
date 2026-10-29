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

## 5. Project board

tamis can keep a private organisation project in sync with the advisories, one draft item each, so the security team sorts them by priority. Give the App the organisation "Projects" permission in read and write, create a private project and add these fields by hand:

| Field | Type | Options, in this order |
|---|---|---|
| `GHSA` | Text | |
| `Duplicate of` | Text | |
| `Duplicates` | Number | |
| `Reported` | Date | |
| `Priority` | Single select | `Look first`, `When possible`, `Duplicate`, `Analysis failed`, `Analysis failed, retrying`, `Analysis pending` |
| `Severity` | Single select | `Critical`, `High`, `Medium`, `Low` |
| `State` | Single select | `triage`, `draft`, `published`, `closed`, `withdrawn` |
| `Policy exclusion` | Single select | `Yes`, `No` |
| `Located` | Single select | `Yes`, `No` |
| `Component` | Text | |
| `Original report` | Text | |

Then set `project` to `your-org/NUMBER`. When the project is public, or a field or an option is missing or renamed, tamis leaves the board out of the run, still triages and comments, and fails the run so the error shows.

The code sets `Priority`:

- `Look first` for a critical or high severity, a faulty statement found in the repository and no policy exclusion,
- `When possible` otherwise,
- `Duplicate` behind the oldest high-confidence exact duplicate the comment shows, which `Duplicate of` names,
- `Analysis pending` while tamis triages again an advisory it commented before the board, `Analysis failed, retrying` after a failed attempt with another to come, and `Analysis failed` once tamis gives up. The draft body then explains the status instead of holding the triage comment.

The model estimates `Severity` from its CVSS vector and ignores the one the reporter claims. `Duplicates` counts the items that name the advisory in `Duplicate of`. `Component` is the directory of the extension, SAPI or subsystem the model names, such as `sapi/fpm` for FastCGI code a report reaches through FPM, once tamis checks the repository has that directory. Without one, tamis takes the directory of the faulty statement two levels deep, and leaves it empty when the statement was not located. `Original report` holds the oldest report of a group of duplicates, on that report and on each of its duplicates, so a view grouped by it shows each original with its duplicates.

At the end of each run, tamis copies the state of every advisory to `State`, recounts `Duplicates` and ranks every triage again from `Severity`, `Policy exclusion`, `Located` and `Duplicate of`, so a new priority rule reaches the board with a release. None of it calls the model. A `Priority` changed by hand comes back at the next run, while a change to one of those four fields lasts. The REST API cannot archive items, so filter the views on `State` instead, for example a table on `State:triage,draft` sorted by `Priority` then `Reported`.

An advisory in the `triage` state that tamis commented but that has no item, for example one triaged before the board existed, is triaged again without a new comment. When that triage fails, the item gets `Analysis failed` and the advisory is not retried. Deleting an item by hand triggers that triage again on the next run.
