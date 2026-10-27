# How it works

Each run goes through four stages. Two models are involved, and no model ever sees both the report and the repository's other advisories.

## 1. Selection

tamis lists the repository's advisories and keeps those in the `triage` state created after `since`, or only the one given in `advisory`. It skips an advisory when a comment from `bot-login` contains the Tamis marker. A marker posted by another account is ignored.

A failed triage posts a comment saying so, with its own marker, and is retried on the next runs. After three failures, the comment asks a maintainer to review the report and the advisory is left alone. An advisory is triaged once: editing the report afterwards does not start a new triage.

The log names the advisory being triaged and each step as it starts: copying the source, reading the report, comparing with other advisories, posting the comment. Each step and each triaged or failed advisory also logs its duration, the model requests and the input and output tokens it spent, with cached input tokens counted as input.

## 2. Reading the report

An agent, Claude Code or Codex, investigates the report in a throwaway container:

- the report and its non-bot followup comments are in `/work/report.md`, and the selected source branch is mounted read-only in `/work/src` with its history,
- it can search public issues and pull requests through the GitHub API,
- it reads the security policy files when the repository has some,
- it writes its findings to `/work/report.json`, following a JSON schema, as soon as it has a first answer and then as it learns more. When the run stops on its budget or an error, a valid report already written is kept in the private artifact and the advisory is retried, and the last attempt posts it with a note that it may be incomplete.

The JSON is decoded strictly: an unknown or mistyped field sends the error back to the agent for one correction round. The agent reports the faulty statement (file, function, line), the public entry points it goes through, the code the report cites, related issues, policy exclusions, CWE and CVSS. The agent analyses the first configured source reference. The code the report cites is then located on each other reference, and the final report names every exact commit. A missing branch fails closed.

## 3. Duplicate search

One offline agent then searches every other advisory of the repository for the same bug, whatever their state: published, in triage, draft or closed, since a closed duplicate tells the maintainers the issue was already handled. It gets the report, the clues whose location exists in the checkout, and one file per advisory, which it greps and reads the way a maintainer would, and the code read-only for the cases the texts leave open. The report, the clues and the advisories remain hostile data. It answers with the identifiers of the duplicates it found, each with a confidence and an exact flag, and an identifier outside the advisories it was given is refused.

The full search result is preserved in the private report. Each unpublished candidate called exact with high confidence is checked again in its own model context, which receives the report, that candidate without its identifier, the checked clues and the code. It returns one `exact` boolean. Only the host knows which candidate that answer belongs to and copies a confirmed identifier into the public comment. All models share the advisory and run budgets.

## 4. Verification and comment

Before posting, tamis checks every claim against GitHub and the checkout:

| Claim | Check |
|---|---|
| Duplicates | Must be one of the advisories the search was given. Its complete result is preserved privately. An unpublished advisory appears publicly, by identifier only, after its exact, high-confidence result passes a separate one-candidate confirmation. |
| Issues and pull requests | Must exist. Titles and links come from GitHub, not from the model. |
| Cited code | Only references named in the report are kept, each marked as found in the repository or not. A cited line and the code the report quotes there are kept only when the report contains them. The quote is looked up in the file at the scanned commit, nearest the cited line, and when it is gone, `git log -S` names the commit that last changed it, since reports often target another version. |
| CWE and CVSS | Must be well-formed. CWE names come from the MITRE catalogue. |

Claims that fail a check are dropped, and the comment counts them. Just before publication, the current report and non-bot comments are read again; if they changed, no result is posted. The public comment is saved before publication. A failed duplicate search leaves the duplicates out of the comment; a failed exact confirmation leaves that unpublished candidate out. Both are marked in the private report and do not invalidate the published triage. A failure before publication leaves the advisory retriable.

## The comment

```markdown
### Automated triage

> Suggestions generated with an LLM. They help sort the report and do not replace a maintainer's review.

Scanned on 2026-10-24 at 14:32 UTC on `main` at `21a7561`.

Plausible signed `char` passed to `isxdigit()` in `php_url_decode_ex()`, the given reproducer never reaches it.

#### Possible duplicates

| Advisory | Status | Confidence |
|---|---|---|
| GHSA-xxxx-xxxx-xxxx (oldest report) | Published | High • Exact duplicate |

#### Related issues and pull requests

<details>
<summary>Show more details from the analysis</summary>

#### Code cited by the report

| Cited | In the repository on `main` at `21a7561` |
|---|---|
| `ext/standard/url.c:592` `php_url_decode_ex` | Same line, [L592](https://github.com/php/php-src/blob/21a7561/ext/standard/url.c#L592) |
| `ext/standard/url.c:480` | Moved to [L512](https://github.com/php/php-src/blob/21a7561/ext/standard/url.c#L512) |
| `main/streams.c:1200` | Quoted code changed by [`9f3c2ab`](https://github.com/php/php-src/commit/9f3c2ab) on 2026-09-01 |
| `ext/foo/bar.c` | Not found |

#### Security policy
#### Weakness and severity

</details>
```

The duplicates and related issues stay visible. The cited code, the security policy and the weakness estimate are folded so the comment scans quickly.

Every piece of model text is escaped, so the comment cannot contain links, images, HTML or mentions coming from the model. The links to cited lines are built from the repository name, the commit hash and the tracked path, and the quoted code itself is never shown.
