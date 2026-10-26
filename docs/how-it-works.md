# How it works

Each run goes through four stages. Two models are involved, and no model ever sees both the report and the repository's other advisories.

## 1. Selection

tamis lists the repository's advisories and keeps those in the `triage` state created after `since`, or only the one given in `advisory`. It skips an advisory when a comment from `bot-login` contains the Tamis marker. A marker posted by another account is ignored.

A failed triage posts a comment saying so, with its own marker, and is retried on the next runs. After three failures, the comment asks a maintainer to review the report and the advisory is left alone. An advisory is triaged once: editing the report afterwards does not start a new triage.

Each triaged or failed advisory logs the model requests and the input and output tokens it spent, with cached input tokens counted as input.

## 2. Reading the report

An agent, Claude Code or Codex, investigates the report in a throwaway container:

- the report and its non-bot followup comments are in `/work/report.md`, and the selected source branch is mounted read-only in `/work/src` with its history,
- it can search public issues and pull requests through the GitHub API,
- it reads the security policy files when the repository has some,
- it writes its findings to `/work/report.json`, following a JSON schema, as soon as it has a first answer and then as it learns more. When the run stops on its budget or an error, a valid report already written is kept in the private artifact and the advisory is retried, and the last attempt posts it with a note that it may be incomplete.

The JSON is decoded strictly: an unknown or mistyped field sends the error back to the agent for one correction round. The agent reports the faulty statement (file, function, line), the public entry points it goes through, the code the report cites, related issues, policy exclusions, CWE and CVSS. The agent analyses the first configured source reference. The code the report cites is then located on each other reference, and the final report names every exact commit. A missing branch fails closed.

## 3. Duplicate search

Potential candidates are selected without a model when their text contains the filtered location or entry points, and a shared CWE ranks them higher. Public and private candidates are selected independently, with at most ten in each group. The location must exist in the selected checkout before it can select candidates. Each candidate is checked in a separate model context with the report text, its clues and that one advisory, and up to four checks run at once. The comparator decides from the two texts when it can and reads the code only when they leave the root cause open. The report and the clues remain hostile even after syntax and existence checks. The comparator answers with confidence and an exact flag; tamis supplies the identifier itself. With a Codex access token, each check runs in an offline throwaway container. All models share the advisory and run budgets.

## 4. Verification and comment

Before posting, tamis checks every claim against GitHub and the checkout:

| Claim | Check |
|---|---|
| Duplicates | Must be a candidate checked in isolation. An unpublished advisory appears, by identifier only, when the comparator calls it an exact duplicate with high confidence. Partial matches on unpublished advisories are dropped. |
| Issues and pull requests | Must exist. Titles and links come from GitHub, not from the model. |
| Cited code | Only references named in the report are kept, each marked as found in the repository or not. A cited line and the code the report quotes there are kept only when the report contains them. The quote is looked up in the file at the scanned commit, nearest the cited line, and when it is gone, `git log -S` names the commit that last changed it, since reports often target another version. |
| CWE and CVSS | Must be well-formed. CWE names come from the MITRE catalogue. |

Claims that fail a check are dropped, and the comment counts them. Just before publication, the current report and non-bot comments are read again; if they changed, no result is posted. The public comment is saved before publication. Only then does Tamis examine private candidates and save the full report: their decisions, failures and counts cannot change the comment. A failed private comparison is marked incomplete in the artifact. A failure before publication leaves the advisory retriable; a failed private search does not invalidate its already-published public triage.

## The comment

```markdown
### Automated triage

> Suggestions generated with an LLM. They help sort the report and do not replace a maintainer's review.

Scanned on 2026-10-24 at 14:32 UTC on `main` at `21a7561`.

Plausible signed `char` passed to `isxdigit()` in `php_url_decode_ex()`, the given reproducer never reaches it.

#### Possible duplicates

| Advisory | Status | Confidence |
|---|---|---|
| GHSA-xxxx-xxxx-xxxx | Published | High • Exact duplicate |

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
