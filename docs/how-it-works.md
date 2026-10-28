# How it works

Each run goes through four stages. Two models take part, and no model sees both the report and the repository's other advisories.

## 1. Selection

tamis lists the repository's advisories and keeps those in the `triage` state created after `since`, or only the one given in `advisory`. It skips an advisory when a comment from `bot-login` holds the tamis marker, and ignores a marker posted by any other account.

A failed triage posts a comment that says so, with its own marker, and tamis retries it on the next runs. After three failures, the comment asks a maintainer to review the report and tamis stops retrying. tamis triages an advisory once, so an edit to the report afterwards starts no new triage.

The log names the advisory and each step as it starts: copying the source, reading the report, comparing with other advisories and posting the comment. Each step, and each triaged or failed advisory, also logs its duration, its model requests and its input and output tokens. Cached input tokens count as input.

## 2. Reading the report

An agent, Claude Code or Codex, investigates the report in a throwaway container:

- `/work/report.md` holds the report and its non-bot followup comments,
- `/work/src` holds the selected source branch, read-only and with its history,
- the agent can search public issues and pull requests through the GitHub API,
- it reads the security policy files when the repository has some,
- it writes its findings to `/work/report.json` against a JSON schema, first as soon as it has an answer, then as it learns more.

The agent reports the faulty statement (file, function, line), the public entry points that reach it, the code the report cites, related issues, policy exclusions, the CWE and the CVSS.

tamis rejects an unknown or mistyped field in the JSON and sends the error back to the agent for one correction round.

When the run stops on its budget or on an error, tamis keeps a valid report already written in the private artifact and retries the advisory. The last attempt posts that report with a note that it may be incomplete.

The agent analyses the first configured reference. tamis then locates the cited code on each other reference, and the final report names every exact commit. A missing branch fails the triage.

## 3. Duplicate search

One offline agent searches every other advisory of the repository for the same bug, whatever its state: published, in triage, draft or closed. A closed duplicate tells the maintainers someone already handled the issue. The agent gets:

- the report,
- the clues whose location exists in the checkout,
- one file per advisory, which it greps and reads the way a maintainer would,
- the code, read-only, for the cases the texts leave open.

tamis treats the report, the clues and the advisories as hostile data. The agent answers with the identifiers of the duplicates it found, each with a confidence and an exact flag. tamis refuses an identifier outside the advisories it gave.

The private report keeps the full search result. tamis checks each unpublished candidate marked exact with high confidence again, in its own model context. That context receives the report, the candidate without its identifier, the checked clues and the code, and returns one `exact` boolean. Only the host knows which candidate the answer belongs to, and it copies a confirmed identifier into the public comment. All models share the advisory and run budgets. The log records the duration and usage of the confirmations and the number of confirmed candidates.

Both stages compare concrete defects, secondary findings of a report included:

- a different PoC, version, configuration or severity estimate leaves the same defective operation the same bug,
- an exact match needs positive evidence of a shared defect, and a similar symptom or a broad patch fixing several independent defects does not qualify,
- an exact match does not settle the other findings of either report, which maintainers still review before closing it.

Matching stays separate from validity. An issue already fixed, or rejected under the security policy, can still be a duplicate. A finding the report explicitly removes, excludes or moves to another advisory no longer counts as one of its findings.

## 4. Verification and comment

Before posting, tamis checks each claim against GitHub and the checkout:

| Claim | Check |
|---|---|
| Duplicates | Each one must belong to the advisories the search received. The private report keeps the complete result. An unpublished advisory appears in the comment, by identifier only, once its exact, high-confidence result passes the one-candidate confirmation. |
| Issues and pull requests | Each one must exist. Titles and links come from GitHub, not from the model. |
| Cited code | tamis keeps only references named in the report, each marked as found in the repository or not, and keeps a cited line and its quoted code only when the report contains them. It looks the quote up in the file at the scanned commit, nearest the cited line. When the quote is gone, `git log -S` names the commit that last changed it, since reports often target another version. |
| CWE and CVSS | Each must be well-formed. CWE names come from the MITRE catalogue. |

tamis drops the claims that fail a check, and the comment counts them.

Just before publication, tamis reads the report and its non-bot comments again and posts nothing if they changed. It saves the public comment before posting it. A failed duplicate search leaves the duplicates out of the comment, and a failed exact confirmation leaves that unpublished candidate out. The private report records both failures, and the triage still gets published. A failure before publication leaves the advisory retriable.

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

The duplicates and related issues stay visible. The cited code, the security policy and the weakness estimate sit in a folded block so the comment reads fast.

tamis escapes all model text, so the comment cannot carry links, images, HTML or mentions coming from the model. It builds the links to cited lines from the repository name, the commit hash and the tracked path, and never shows the quoted code.
