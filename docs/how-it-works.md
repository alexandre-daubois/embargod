# How it works

Each run goes through four stages. Two models are involved, and no model ever sees both the report and the repository's other advisories.

## 1. Selection

embargod lists the repository's advisories and keeps those in the `triage` state created after `since`, or only the one given in `advisory`. It skips an advisory that already carries a comment from `bot-login` containing the `<!-- embargod -->` marker. A marker posted by anyone else is ignored.

A failed triage posts a comment saying so, with its own marker, and is retried on the next runs. After three failures, the comment asks a maintainer to review the report and the advisory is left alone. An advisory is triaged once: editing the report afterwards does not start a new triage.

Each triaged or failed advisory logs the model requests and the input and output tokens it spent, with cached input tokens counted as input.

## 2. Reading the report

An agent, Claude Code or Codex, investigates the report in a throwaway container:

- the report is in `/work/report.md`, and the repository is mounted read-only in `/work/src` with its history,
- it can search public issues and pull requests through the GitHub API,
- it reads the security policy files when the repository has some,
- it writes its findings to `/work/report.json`, following a JSON schema.

The JSON is decoded strictly: an unknown or mistyped field sends the error back to the agent for one correction round. The agent reports the faulty statement (file, function, line), the public entry points it goes through, the code the report cites, related issues, policy exclusions, CWE and CVSS.

## 3. Duplicate search

Potential candidates are selected without a model when their text contains the filtered location, entry points or CWE, with at most ten comparisons. Each candidate is then checked in its own model context: it gets only the filtered clues and that one advisory, so no hostile report can make it read another one. It answers with a confidence level and an exact flag; embargod supplies the identifier itself. With a Codex access token, which cannot call the OpenAI API, each check runs as Codex in a throwaway container that holds the candidate and the read-only repository, and cannot reach GitHub.

## 4. Verification and comment

Before posting, embargod checks every claim against GitHub and the checkout:

| Claim | Check |
|---|---|
| Duplicates | Must be a candidate checked in isolation. Unpublished ones are only listed when they are exact duplicates, with their identifier and link, never their title. |
| Issues and pull requests | Must exist. Titles and links come from GitHub, not from the model. |
| Cited code | Only references named in the report are kept, each marked as found in the repository or not. A cited line and the code the report quotes there are kept only when the report contains them. The quote is looked up in the file at the scanned commit, nearest the cited line, and when it is gone, `git log -S` names the commit that last changed it, since reports often target another version. |
| CWE and CVSS | Must be well-formed. CWE names come from the MITRE catalogue. |

Claims that fail a check are dropped, and the comment counts them. Dropped duplicates are not counted, so the comment never hints at an unpublished advisory.

## The comment

```markdown
### Automated triage

> Suggestions generated with an LLM. They help sort the report and do not replace a maintainer's review.

Scanned on 2026-10-24 at 14:32 UTC on `main` at `21a7561`.

Plausible signed `char` passed to `isxdigit()` in `php_url_decode_ex()`, the given reproducer never reaches it.

#### Possible duplicates

| Advisory | Status | Confidence |
|---|---|---|
| GHSA-xxxx-xxxx-xxxx | Unpublished | High • Exact duplicate |

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
