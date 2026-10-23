# How it works

Each run goes through four stages. Two models are involved, and no model ever sees both the report and the repository's other advisories.

## 1. Selection

embargod lists the repository's advisories and keeps those in the `triage` state created after `since`, or only the one given in `advisory`. It skips an advisory that already carries a comment from `bot-login` containing the `<!-- embargod -->` marker. A marker posted by anyone else is ignored.

## 2. Reading the report

An agent, Claude Code or Codex, investigates the report in a throwaway container:

- the report is in `/work/report.md`, and the repository is mounted read-only in `/work/src` with its history,
- it can search public issues and pull requests through the GitHub API,
- it reads the security policy files when the repository has some,
- it writes its findings to `/work/report.json`, following a JSON schema.

The JSON is decoded strictly: an unknown or mistyped field sends the error back to the agent for one correction round. The agent reports the faulty statement (file, function, line), the PHP entry points it goes through, the code the report cites, related issues, policy exclusions, CWE and CVSS.

## 3. Duplicate search

A second model compares the report with the other advisories without ever reading it. It only gets the faulty statement, the entry points and the CWE, each filtered against strict patterns (paths, identifiers, numbers). It reads the other advisories and the code, and answers with GHSA identifiers, a confidence level and an exact flag, nothing else.

## 4. Verification and comment

Before posting, embargod checks every claim against GitHub and the checkout:

| Claim | Check |
|---|---|
| Duplicates | Must be an existing advisory. Unpublished ones are only kept when they are exact duplicates with high confidence. |
| Issues and pull requests | Must exist. Titles and links come from GitHub, not from the model. |
| Cited code | Only references named in the report are kept, each marked as found in the repository or not. |
| CWE and CVSS | Must be well-formed. CWE names come from the MITRE catalogue. |

Claims that fail a check are dropped, and the comment counts them. Dropped duplicates are not counted, so the comment never hints at an unpublished advisory.

## The comment

```markdown
### Automated triage

> Suggestions generated with an LLM. They help sort the report and do not replace a maintainer's review.

Plausible signed `char` passed to `isxdigit()` in `php_url_decode_ex()`, the given reproducer never reaches it.

#### Possible duplicates

| Advisory | Status | Confidence |
|---|---|---|
| GHSA-xxxx-xxxx-xxxx | Unpublished | High • Exact duplicate |

#### Related issues and pull requests
#### Code cited by the report
#### Security policy
#### Weakness and severity
```

Every piece of model text is escaped, so the comment cannot contain links, images, HTML or mentions coming from the model.
