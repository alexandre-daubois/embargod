# Security

tamis reads text from an outside reporter, holds access to embargoed advisories and an API key, and posts a comment the reporter can read. The design assumes a hostile report.

## Threats

| Threat | Mitigation |
|---|---|
| A prompt injection makes the agent leak other advisories | See [Duplicate search isolation](#duplicate-search-isolation). |
| The agent leaks secrets | The container holds no secret. The model key stays on the runner, the GitHub token never enters the container, and the container gets a clean single-branch clone with an empty `.git/config`. |
| The agent exfiltrates data over the network | The container sits on an isolated internal network and only reaches a private egress sidecar. The model proxy pins the model and rejects remote URLs, remote MCP servers, hosted tools, stored conversations and background calls. |
| The comment loads a remote image carrying data, or pings people | tamis escapes all model text: no links, images, HTML, entities or mentions. |
| A reporter posts the marker to block triage | tamis only considers markers in comments from `bot-login`. |
| A report changes during triage | tamis hashes the title, description, metadata and non-bot comments, reads them again before publication and cancels the post when the revision changed. It does not triage a completed advisory again after a later edit. |
| A reporter drains the model budget | Branches, agents and comparators share the advisory and run budgets. tamis bounds requests, bytes, output tokens and runtime, and one known reporter cannot take a whole run. A provider spending ceiling bounds costs across runs. |
| Someone replaces a release tag | The action requires a full reviewed commit SHA. tamis also pins agent images by digest and verifies them against their build attestation. |
| Logs of a public repository expose the report | The action refuses to run from a public repository. See [Logs](#logs). |

## Duplicate search isolation

The duplicate search is one offline agent that reads the report next to every other advisory, embargoed and closed ones included, so it can search them the way a maintainer would. The private report keeps its complete result, and the comment shows published matches to the reporter.

A separate model context confirms each unpublished exact, high-confidence candidate, and holds that candidate only. The host owns the candidate's identifier and publishes it only when this second model returns `exact: true`. A failed search or confirmation keeps unconfirmed unpublished identifiers out of the comment.

A hostile report can still push the confirmations to disclose candidate identifiers. An instruction hidden in one candidate only reaches that candidate's confirmation.

## Logs

tamis logs the identifier of the advisory it works on, its steps, counters and status codes. For requests the model proxy refuses, it logs the routes, the JSON keys and the `type`, `role` and `execution` values.

tamis itself never logs report text, the identifiers of other advisories or provider error bodies. A hostile agent still chooses the routes, keys and values of its requests, so it can write the report into the log, or with a Codex access token the advisories it searches. GitHub also prints step inputs, which is why the action refuses a public repository.

## The agent container

The agent runs through [harness](https://github.com/alpha-omega-security/harness), the isolation layer of [scrutineer](https://github.com/alpha-omega-security/scrutineer):

- a throwaway container per advisory, with a read-only root filesystem, all capabilities dropped and no new privileges,
- one single-branch clone of the analysed branch per execution, mounted read-only into each agent run, with no untracked files and an empty `.git/config`, while only tamis reads the other branches, checked out as worktrees,
- an internal bridge network with both gateway modes set to `isolated` and IPv6 disabled, whose only peer is an authenticated egress proxy that allows the model proxy and `api.github.com`,
- a read-only workspace except for `report.json`, with memory, CPU, process and file-size limits,
- an image with only the agent CLI, git, curl, ripgrep and `harness-proxy`, each download checked against a pinned checksum,
- that image pinned by digest in each release, and checked by the action against its build attestation before use, like the tamis binary of a release.

## The model proxy

The model key never enters the container. A proxy on the runner gives each agent a random token and revokes it when the run ends.

The proxy accepts only these routes:

- `POST /v1/messages`, `POST /v1/messages/count_tokens` and `POST /v1/responses`,
- with a Codex access token, `POST /backend-api/codex/responses` and a `GET` of the token check, the workspace configuration and the model catalogue, with `client_version` as the only permitted query.

It pins the configured model and charges a shared request and byte budget. It checks protocol fields, input item types and tool definitions against allowlists, tools under `additional_tools`, tool search results and namespaces included. Only local tools and client-side tool search pass. Hosted execution, remote retrieval, persisted conversation references and unknown protocol extensions fail closed. The proxy discards provider capability headers from the agent. It lets stateless encrypted reasoning blocks through, since the CLI resends them as conversation data.

A Codex access token stays on the runner the same way. Codex only sends it over HTTPS, so the proxy serves a certificate from a CA generated for the process and drops the CA key once it signs the certificate. The agent gets a fake `at-` token. The proxy:

- accepts only the token check, the workspace configuration, which it answers as empty, and `POST /backend-api/codex/responses`,
- strips the email, user and workspace identifiers from the token check's answer,
- adds the real workspace identifier to upstream requests itself.

tamis turns off the Codex ChatGPT features that call other routes: plugins, apps, image generation and analytics.

## Known limits

- The reporter reads the comment. A crafted report can still steer the agent's own text, such as its summary or its policy check.
- Filtered paths and identifiers remain hostile text and offer no prompt-injection defence. tamis checks their code location before comparison, and the privacy boundary of the output does not rely on the model following instructions.
- Reading the report again before publication narrows the update race, but GitHub offers no conditional comment creation tied to an advisory revision. tamis does not revisit a completed advisory after a later edit. Each result shows the digest it covers.
- Request and byte limits bound one run, not the cost of an endless series of runs. Enforce a provider spending ceiling and a workflow timeout as the [setup guide](setup.md#2-create-a-private-repository) describes.
- tamis sends the report to the model provider. Check its data retention terms against your disclosure policy.
- An internal network without a host gateway needs Docker Engine 28 or newer.
- The agent CLI state is a writable host directory, removed after each advisory. A run can rewrite its own configuration for the correction round and fill the runner disk, though not leave the network or the model proxy.
- The advisory comments API is in public preview and may change.

CI builds both agent images and runs the Docker isolation tests on `ubuntu-latest`. They test the model path, direct and proxied host access, DNS, and IPv4 and IPv6 egress, without real provider credentials. Treat both `isolation` jobs as required checks before releasing or updating the deployment SHA.

## Reporting a vulnerability

Report vulnerabilities in tamis privately through [GitHub security advisories](https://github.com/php/tamis/security/advisories/new).
