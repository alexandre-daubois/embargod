# Security

tamis reads text written by an outside reporter, with access to embargoed advisories and an API key, and posts a comment the reporter can read. The design assumes the report is hostile.

## Threats

| Threat | Mitigation |
|---|---|
| A prompt injection makes the agent leak other advisories | The duplicate search is one offline agent that reads the report next to every other advisory, embargoed and closed ones included, so it can search them the way a maintainer would. It only returns identifiers from those advisories, each with a confidence and an exact flag, and tamis writes the comment from templates. An embargoed advisory reaches the comment only as the identifier of an exact, high-confidence duplicate, without its title or text. A hostile report or a hostile advisory can still push the search to that answer, which tells the reporter that another private report exists on the same bug, or sway its verdict on another advisory. A failed search leaves the duplicates out of the comment rather than blocking it. |
| The agent leaks secrets | The container holds no secret. The model key stays on the runner, the container receives a clean single-branch clone with an empty `.git/config`, and the GitHub token never enters it. |
| The agent exfiltrates data over the network | The container sits on an isolated internal network and only knows a private egress sidecar. The model proxy pins the model and rejects remote URLs, remote MCP servers, hosted tools, stored conversations and background calls. |
| The comment loads a remote image carrying data, or pings people | All model text is escaped: no links, images, HTML, entities or mentions. |
| A reporter posts the marker to block triage | Only comments from `bot-login` containing the marker are considered. |
| A report changes while being triaged | The title, description, metadata and non-bot comments are hashed. They are re-read before publication; a changed revision cancels the post. Completed advisories are not automatically triaged again after later edits. |
| A reporter consumes the model budget | Advisory and run budgets are shared across branches, agents and comparators. Requests, bytes, output tokens and runtime are bounded; one known reporter cannot monopolise a run. A dedicated provider spending ceiling bounds costs across runs. |
| A release tag is replaced | The action requires a full reviewed commit SHA. Agent images are additionally pinned by digest and verified against their build attestation. |
| Logs of a public repository expose the report | tamis logs the identifier of the advisory it works on, its steps, counters, status codes and the routes and JSON keys of requests the model proxy refuses, never report text, the identifiers of other advisories or provider error bodies. A hostile agent chooses the keys of the requests it sends, and GitHub prints step inputs, so the action refuses to run from a public repository. |

## The agent container

The agent runs through [harness](https://github.com/alpha-omega-security/harness), the isolation layer of [scrutineer](https://github.com/alpha-omega-security/scrutineer):

- a throwaway container per advisory, with a read-only root filesystem, all capabilities dropped and no new privileges,
- one single-branch clone of the analysed branch per execution, mounted read-only into every agent run, containing no untracked files and an empty `.git/config`, while the other branches are worktrees that only tamis reads,
- an internal bridge network with both gateway modes set to `isolated` and IPv6 explicitly disabled, whose only peer is an authenticated egress proxy allowing the model proxy and `api.github.com`,
- the workspace mounted read-only except for `report.json`, with memory, CPU, process, file-size, output-capture and Docker-log limits,
- an image containing only the agent CLI, git, curl, ripgrep and `harness-proxy`, with every download checked against a pinned checksum,
- that image pinned by digest in each release, and checked by the action against its build attestation before use, like the tamis binary of a release.

## The model proxy

The model key never enters the container. A proxy on the runner gives each agent a random token revoked when the run ends. It only accepts `POST /v1/messages`, `POST /v1/messages/count_tokens` or `POST /v1/responses`, or with a Codex access token `POST /backend-api/codex/responses` and a `GET` of the token check, the workspace configuration and the model catalogue, whose only permitted query is `client_version`. It pins the configured model and charges a shared request/byte budget. Protocol fields, input item types and tool definitions are checked against allowlists, including tools under `additional_tools`, tool search results and namespaces. Only local tools and client-side tool search pass; hosted execution, remote retrieval, persisted conversation references and unknown protocol extensions fail closed. Provider capability headers from the agent are discarded. Stateless encrypted reasoning blocks are permitted, since the CLI resends them as conversation data.

A Codex access token stays on the runner the same way. Codex only sends it over HTTPS, so the proxy serves a certificate from a CA generated for the process, whose key is dropped once the certificate is signed. The agent gets a fake `at-` token and the proxy only accepts the token check, the workspace configuration, which it answers as empty, and `POST /backend-api/codex/responses`. It strips the email, user and workspace identifiers from the token check's answer and adds the real workspace identifier to upstream requests itself. Codex's ChatGPT features that call other routes (plugins, apps, image generation, analytics) are turned off.

## Known limits

- The reporter reads the comment. A crafted report can still steer the agent's own text, for example its summary or its policy check.
- Filtered paths and identifiers are still hostile text, not a prompt-injection defence. Their code location is checked before comparison; the output's privacy boundary does not depend on the model following instructions.
- Re-reading before publication narrows the update race but GitHub offers no conditional comment creation tied to an advisory revision. Completed advisories are not automatically revisited after a later edit. Results display the digest they cover.
- Request/byte limits bound one run, not the cost of an unlimited series of runs. Enforce a provider spending ceiling and a workflow timeout as described in the setup guide.
- The report is sent to the model provider. Check its data retention terms against your disclosure policy.
- Docker Engine 28 or newer is required for an internal network without a host gateway.
- The advisory comments API is in public preview and may change.

CI builds both agent images and runs the Docker isolation tests on `ubuntu-latest`. Treat both `isolation` jobs as required checks before releasing or updating the deployment SHA. They test the model path, direct and proxied host access, DNS and IPv4/IPv6 egress without real provider credentials.

## Reporting a vulnerability

Report vulnerabilities in tamis privately through [GitHub security advisories](https://github.com/php/tamis/security/advisories/new).
