# Security

embargod reads text written by an outside reporter, with access to embargoed advisories and an API key, and posts a comment the reporter can read. The design assumes the report is hostile.

## Threats

| Threat | Mitigation |
|---|---|
| A prompt injection makes the agent leak other advisories | The agent never has access to them. Each duplicate candidate runs in its own model context, which sees no other advisory and returns only confidence and an exact flag. An unpublished advisory only appears when it is an exact duplicate, as its identifier and a link the reporter cannot open. |
| The agent leaks secrets | The container holds no secret. The model key stays on the runner, the container receives a clean single-branch clone with an empty `.git/config`, and the GitHub token never enters it. |
| The agent exfiltrates data over the network | The container sits on an isolated internal network and only knows a private egress sidecar. The model proxy pins the model and rejects remote URLs, remote MCP servers, hosted tools, stored conversations and background calls. |
| The comment loads a remote image carrying data, or pings people | All model text is escaped: no links, images, HTML, entities or mentions. |
| A reporter posts the marker to block the triage | Only comments from `bot-login` are trusted. |
| Logs of a public repository expose the report | embargod only logs counters and status codes, never report text, GHSA identifiers or provider error bodies. GitHub still prints step inputs, so run the workflow from a private repository. |

## The agent container

The agent runs through [harness](https://github.com/alpha-omega-security/harness), the isolation layer of [scrutineer](https://github.com/alpha-omega-security/scrutineer):

- a throwaway container per advisory, with a read-only root filesystem, all capabilities dropped and no new privileges,
- a single-branch clone copied into the read-only workspace, containing no untracked files and an empty `.git/config`,
- an internal network with no host gateway whose only peer is an authenticated egress proxy allowing the model proxy and `api.github.com`,
- the workspace mounted read-only except for `report.json`, with memory, CPU, process, file-size, output-capture and Docker-log limits,
- an image containing only the agent CLI, git, curl, ripgrep and `harness-proxy`, with every download checked against a pinned checksum,
- that image pinned by digest in each release, and checked by the action against its build attestation before use.

## The model proxy

The model key never enters the container. A proxy on the runner gives each agent a random token revoked when the run ends. It only accepts `POST /v1/messages`, `POST /v1/messages/count_tokens` or `POST /v1/responses`, pins the configured model, caps the request count and tokens, and rejects provider features that can reach another system or persisted provider data.

A Codex access token stays on the runner the same way. Codex only sends it over HTTPS, so the proxy serves a certificate from a CA generated for the process, whose key is dropped once the certificate is signed. The agent gets a fake `at-` token and the proxy only accepts the token check, the workspace configuration, which it answers as empty, and `POST /backend-api/codex/responses`. It strips the email, user and workspace identifiers from the token check's answer and adds the real workspace identifier to upstream requests itself. Codex's ChatGPT features that call other routes (plugins, apps, image generation, analytics) are turned off.

## Known limits

- The reporter reads the comment. A crafted report can still steer the agent's own text, for example its summary or its policy check.
- A report can point the duplicate search at a line of its choice and learn whether an unpublished report describes that exact bug, much like a bug bounty platform answering "duplicate". The comment then shows that advisory's identifier, not its content.
- The report is sent to the model provider. Check its data retention terms against your disclosure policy.
- Docker Engine 28 or newer is required for an internal network without a host gateway.
- The advisory comments API is in public preview and may change.

## Reporting a vulnerability

Report vulnerabilities in embargod privately through [GitHub security advisories](https://github.com/alexandre-daubois/embargod/security/advisories/new).
