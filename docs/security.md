# Security

embargod reads text written by an outside reporter, with access to embargoed advisories and an API key, and posts a comment the reporter can read. The design assumes the report is hostile.

## Threats

| Threat | Mitigation |
|---|---|
| A prompt injection makes the agent leak other advisories | The agent never has access to them. The duplicate search runs in a separate model that never sees the report and can only answer with identifiers and enums. |
| The agent leaks secrets | The container holds no secret. The model key stays on the runner, `.git/config` is masked and the GitHub token never enters the container. |
| The agent exfiltrates data over the network | The container sits on an internal network. Its only exits are the model proxy and the public GitHub API. |
| The comment loads a remote image carrying data, or pings people | All model text is escaped: no links, images, HTML, entities or mentions. |
| A reporter posts the marker to block the triage | Only comments from `bot-login` are trusted. |
| Logs of a public repository expose the report | embargod only logs counters and status codes, never report text, GHSA identifiers or provider error bodies. GitHub still prints step inputs, so run the workflow from a private repository. |

## The agent container

The agent runs through [harness](https://github.com/alpha-omega-security/harness), the isolation layer of [scrutineer](https://github.com/alpha-omega-security/scrutineer):

- a throwaway container per advisory, with a read-only root filesystem, all capabilities dropped and no new privileges,
- the repository mounted read-only, with `.git/config` hidden behind an empty file,
- an internal network whose only route out is an authenticated egress proxy allowing the model proxy and `api.github.com`,
- an image containing only the agent CLI, git, curl, ripgrep and `harness-proxy`, with every download checked against a pinned checksum.

## The model proxy

The model key never enters the container. A proxy on the runner, adapted from scrutineer, gives the agent a random token revoked when the run ends. It swaps the token for the key on a fixed list of routes (`/v1/messages` and `/v1/models` for Anthropic, `/v1/responses` and `/v1/models` for OpenAI), refuses everything else and never follows redirects.

## Known limits

- The reporter reads the comment. A crafted report can still steer the agent's own text, for example its summary or its policy check.
- A report can point the duplicate search at a line of its choice and learn whether another report describes that exact bug, much like a bug bounty platform answering "duplicate".
- The report is sent to the model provider. Check its data retention terms against your disclosure policy.
- On Docker Desktop and rootless podman, harness routes egress through a sidecar with a wider allowlist, including package registries. GitHub-hosted runners use the strict host proxy.
- The advisory comments API is in public preview and may change.

## Reporting a vulnerability

Report vulnerabilities in embargod privately through [GitHub security advisories](https://github.com/alexandre-daubois/embargod/security/advisories/new).
