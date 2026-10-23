# Image the reader agent runs in: one agent CLI, git, curl and harness-proxy, nothing else, since the agent
# has a shell while it reads a report that may be hostile.
#   docker build --target claude -t embargod-agent:claude docker/agent
#   docker build --target codex -t embargod-agent:codex docker/agent

# Each release tag sits beside the digest of its asset, as in scrutineer's Dockerfile.runner, so a version
# bump updates both and a mismatch fails sha256sum below.
ARG CLAUDE_AMD64_LOCK=v2.1.301@sha256:40d2cbbd74a43e9ed683c9f8f93afdadeed09d16d56095fe1e46dedaa1728082
ARG CLAUDE_ARM64_LOCK=v2.1.301@sha256:a19875467f8125449a39ebe0467e11b04be8a3130e100783043fc281ef6ed4a3
ARG CODEX_AMD64_LOCK=rust-v0.163.0@sha256:582646c6bf0561eb0de540f7fc85b9121b0091a826bc6e96830b7f1722122182
ARG CODEX_ARM64_LOCK=rust-v0.163.0@sha256:9d8ecf2d19d3e184877983902d6c85de48b3888dcb72c382a8a0c975845927fb
ARG HARNESS_VERSION=v0.1.16

FROM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS proxy
ARG HARNESS_VERSION
# The egress proxy sidecar harness starts on Docker Desktop and rootless podman.
RUN GOBIN=/out CGO_ENABLED=0 go install -trimpath github.com/alpha-omega-security/harness/cmd/harness-proxy@${HARNESS_VERSION}

FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git ripgrep libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -ms /bin/bash agent
COPY --from=proxy /out/harness-proxy /usr/local/bin/harness-proxy

FROM base AS claude
ARG TARGETARCH
ARG CLAUDE_AMD64_LOCK
ARG CLAUDE_ARM64_LOCK
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) arch=x64;   lock="${CLAUDE_AMD64_LOCK}" ;; \
      arm64) arch=arm64; lock="${CLAUDE_ARM64_LOCK}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/claude.tgz "https://github.com/anthropics/claude-code/releases/download/${lock%@*}/claude-linux-${arch}.tar.gz"; \
    echo "${lock#*@sha256:}  /tmp/claude.tgz" | sha256sum -c -; \
    tar -xzf /tmp/claude.tgz -C /usr/local/bin claude; \
    rm /tmp/claude.tgz; \
    claude --version
USER agent

FROM base AS codex
ARG TARGETARCH
ARG CODEX_AMD64_LOCK
ARG CODEX_ARM64_LOCK
# The package archive installs the CLI with its version-matched code-mode host.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) triple=x86_64-unknown-linux-musl;  lock="${CODEX_AMD64_LOCK}" ;; \
      arm64) triple=aarch64-unknown-linux-musl; lock="${CODEX_ARM64_LOCK}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/codex.tgz "https://github.com/openai/codex/releases/download/${lock%@*}/codex-package-${triple}.tar.gz"; \
    echo "${lock#*@sha256:}  /tmp/codex.tgz" | sha256sum -c -; \
    tar -xzf /tmp/codex.tgz -C /tmp bin/codex bin/codex-code-mode-host; \
    install -m 0755 /tmp/bin/codex /tmp/bin/codex-code-mode-host /usr/local/bin/; \
    rm -rf /tmp/codex.tgz /tmp/bin; \
    codex --version
USER agent
