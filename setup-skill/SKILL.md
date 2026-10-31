---
name: tamis-setup
description: Install tamis, the first-pass triage of GitHub security advisories, for an open source project. Gathers what the setup needs, composes the `tamis init` command for the user to run, and walks them through installing the GitHub App and the first run. Use when someone wants to set up, install or try tamis on their project or organisation.
---

# tamis setup

You help a maintainer install tamis on their project. `tamis init` does almost everything: it registers the GitHub App, creates a private runner repository with its `tamis` environment and secrets, writes the workflow pinned to the latest release and, with `-board`, creates the project board. Your job is to gather its inputs, check the prerequisites, hand over the command and guide the two clicks it cannot do. [docs/setup.md](https://github.com/php/tamis/blob/main/docs/setup.md) is the reference when something below is not enough.

Never ask for the model provider key, never put it in a command you run or show it in the conversation. The user types it in their own terminal.

## 1. Gather the inputs

Ask only for what you cannot find yourself:

1. The project, as `org/name`. Check it with `gh repo view org/name --json visibility,defaultBranchRef`. It must be public, since GitHub only serves security advisories for public repositories, and it must belong to an organisation, since the App is created there. `tamis init` refuses a private project anyway.
2. The supported branches. Read the security policy (`SECURITY.md`, `.github/SECURITY.md`) or the release branches with `gh api repos/org/name/branches --paginate --jq '.[].name'`, then confirm them with the user. The workflow checks the project out with its full history, so every branch other than the default one is written `origin/<branch>`, the analysed one first: `-references "master origin/PHP-8.4 origin/PHP-8.3"`, or `-references main` for a project that only supports its default branch.
3. The engine: `claude` with an Anthropic API key, the default, or `openai` with an OpenAI API key or a Codex access token.
4. Comments or board. With comments, the reporter reads the triage on the advisory, since GitHub cannot post confidential comments yet. With `-board`, the triage only lands on a private organisation project the security team reads. Make sure the user knows the reporter reads the comment before they pick comments. `-board` always creates a new project. To reuse an existing tamis board, run `init` without `-board`, then replace `comment: true` with `project: org/NUMBER` in the workflow it writes.

The runner repository defaults to `org/tamis-runner` and the App to `org-tamis`. Change them with `-runner` and `-app-name` only if those names are taken or the user asks.

A name can be taken by an earlier install or attempt. `gh repo view org/tamis-runner` and `gh api apps/org-tamis` both succeed then, and `init` stops before creating anything. Ask the user whether that leftover is still in use. If it is not, the user deletes it, the App from the organisation settings under "GitHub Apps", rather than adding a second one: an App left installed on the project keeps its write access to the advisories. If it is, pick other names.

## 2. Check the prerequisites

- The user is an owner of the organisation, which creating an organisation App needs. `gh api user/memberships/orgs/ORG --jq .role` answers `admin`.
- The runner repository and the App name are free, as section 1 describes.
- The `gh` token has the `project` and `workflow` scopes. `gh auth status` lists them, `gh auth refresh -s project,workflow` adds them.
- The provider key comes from a dedicated project or account with a hard spending limit, since alerts alone do not stop charges, and the user accepts that reports are sent to that provider.
- The tamis binary of the latest release. Pick the asset from `uname -sm`, `Darwin arm64` giving `tamis-darwin-arm64`, download it and check its build attestation:

```bash
gh release download -R php/tamis --pattern 'tamis-darwin-arm64' --output tamis
gh attestation verify tamis -R php/tamis --signer-workflow php/tamis/.github/workflows/release.yml
chmod +x tamis
```

The assets are `tamis-{darwin,linux}-{amd64,arm64}` and `tamis-windows-{amd64,arm64}.exe`. `./tamis init -h` lists the flags of `init`. A release without `init` answers `REPOSITORY is required` instead, and the setup then follows docs/setup.md by hand.

## 3. Hand over the command

Write the command with the inputs filled in and ask the user to run it in their own terminal, not through you, so the key stays out of the conversation and the browser step runs on their machine:

```bash
read -rs LLM_API_KEY && export LLM_API_KEY && GH_TOKEN=$(gh auth token) ./tamis init -repository org/name -references "main origin/release-1" -board
```

`read -rs` waits for the key without echoing it. Add `-engine openai` for an OpenAI key or a Codex access token.

The command opens the browser on a GitHub page that creates the App. The user checks the organisation and the name, then clicks "Create GitHub App". The command goes on alone and prints what it created, then the installation address.

When it fails before the App is created, fix the cause and run it again. When it fails after, the App and maybe the runner repository already exist. Have the user delete them, the App from the organisation settings under "GitHub Apps", before running it again, or finish the remaining steps by hand from docs/setup.md.

## 4. Install the App

The installation address opens by itself. The user picks "Only select repositories" and selects the project only. Never "All repositories": the App can write advisories wherever it is installed.

## 5. First run

Trigger the workflow on a test advisory of the project, in any state. A project without one can get a draft from its Security tab, under "Advisories" then "New draft security advisory", which the user closes once the test is over:

```bash
gh workflow run tamis.yml -R org/tamis-runner -f advisory=GHSA-xxxx-xxxx-xxxx
gh run watch -R org/tamis-runner
```

Without a test advisory, a run without `advisory` only triages the advisories created since the setup day, usually none, which still checks the App, the secrets and the checkout. Then check the result where it lands: the comment on the advisory, or the item on the board. The private `tamis-reports` artifact of the run holds the full report, and access to it follows the permissions of the runner repository, so grant that repository to the security team only.

After that the schedule polls every 15 minutes. `.github/tamis.md` in the project tells the agent what it cannot guess, such as the scope or how the project scores CVSS, and is worth writing once the first triages are in.
