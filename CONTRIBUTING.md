# Contributing to AMDN

## Build and check

Use the SDK selected by global.json, Python 3 and GNU Make. `make setup` installs
versioned hooks and restores locked dependencies. `make verify` builds, runs the
bootstrap HTTP and hook tests, verifies formatting, and checks local Markdown
file links. It does not certify F0's security or delivery gates.

Package changes must regenerate and commit packages.lock.json files with
`dotnet restore AMDN.sln --force-evaluate`; `make build` uses locked restore.

## Git and agent instructions

Agent hooks that protect sensitive tool access are separate from Git hooks.
Read [agent safety](docs/security/agent-safety.md) to activate the Codex/Claude
controls and understand their limits. They are not automatically active in this
chat or in every no-mistakes subprocess.

Work on a feature branch. Read AGENTS.md; CLAUDE.md imports the same guidance.
Run `bash scripts/install-hooks.sh` in every new clone. Git does not automatically
activate hooks from a clone. The installer refuses to replace a different hooksPath.
The pre-commit hook checks staged whitespace and obvious private/local filenames;
it is not a comprehensive secret scanner. The pre-push hook permits only the
no-mistakes remote and refuses main/master. Hooks are convenience guardrails;
see [Repository administration](#repository-administration) for the current
GitHub enforcement limitation and required maintainer configuration.

## no-mistakes setup

Use no-mistakes v1.106.1 or a reviewed newer release from the
[upstream releases](https://github.com/kunchenguid/no-mistakes/releases).
Download the binary for your OS/architecture and verify its SHA-256 against the
release checksums before running it. Do not commit binaries, credentials or daemon
state. This checkout uses .tools/no-mistakes with an isolated .local/no-mistakes
state directory; another clone can use the same layout or its installed binary.

Authenticate GitHub CLI as Prakash-Capsitech before publication. A fresh clone
needs `origin` pointing to `https://github.com/Prakash-Capsitech/AMDN.git`.
Run the following from the repository root (use your absolute binary path if different):

```sh
export NM_HOME="$PWD/.local/no-mistakes"
export NO_MISTAKES_TELEMETRY=0
export PATH="$PWD/.tools:$PATH"
no-mistakes init --skip-user-skill
no-mistakes axi
# Commit the requested change on a feature branch, then:
no-mistakes axi run --intent 'Describe the user goal, constraints and deliberate choices'
```

Use a supported authenticated coding agent (this repo selects Codex). The config
on main owns executable gate commands. Review auto-fix is disabled; read findings
and use `axi respond --action fix --findings <ids>` for appropriate fixes. While a
run is active, let the pipeline own edits. Escalate product decisions to the user.
Stop driving the run at `checks-passed`: review and merge the PR separately.
Do not manually synthesize the PR attestation or bypass an unsuccessful gate.

The remote check verifies the pipeline declaration against the PR head and requires
completed review, test and document steps. As upstream documents, this declaration
is a contributor guardrail, not a cryptographically signed security boundary.

## Repository administration

The initial main commit bootstraps the repository and trusted gate configuration.
Subsequent work goes through PRs. Configure main protection to require
`Build test and lint` and `PR must be raised via no-mistakes`, disallow force pushes
and deletion, and require conversations to be resolved. Private-repository branch
protection depends on GitHub account entitlements; verify the actual server setting
rather than claiming the workflow files alone enforce it.

Setup result on 12 November 2026: GitHub returned HTTP 403 when enabling main
protection for this private repository, requiring GitHub Pro or public visibility.
The repository remains private. CI and local hooks are configured, but required
checks and PR-only merging are not enforced by GitHub until an eligible plan is
available and a maintainer enables protection.

The owner is staying on the current plan. Follow the exact-head, explicitly
authorized [review and merge procedure](docs/security/review-and-merge.md).
It records the live Actions allowlist/SHA policy, Dependabot settings and current
enforcement gaps. Automatic merging remains disabled.

Before publication on Linux x86_64, run `make security-tools` and `make security`.
The installer verifies pinned release archive SHA-256 hashes before extraction.
Gitleaks scans Git history (not uncommitted files or every binary format), with
findings redacted. If a secret is found, rotate it before remediation; never
disable the rule just to pass CI. actionlint validates the workflow files.
Scanner upgrades change both version and reviewed checksum in a normal PR.

The setup follows kunchenguid's [shared agent guidance](https://github.com/kunchenguid/dotfiles/blob/main/home/AGENTS.md),
[CLAUDE import](https://github.com/kunchenguid/no-mistakes/blob/v1.106.1/CLAUDE.md),
and [PR enforcement action](https://github.com/kunchenguid/no-mistakes/tree/v1.106.1/.github/actions/require-no-mistakes).
AMDN's versioned local hooks are a project-specific addition.
