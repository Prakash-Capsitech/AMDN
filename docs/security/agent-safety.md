# Agent hooks and sensitive data

The agent controls in this repository protect against common accidental secret
access. They supplement OS sandboxing. They are not a guarantee against a
malicious agent, compromised host, arbitrary executable code, or tools that run
outside the sandbox. Keep production credentials out of development workspaces.

## Installed project controls

| Layer | Configuration | Purpose and boundary |
| --- | --- | --- |
| Shared pre-tool guard | scripts/agent-guards/pre_tool_use.py | Deny known sensitive paths and obvious credential-printing commands; no input/content logging |
| Codex hooks | .codex/hooks.json | Run the guard before supported local tools, after explicit hook trust |
| Codex permissions | .codex/config.toml | amdn-dev profile denies credential reads, protects guard configuration from shell writes, and disables command networking |
| Claude hooks and permissions | .claude/settings.json | PreToolUse guard, native read denies and strict shell sandbox with no unsandboxed retry |
| Publication scanning | make security | Gitleaks scans Git history; actionlint checks workflows; neither prevents a prior tool read |

The guard covers .env variants, common private-key formats, secret directories,
SSH, AWS, Kubernetes and GPG directories, GitHub and cloud credential paths, explicit
token printing and environment dumps. Normal tool requests pass through without
an allow decision, so existing permission checks still apply. It does not read
transcripts, open secret files, or echo tool input in errors. It recognizes
literal command paths and resolves symlinks for path arguments, but cannot
interpret arbitrary Python, shell expansion, encoded payloads or executable files.

Filesystem profiles intentionally block .env.example too; use a documented
non-secret file such as config.example.json for examples. The hook alone permits
.env.example for compatibility with the existing Git template hook. The more
restrictive native filesystem policy wins where active.

## Activate Codex

1. Use a current Codex version supporting permission profiles and hooks. This
   setup was exercised with codex-cli 0.167.0-alpha.4.1 on Linux.
2. Review the committed hook and script. Open `/hooks` in the CLI or
   **Settings > Hooks / Review hooks** in the desktop app and trust the exact
   AMDN hook definition. Project trust is also required. Do not use a hook-trust
   bypass flag. Changed definitions may need fresh trust.
3. Select Custom permissions with the `amdn-dev` profile and inspect the effective
   configuration in a new session. Old `sandbox_mode` settings or `--sandbox`
   arguments can override `default_permissions`. The current desktop chat can
   retain its existing managed permission profile; creating this file does not
   retroactively restrict it.
4. Keep human approval for escalation. Do not approve reading denied credentials
   or unrestricted retries merely to make a command succeed. Network-dependent
   restore/publication belongs in a separately reviewed trusted operation.
5. Test using synthetic files only. The local validation explicitly selected
   `codex sandbox -P amdn-dev -C <repo> -- <command>`; direct and symlink reads
   of a fake .env were denied and README was readable.

Codex pre-tool errors/timeouts may fail open, and hooks cover only supported tool
paths. The configured shell wrapper converts script launch failures into an
explicit denial, but cannot repair a runtime timeout. Hosted web/app tools,
MCP servers outside the process sandbox and interactive stdin continuations have
separate boundaries. Do not authorize them to fetch or transmit private data.

On Linux, deny-read globs are expanded when each sandboxed process starts, up to
the configured depth of eight. New files created during a long-lived process,
deeper paths and unlisted credential locations are not fully covered by these
globs. Prefer the explicitly denied secrets/.secrets directories, stop long-lived
processes before adding secrets, and use a clean environment without real secrets.
The environment policy reduces inherited variables; login-shell loading is off.
It does not remove credentials used by the agent harness itself.

## Activate Claude Code

The project settings load on a compatible, trusted Claude Code session. Use
Claude Code 2.1.295 or newer for the configured `onFailure: block` behavior.
Inspect `/hooks`, `/permissions` and `/sandbox` before using sensitive workspaces.
The sandbox must be available: it is configured to fail rather than silently run
without it, and unsandboxed retries are disabled. Linux needs bubblewrap and socat.

Claude Code is not installed on this setup host. JSON syntax and the shared guard
were tested; native Claude hook and sandbox integration remain unverified. Test
with fake .env files and a missing-hook failure before relying on these settings.
The sandbox domain list permits package/release retrieval, not arbitrary hosts;
a permitted destination is still a possible exfiltration route. Do not rely on
network allowlists to make readable secrets safe.

## Other agents and stronger isolation

AGENTS.md is guidance, not an access-control mechanism. Other agents do not inherit
Codex or Claude hooks automatically. Configure their supported pre-tool mechanism
and OS sandbox separately, or run them in a disposable container/VM with only a
sanitized checkout mounted. Never mount the host home directory, Docker socket,
SSH agent, cloud credentials or a privileged GitHub token into an untrusted run.

Repository settings can be changed or disabled by a writer. Strong enforcement
requires administrator-owned managed policy or an externally controlled sandbox.
Do not put owner/admin credentials into an unattended coding or review agent.
The current owner's GitHub authentication is still used for explicitly authorized
publishing; this setup has not created a separate least-privileged bot identity.
no-mistakes launches separate agent processes and worktrees: verify their effective
sandbox and hook trust too; a green pipeline does not prove hooks were active.

## Validation and sources

Run `python3 -m unittest discover -s tests/Repository -v` for fake-file/tool-payload
cases. No production secret is needed. These tests verify guard behavior, not
complete prevention of exfiltration.

Implementation contracts were checked against [Codex hooks](https://learn.chatgpt.com/docs/hooks),
[Codex permission profiles](https://learn.chatgpt.com/docs/permissions),
[Claude hooks](https://code.claude.com/docs/en/hooks), and
[Claude sandboxing](https://code.claude.com/docs/en/sandboxing).
