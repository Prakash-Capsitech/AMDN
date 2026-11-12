# F0 encryption experiment

Disposable MLS 1.0 feasibility code; **synthetic messages only**. No production
library or protocol is approved. Read the
[assessment and evidence](../../docs/security/encryption-feasibility.md).

Use the Node version selected by the repository .nvmrc (for example, nvm install then nvm use).
From the repository root:

```sh
make crypto-restore  # locked install without scripts, then dependency-tree validation
make crypto-test     # behavioral/negative scenarios
make crypto-spike    # safe status-only offline exchange
make crypto-browser  # Chrome required; CHROME_BIN may specify its executable
```

For manual browser inspection, serve this directory only:

```sh
python3 -m http.server 5081 --bind 127.0.0.1 --directory clients/crypto
```

Open http://127.0.0.1:5081/browser-smoke.html and stop the server afterward.
No React app, provider endpoint, production key storage or deployment is included.
The page runs the same module as Node with local import maps and no CDN code.
All clients and relay are in one page/process.

Tests intentionally prove stale-state rollback permits replay. Never export
checkpoints or private keys to the relay, files, logs, snapshots or PR evidence.
The harness holds synthetic private state in memory to exercise serialization.
Do not bypass a browser/agent sandbox to make a probe run.

Dependency licenses are retained in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Dependabot PR #10's curves 2.4.0 / hashes 2.4.0 update is deferred: pinned
ts-mls 1.6.4 declares an optional peer dependency on exactly
`@noble/curves` 2.0.1. The experiment retains curves 2.0.1 and its transitive
hashes 2.0.1 dependency. `make crypto-restore` runs `npm ls --all` after
installation so an invalid installed peer relationship fails the restore target.
No peer overrides or compatibility relaxations are applied. PR #10 remains open;
this replacement supersedes only setup-node PR #9. Execution of the pinned
setup-node action still requires hosted CI. Production crypto approval and
native agent checks N01/N02 remain pending.
