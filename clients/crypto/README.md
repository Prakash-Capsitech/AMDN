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

## PR #10 compatibility evaluation

Dependabot PR #10's curves 2.4.0 / hashes 2.4.0 update was separately evaluated
and closed without merging on 18 November 2026. Pinned ts-mls 1.6.4 declares an
optional peer dependency on exactly `@noble/curves` 2.0.1. An isolated fixture
containing the proposed update passed `npm ci --ignore-scripts`, but
`npm ls --all` exited 1 with `ELSPROBLEMS`, flagging curves 2.4.0 as invalid
against ts-mls's 2.0.1 requirement. `make crypto-restore` includes that
dependency-tree check, so the update is incompatible as submitted.

The experiment retains curves 2.0.1 and its transitive hashes 2.0.1 dependency.
No peer overrides or compatibility relaxations are applied. A coordinated
MLS/dependency upgrade remains separate future work. The original Dependabot
branch is retained at `44d0c689d86296c090bc94e05ae90dd2baa8e6a2`; it was restored
at that exact SHA after Dependabot automatically deleted it on closure.

The earlier setup-node replacement superseded only PR #9. Execution of the pinned
setup-node action still requires hosted CI. Production crypto approval and
native agent checks N01/N02 remain pending.
