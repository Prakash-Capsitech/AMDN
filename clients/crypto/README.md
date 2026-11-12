# F0 encryption experiment

Disposable MLS 1.0 feasibility code; **synthetic messages only**. No production
library or protocol is approved. Read the
[assessment and evidence](../../docs/security/encryption-feasibility.md).

Use the Node version selected by the repository .nvmrc (for example, nvm install then nvm use).
From the repository root:

```sh
make crypto-restore  # locked npm install, dependency scripts disabled
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
