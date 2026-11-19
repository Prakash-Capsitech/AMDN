# Browser enrollment adapter

[enrollment.mjs](enrollment.mjs) is a dependency-free ES module for the
first-party WebAuthn management credential profile. It can be wrapped by the
future React/TypeScript application; no UI framework, login flow, token store,
production hosting or messaging client is installed by this slice.

The adapter implements the [six staged commands](../../docs/protocols/device-enrollment.md)
against the [opt-in Gateway](../../docs/security/enrollment-http.md). Import it
from a trusted, top-level HTTPS page on the **same origin** as those endpoints.
Pass the deployment's explicit RP ID and the selected canonical tenant UUID.
The server still derives authority from authenticated membership, fresh step-up
and current grants; a selector or client-side validation supplies no authority.

```js
import { EnrollmentClient } from './enrollment.mjs'

const flow = new EnrollmentClient({
  tenantId: selectedTenantId,
  rpId: configuredRpId,
  getAccessToken: async ({ signal }) => acquireFreshAccessToken({ signal })
})
await flow.beginEnrollment({ expectedIdentityVersion: currentIdentityVersion })
// Invoke each prove from an explicit user action; expose the returned stage.
await flow.prove() // registration -> candidate proof options
await flow.prove() // initial activation -> completed, messaging_ready false
flow.dispose()
```

Token acquisition, membership/version discovery and user interaction belong to
the calling application and remain unimplemented here. Never invent an identity
version or refresh step-up by merely renewing a token. `getAccessToken` is called
per HTTP attempt and must honor its AbortSignal and return a current bearer token
for the same actor/client binding. The module neither parses JWTs nor retains
tokens in its state, URLs, localStorage, sessionStorage, IndexedDB or logs.

Use a fresh flow for each ceremony. Replacement starts with
`beginEnrollment({ expectedIdentityVersion, replaceDeviceId })`, then needs
registration, candidate proof and current-credential proof in that order.
The user must retain the current credential; two authenticators may be needed
because the current credential is excluded when creating the candidate.
Revocation starts with `beginRevocation({ expectedIdentityVersion, deviceId })`
and has one proof. Lost-credential recovery or bearer-only overrides are absent.

## State, cancellation and retry

`state` returns a defensive copy containing `status`, `busy` and the last accepted
public snapshot. Status is idle, ready, uncertain, completed or disposed.
Only one action may run at a time. Pending responses must match the expected
stage, ceremony/device UUIDs, RP and the restricted profile before any prompt.
Creation/assertion options decode bounded canonical base64url; ES256, required
UV, no attestation and the selected credential list cannot be downgraded.
Browser timeout is capped by the server's challenge/ceremony deadlines.

Every method accepts an optional `{ signal }`. Cancelling browser collection
leaves the prior options available and sends no proof. Cancelling after dispatch
can leave a committed request: it is uncertain, never a claim of rollback.
The calling application should provide a request deadline and a cancel control.
`dispose()` aborts the active operation and drops snapshots and pending bytes;
late responses cannot restore state. Disposing cannot undo a server commit.

An uncertain network/503/429 outcome retains **the exact serialized request
bytes and Idempotency-Key in memory**. Call `retry()` explicitly: it gets a fresh
token and resends the same bytes/key, without another WebAuthn prompt or signature.
It does not schedule retries or ignore Retry-After. A definitive HTTP
400/401/403/404/409/413/415 clears the pending command and reports the generic
status; the caller must resolve the error before an explicit next action.
Rejected or malformed 200 responses remain uncertain. Never treat an error as
success, start a new ceremony to conceal uncertainty, or assume a completed
historical response reactivates a revoked device. Reload/closing/dispose loses
the in-memory retry material; there is no durable browser recovery store.

`EnrollmentError` exposes a fixed code/message plus optional HTTP `status` and
numeric `retryAfter`. Raw token, browser, transport and server diagnostic messages
are not propagated. The adapter omits cookies, uses no-store and no-referrer,
pins the destination URL to the page's origin, rejects redirects, and lets the
browser supply Origin. Request mode is `cors`: with `no-referrer`, Firefox and
WebKit otherwise send `Origin: null` in `same-origin` mode. This does not enable
cross-origin endpoints; the pinned URL and unchanged exact server Origin check
remain mandatory.
Do not inject request/response logging around proof or authorization headers.

The proof projection copies only raw signed bytes and profile fields. It does
not call browser `toJSON()`, parse/reserialize clientDataJSON, export private keys,
accept extension outputs or send browser-computed public keys as authority.
The server independently verifies every proof and all current authorization.

## Checks and limits

`make web-test` runs Node tests using browser/transport fixtures; it is included
in `make verify`. `make harness-test` also requires installed Chrome (or an
explicit CHROME_BIN) and runs real `navigator.credentials.create/get` with two
disposable CDP virtual authenticators, signed synthetic OIDC tokens, the actual
Gateway and PostgreSQL application roles. The test-only HTTPS proxy serves the
module and forwards requests; it is not deployed hosting. It pins only its
ephemeral certificate's SPKI in an isolated browser profile. Chrome's sandbox
stays enabled, no system certificate is installed and no authenticator key is
exported. Profile, process and owned service resources are removed at teardown.

This covers initial enrollment, both replacement credentials, revocation,
cancellation before dispatch and byte-identical retry after losing a successful
proof response, with durable version/attempt assertions. It qualifies a synthetic
Chrome path. The separate [browser qualification matrix](../../docs/security/browser-enrollment-qualification.md)
adds Edge/Chromium native cases, a narrower native Firefox case and seven adapter
runtime configurations. Run `make web-browser-restore`, `make web-browser-test`
and `make web-browser-native-test` on the documented local toolchain. Playwright
is a pinned development dependency only; the shipped adapter has no dependencies.
Real Safari, physical mobile/authenticators, synced-passkey UX, production
OIDC/TLS, client distribution and accessibility remain unqualified.

The adapter provides **no messaging key binding, peer fingerprint/verification,
delivery acknowledgment credential or messaging activation**. A completed
response must retain `messaging_ready: false`. First-contact and replacement peer
verification, independent E02/E01/E06 review, Proposed ADR approvals, native
N01/N02 and full production P01–P03 remain pending. See the
[credential design](../../docs/security/enrollment-credential-design.md).

References: [WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/),
[CDP virtual authenticators](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).
