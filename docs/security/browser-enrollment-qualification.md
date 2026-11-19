# Local browser enrollment evidence

This is compatibility evidence for the [browser adapter](../../clients/web/README.md),
not production or physical-authenticator qualification, independent security
approval, an ADR approval or closure of any F0 gate. The maintainer has no real
test devices. Emulation cannot close those gaps.

## Reproduce locally

Use Ubuntu 24.04 x86_64, Node from `.nvmrc`, the .NET SDK from `global.json`,
Docker Engine/Compose, installed Google Chrome and Firefox with geckodriver
0.37.1 or later. Keep the existing root-owned, non-writable setuid Chromium
sandbox helper (`/opt/google/chrome/chrome-sandbox`). Setup fails rather than
disabling the sandbox or installing privileged system components.

```sh
make web-browser-restore
make web-browser-test
make web-browser-native-test
make verify
make security-tools security
```

The restore installs locked Playwright 1.65.1 development packages, its pinned
browser revisions, a SHA-256-verified Microsoft Edge package and verified Ubuntu
runtime/NSS tools under ignored `.tools/browser-matrix`. It extracts packages
locally without running package scripts. The extracted Edge helper links to the
existing trusted Chrome helper; local WebKit libraries are linked inside its
test bundle. It does not modify system browsers, certificates or user profiles.
The adapter itself remains dependency-free. Other hosts need a reviewed setup;
the installer explicitly rejects unsupported platforms.

Adapter results are written to ignored `.local/browser-evidence/adapter-matrix.json`
with the module SHA-256, versions, scope and per-configuration results. Native
results are in `native-matrix.json`, pointing to the owned harness evidence.
Failed or unavailable configurations make the command fail; they are not skipped
as successes. Each browser uses a disposable session; no existing browser is attached.
Native fixture scripts can carry synthetic tokens in protocol messages: driver
logging is suppressed, and raw protocol/proof/token data must never be published.

## Coverage and limits

The following adapter configurations passed 21 check groups each locally on
19 November 2026. HTTPS and credential responses in this matrix are intercepted
synthetic fixtures, including on browsers with a native credentials API.

| Runtime | Version | Scope |
| --- | --- | --- |
| Chrome desktop | 157.0.8103.50 | Adapter and transport behavior |
| Edge desktop | 155.0.4283.62 | Adapter and transport behavior |
| Chromium desktop | 159.0.8154.6 | Adapter and transport behavior |
| Firefox desktop | 159.0 | Adapter and transport behavior |
| Linux WebKit desktop | 27.2 | Adapter with injected credential fixture |
| Android Chromium emulation | 159.0.8154.6 | Mobile runtime emulation with synthetic credentials |
| iPhone WebKit emulation | 27.2 | Mobile runtime emulation with injected credential fixture |

These checks cover binary projection, required UV/ES256/none attestation,
closed hostile options, stage/ID/RP/expiry rejection, actual Origin/no-cookie/
no-referrer transport, definitive HTTP denials, malformed/oversized responses,
exact-byte/key retries with fresh tokens, cancellation, disposal and state copies.
The Linux headless WebKit build exposes `PublicKeyCredential` but has no native
`navigator.credentials`: the adapter rejects this environment as unsupported
before the test installs its JavaScript credential fixture. A synthetic pass
does not make that native environment supported.

The native matrix passed locally on 19 November 2026: all 253 service cases with
Chrome and three focused repetitions each in Edge, Chromium and Firefox, with
owned-resource cleanup complete. Firefox used the installed 159.0 browser and
geckodriver 0.37.1; the other versions match the table above.

The native harness uses actual HTTPS, signed disposable OIDC tokens, Gateway's
verifier and PostgreSQL execution roles. Chrome's full service suite and repeated
Edge/Chromium runs exercise native create/get with two CDP virtual authenticators:
initial enrollment, replacement candidate/current proofs, revocation, cancellation
before dispatch and exact-byte retry after a lost successful response. Durable
attempt counts and identity/device lifecycle state are asserted. Browser TLS
trust is restricted to the ephemeral certificate's SPKI and the OS sandbox stays enabled.

Firefox uses W3C WebDriver virtual authenticators and a fresh NSS profile trusting
only the fixture's public test authority and validating its localhost leaf
certificate, with `acceptInsecureCerts: false`. The
test profile explicitly selects Firefox's native soft-token manager and turns
off USB hardware routing; native proof generation and server verification remain
enabled. These settings are discarded with the profile. Its
narrower case covers native enrollment, exact proof retry, pre-aborted cancellation
with no reservation and revocation. Replacement/presence switching is pending:
the WebDriver API cannot toggle consent on an existing authenticator, and the
harness does not export/import private keys to imitate that behavior. Native
Firefox results must be read separately from its synthetic adapter results.

| Remaining target | Status |
| --- | --- |
| Firefox two-authenticator replacement and in-prompt cancellation | Pending native coverage |
| Safari on macOS | Unavailable; Linux WebKit is not Safari |
| Actual Android Chrome and iPhone/iPad Safari | Unavailable; emulation is not a physical device |
| Physical FIDO2 keys, platform/synced passkeys, biometric/PIN UI | Unavailable; virtual authenticators do not qualify them |
| Full account UI/accessibility, production TLS/OIDC/hosting | Unimplemented or unqualified |

## Compatibility repairs

Chrome/Chromium sometimes add a signed `other_keys_can_be_added_here` member;
Edge uses a different constant string. The server permits only the two exact
non-authoritative values in the [HTTP boundary](enrollment-http.md), with existing
bounds, duplicate/unknown-field checks and signature verification preserved.
Nothing strips or reserializes signed client data. Deterministic signed-proof
tests cover all four stages, tampered metadata, exact replay and no-reservation
rejection of malformed values; random browser emission is supplementary evidence.

Firefox and WebKit send `Origin: null` for `same-origin` request mode combined
with `no-referrer`. The adapter uses `cors` request mode while pinning the complete
URL to its original page origin and rejecting redirects, so browsers supply the
exact Origin without cookies or Referer. The server's strict Origin check remains
unchanged; this does not add cross-origin service support.

## When physical devices become available

Record OS, browser and authenticator model/firmware, attachment and passkey sync
state. Use a dedicated test account/tenant and trusted test deployment. Record
sanitized outcomes and durable effects, never raw proofs, tokens or private keys.

1. Complete initial enrollment with required UV; test user denial, cancellation,
   wrong RP/origin and expired step-up without unintended activation.
2. Replace using separate candidate/current credentials, including exclusion of
   the existing credential, wrong credential and missing current authenticator.
3. Revoke, then prove the old credential cannot reactivate itself. Confirm retained
   attribution, expected identity versions and `messaging_ready: false`.
4. Interrupt successful responses and explicitly retry the same bytes/key without
   another prompt; confirm one durable attempt/effect. Exercise reload and disclose
   that the adapter has no persistent retry recovery.
5. Exercise PIN/biometric failures, authenticator removal, browser prompts, passkey
   synchronization/counter behavior and accessibility. Keep unsupported outcomes
   open rather than weakening UV, origin, signature or lifecycle checks.

References: [Fetch Origin algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header),
[Playwright browser coverage](https://playwright.dev/docs/browsers),
[WebAuthn automation](https://www.w3.org/TR/webauthn-3/#sctn-automation),
[Mozilla WebDriver implementation](https://bugzilla.mozilla.org/show_bug.cgi?id=1854568).
