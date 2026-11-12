# Enrollment credential feasibility experiment

An isolated executable checks **Fido2 4.3.3** against synthetic WebAuthn
registration/assertion fixtures on .NET 10. It supports the [credential design](../../docs/security/enrollment-credential-design.md).
No application project references it. It exposes no HTTP endpoint and stores no
credentials, keys, browser state or enrollment data. The fixture creates fresh
P-256 keys and public responses in memory; output contains scenario names only.

Run `make enrollment-experiment` from the repository root, or `make verify`
for the normal build, experiment and existing checks. Locked restore uses
[packages.lock.json](packages.lock.json). An unexpected acceptance/rejection
returns nonzero. This experiment runs on CI as part of `make test`; no browser,
authenticator, OIDC provider, Docker or external metadata service is required.

## Evidence and limits

The 31 scenarios cover valid none-attestation registration followed by ES256
assertion, backup-eligible credentials, zero counters, signature mutation/wrong
signer, origin/RP/challenge/type mismatch, cross-origin requests, missing UP/UV,
duplicate registration IDs, unoffered algorithms, invalid backup flags, wrong
assertion credential/user handle, and counter regression/reset.

Two cases intentionally demonstrate **successful raw-library checks that do not
satisfy application policy**: replaying the same zero-counter assertion, and
changing backup eligibility from its registered value. The future application
must atomically consume challenges and compare stored BE. These cases are not
claims that replay or BE changes are safe. There is no application enforcement
or database simulation in this experiment.

This is real library parsing and signature verification with a synthetic
authenticator, not browser/hardware compatibility, authenticator attestation,
physical-device isolation, full FIDO conformance, a security audit or production
enrollment. Standard fixture generation is test code, not a new crypto protocol
or production verifier. Registration success alone does not demonstrate
possession: the subsequent signed assertion is the possession evidence.

On 12 November 2026, the experiment passed locally; NuGet's advisory lookup with
`dotnet list experiments/Enrollment/AMDN.EnrollmentExperiment.csproj package --vulnerable --include-transitive`
reported no known vulnerable packages from its configured source. This is dated
advisory evidence, not an audit. The upstream [4.3.3 release](https://github.com/passwordless-lib/fido2-net-lib/releases/tag/4.3.3)
includes the CBOR dependency update; do not downgrade to versions affected by
[GHSA-jc6v-cf3v-w2fm](https://github.com/passwordless-lib/fido2-net-lib/security/advisories/GHSA-jc6v-cf3v-w2fm)
or [GHSA-gw6g-q29j-3jvp](https://github.com/passwordless-lib/fido2-net-lib/security/advisories/GHSA-gw6g-q29j-3jvp).
No attestation metadata service is configured, and validation performs no network
fetches. Audits, browser trials, bounds/fuzzing and application integration remain
required before production adoption.

Fido2 is [MIT licensed](https://github.com/passwordless-lib/fido2-net-lib/blob/4.3.3/LICENSE.txt).
No upstream source or compiled dependencies are committed. NuGet metadata in the
restored packages owns dependency license information; any binary redistribution
must carry the applicable notices and receive the separate maintainer license
review. The lockfile includes transitive dependencies even where this narrow
ES256/no-metadata experiment does not exercise them.

Native N01/N02 and production P01–P03 remain pending. The MLS experiment and
deferred Dependabot #10 are unchanged.
