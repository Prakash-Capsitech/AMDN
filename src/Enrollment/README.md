# Internal enrollment verifier

Pinned WebAuthn verification connected to committed ceremony reservations.
See the [boundary and evidence guide](../../docs/security/enrollment-verifier.md).
No application host references or registers this library. The constructor's
connection factory and actor are trusted server inputs, never HTTP bindings.
No database grants or production credentials are installed by this project.

Build with `make verify`; exercise real verifier/database integration with
`make harness-test`. Synthetic key generation exists only in tests. Live enrollment,
native N01/N02 and production P01–P03 remain pending.
