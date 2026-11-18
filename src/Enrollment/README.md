# Internal enrollment integration

Pinned WebAuthn verification connected to committed ceremony reservations, with
[validated principals and scoped execution roles](../../docs/security/enrollment-authority.md).
`EnrollmentPrincipalMapper` consumes successful AMDN OIDC evidence;
`EnrollmentCommands` accepts only its bound principals; callers must supply a guarded
`EnrollmentDatabase` pool. Raw actor/verifier types are internal (the harness is a
friend assembly for synthetic tests). See the [verifier profile](../../docs/security/enrollment-verifier.md).

No application host registers this library or exposes enrollment routes. Deploy
roles and migration 005 explicitly; never give an application owner/executor
membership. Build with `make verify`; run the signed-token/verifier/role cases with
`make harness-test`. Live enrollment, native N01/N02 and production P01–P03 remain pending.
