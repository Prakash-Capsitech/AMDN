# Enrollment integration

Pinned WebAuthn verification connected to committed ceremony reservations, with
[validated principals and scoped execution roles](../../docs/security/enrollment-authority.md).
`EnrollmentPrincipalMapper` consumes successful AMDN OIDC evidence;
`EnrollmentCommands` accepts only its bound principals; callers must supply a guarded
`EnrollmentDatabase` pool. Raw actor/verifier types are internal (the harness is a
friend assembly for synthetic tests). See the [verifier profile](../../docs/security/enrollment-verifier.md).

Gateway exposes six staged routes only with explicit
[EnrollmentApi configuration](../../docs/security/enrollment-http.md). Deploy roles
and migrations through 007 explicitly; never give an application owner/executor
membership. Build with `make verify`; run the actual HTTPS/signed-proof/database
cases with `make harness-test`. Browser and production enrollment, native N01/N02
and full production P01–P03 remain pending.
