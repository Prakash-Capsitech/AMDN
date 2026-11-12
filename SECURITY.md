# Security policy

AMDN is a foundation scaffold, not a production messaging service. Do not use it
to exchange sensitive messages. Track the current model and open gates in
[the threat model](docs/security/threat-model.md).

Report suspected vulnerabilities privately to the repository owner through an
existing trusted private channel. Do not paste credentials, plaintext messages,
private keys or exploit data into a public issue, PR, CI log or chat transcript.
No dedicated disclosure mailbox, response SLA or security-support period has
been established yet.

If a credential is exposed, revoke or rotate it first, preserve restricted
incident evidence, and inspect access logs. Deleting a file or rewriting Git
history does not invalidate a leaked credential. Agree any history rewrite with
the maintainer; do not force-push automatically.

Repository safeguards and their limitations are documented in
[review and merge controls](docs/security/review-and-merge.md).
