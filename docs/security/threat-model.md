# F0 threat model draft

Status: Initial inventory for F0.2; not a completed security review.

Assets include device private keys, message plaintext, ciphertext, routing
metadata, tenant membership, grants, inbox state, receipts, audit history and
provider credentials. Actors include legitimate users, malicious tenant members,
compromised devices, compromised workers, operators and an actively malicious
provider. E2EE protects content only under its stated endpoint/key trust model.

| Threat | Proposed control | Required evidence |
| --- | --- | --- |
| Forged tenant or postman identity | Authenticated membership plus server authorization | Negative API and forged-job tests |
| Cross-tenant DB access or pooled context leak | Transaction-local context, RLS, least privilege | Tests with actual app roles and pool reuse |
| Compromised routing worker | Narrow recipient write interface, no private keys | Privilege review and forbidden-read tests |
| Directory key substitution | Authenticated keys, visible key changes, explicit trust model | First-contact/rekey review; residual provider trust documented |
| Ciphertext/metadata tampering or replay | Reviewed E2EE binding and idempotency | Protocol-specific mutation and replay tests |
| Forged or reordered receipt | Authorized recipient device, atomic transitions | Wrong-device and late/duplicate receipt tests |
| Revocation race | Explicit cancellation boundary and worker rechecks | Queued-job and concurrent-policy tests |
| Noisy tenant or directory enumeration | Quotas, fair dispatch, bounded lookup responses | Load, throttling and enumeration tests |
| Secrets in logs or backups | Minimized telemetry, credential controls, protected backups | Log inspection and restore exercise |
| Compromised browser delivery/client code | Client distribution trust and dependency review | Document residual provider/client-code trust and mitigations |

Open decisions: device acknowledgment meaning, first-contact identity verification,
client key storage, administrative roles, OIDC provider, recovery, retention,
recipient consent/blocking and abusive account handling. Assign reviewers and
accept residual risks explicitly before F0.2 is complete.
