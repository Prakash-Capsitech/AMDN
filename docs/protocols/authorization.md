# F0.4 authorization matrix

Status: Proposed. Source: blueprint sections 4, 9 and 11; ADR 0008; threats
T01–T04 and T10–T14. This is the proposed full contract. The
[F1.3 implementation](../security/provisioning-owner-access.md) enforces the
provisioning and owner-read subset; other operations remain unimplemented.

An allow decision requires verified identity, the required access-token scope,
an active action/resource grant and satisfied constraints. Tenant operations
require an eligible active membership; platform provisioning instead requires
the [platform authority](../security/provisioning-owner-access.md#atomic-provisioning-grants-and-audit).
Token scope alone never grants object access. Check current policy
at the operation's atomic boundary and retain the evaluated version in scoped
audit. Never log the token, raw request body, ciphertext or keys.

The [OpenAPI draft](openapi.json) uses bearer authentication and records the
required scope in `x-required-scope` and the object rule in `x-authorization`.
These extensions document enforcement requirements; OpenAPI validation does not
implement them. OIDC provider and device-bound execution credential format remain pending.

| Operation | Scope / actor | Resource rule and additional checks |
| --- | --- | --- |
| provisionTenant | tenant.provision / platform provisioner | Separate platform grant, quota and audited provisioning; ordinary tenant owners denied |
| provisionMembership | membership.provision / platform provisioner | Current platform grant that created the tenant, exact owner issuer and member quota; audited atomic enrollment |
| beginDeviceEnrollment, registerEnrollmentCredential, proveEnrollmentCandidate, authorizeDeviceReplacement | device.manage / owner | Active membership/postman, explicit object grant, fresh step-up, bound issuer/sub/client/origin and ordered candidate/current proof; see [staged contract](device-enrollment.md) |
| beginDeviceRevocation, completeDeviceRevocation | device.manage / owner | See the [staged contract](device-enrollment.md) for revocation authority, proof requirements and historical completion replay |
| resolveDirectory | directory.resolve / active member | Policy permits resolving this address; public projection only; unknown and hidden records both 404; throttle enumeration |
| submitMessage | message.send / owner device | Derive sender from active membership/device; own postman; send grant and recipient receive policy; immutable expected recipient key/device |
| getMessageStatus | message.status / sender | Only authenticated sender's envelope view; foreign and missing IDs both 404 |
| getInbox | inbox.read / recipient device | Own membership/device inbox, not an arbitrary tenant/user; cursor bound to that same view |
| acknowledgeDelivery | delivery.ack / addressed device | Active credential bound to the delivery's exact device, user and tenant; matching key lifecycle; conditional state/expiry check |
| getPostman | postman.read / owner | Own personal postman; excludes encryption secrets and another user's settings |
| updatePostmanPolicy | policy.manage / owner | Own postman; expected policy version; may only change defined Foundation preferences; cannot grant content access or autonomous replies |
| getPostmanAudit | audit.read / owner | Own postman audit projection; opaque scoped cursor; no global/operator audit feed |
| Internal dispatch | delivery.dispatch / constrained worker | Validated job provenance and sender envelope reference; current send/dispatch and recipient receive policy, identity and expiry checks |
| Internal retry | delivery.retry / constrained worker | Same checks as dispatch, bounded attempt budget and expiry; never recreate terminal delivery |
| Internal recipient write | message.receive / narrow router | Recipient's independently authorized boundary; deduplication and current identity/key/policy; no broad history read |
| Internal receipt projection | receipt.project / constrained worker | Validated recipient event, expected envelope/delivery binding and monotonic version; no client-supplied receipt authority |
| Content access / autonomous reply | message.read_content / message.reply | Denied to provider/postman in Foundation; neither is grantable through this API |

## Defaults, revocation and concurrency

At provisioning, explicitly seed owner operations and constrained system grants.
Receive, dispatch and bounded retry start enabled only through those defined
grants. Missing grants and all undeclared actions fail closed. Device ack is a
separate grant; knowledge of a delivery UUID is never sufficient.

`PATCH /v1/postman/policy` is a narrow replacement of receive/dispatch/retry
preferences, using a strong numeric ETag in If-Match. Validate all fields before
writing; unknown fields or attempts to add arbitrary capabilities fail. Atomically
advance the policy version and append audit/outbox records. Stale preconditions
fail with 412. There is no general policy-language upload in Foundation.

Before inbox commit, serialize grant changes and the authorization decision for
the affected recipient operation so a revocation ordered before the commit wins.
The sender and recipient transactions are separate: a sender revocation after
dispatch authorization may race a remote inbox commit. It prevents subsequent
eligible dispatch/retry; it cannot promise rollback of already-authorized work.
That ordering and its implementation require A03/A05 review and F0.5 race tests.

Once INBOX_STORED, revoking send/dispatch does not retract received ciphertext
or disable an otherwise-authorized device ack. Membership or device revocation
does disable ack. Device replacement cannot ack a delivery addressed to the old
device. All owner/system grants still require current active identity.

## Required negative scenarios

Test another tenant's status/inbox/audit IDs, a token scope without object grant,
forged sender/body tenant fields, a cursor copied between users or devices,
directory enumeration, revoked/expired jobs, simultaneous policy updates,
old-device acks, disabled receive before commit and injected worker contexts.
Contract fixtures exercise input shape and state rules only; real authorization
and database/broker evidence is pending F0.5/F1–F4.
