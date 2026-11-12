# AMDN agent guidance

AMDN is a provider-operated, multi-tenant encrypted delivery network. Read
README.md for implemented scope, docs/adr/README.md for decisions, and
Makefile for authoritative commands. CLAUDE.md imports this file.

## Invariants

- The foundation works without AI. A personal postman is an identity, not a process.
- Provider components handle ciphertext and routing metadata, never plaintext or private encryption keys.
- Derive tenant context from authenticated membership. Apply transaction-local RLS context and narrow cross-tenant routing; never use a superuser or BYPASSRLS application role.
- Accept only after durable envelope plus outbox commit. Inbox storage and device acknowledgment are different states; retries and duplicate events must be safe.
- ADRs start Proposed. Do not invent approvals, passing security reviews, performance measurements or completed F0 gates.

## Workflow

- Inspect git status and preserve unrelated work. Work on a feature branch.
- Keep instructions concise; put detailed knowledge in its owning document.
- Use make verify before submission. Add meaningful tests when behavior changes.
- Run no-mistakes with the user's full intent and drive its findings to a terminal result or review-ready PR. Follow CONTRIBUTING.md for the isolated local setup.
- While a no-mistakes run owns a branch, send fixes through its respond command; do not edit its worktree or bypass its gate.
- Never bypass hooks, forge pipeline attestations, push directly to main, or force-push shared history.
- Follow docs/security/review-and-merge.md for reviews and merges. Merge only with explicit user authorization, fresh successful checks and the reviewed head SHA; never use --admin or treat another agent on this account as an independent approver.
- Keep credentials, private keys, generated output and local tool state out of Git.
- Read docs/security/agent-safety.md before changing hooks or requesting access to a denied file. Use synthetic fixtures; never disable a guard or print credentials to diagnose it. Agent instructions and Git hooks do not replace filesystem restrictions.
- Report what was tested and what remains unimplemented. Do not add agent co-author trailers automatically.
