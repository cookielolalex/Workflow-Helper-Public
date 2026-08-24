# ADR 0010: Provider-neutral legacy-session security composition

- Status: accepted for a hermetic, explicitly injected reference boundary
- Date: 2026-08-18
- Decision boundary: private synthetic code; default and live use blocked
- Builds on: ADR 0005, ADR 0007, ADR 0008, and ADR 0009

## Context

The verified-identity/MFA policy, browser session/CSRF policy, workload-proof
policy, and durable legacy SQLite store existed as independently tested
primitives. The legacy routes still selected independent dependencies: workload
authorization trusted provider-supplied generation, revocation, and replay
decisions, while handlers used a process-global in-memory repository. That split
could not establish one durable authority across the guard and handler.

## Decision

Introduce one `ProviderNeutralSecurityComposition`. A caller must give it exact
server-owned group-to-role and subject-to-scope policies, three request-scoped
collaborator factories, and exactly one already-constructed
`SQLiteLegacySessionStore`. It accepts no path, environment setting, provider
SDK, credential, fallback repository, or second proof store.

For browser requests, the composition obtains verified provider evidence,
enforces exact MFA evidence, maps exact server-owned groups and subject scope,
obtains the browser session context, requires principal equality, and applies
session lifetime, transport, Origin/CSRF, action, and exact-role rules. Existing
control-route dependency getters are adapters over the same composition, so no
change to application assembly is needed.

For workload requests, the composition invokes only the workload credential
verifier, validates the provider-neutral request binding, and calls
`claim_workload_proof` on its one store. Durable generation, revocation, and
proof uniqueness are authoritative; the provider's `active_generation`,
`revoked`, and `replay_decision` fields are ignored. The committed claim precedes
all scoped reads and external calls. Handlers use `composition.store`, preserving
the order claim, scoped read, external verification, atomic mutation/event
commit, then queue submission. No store transaction spans an external call.

Missing composition or collaborators and provider/store operational failures
return bounded generic 503 responses. Invalid identity, session, or proof
returns generic 401. Absence and conflict responses are generic and do not
disclose provider, credential, proof, generation, scope/owner, SQLite path, SQL,
or raw exception detail.

## Default and live-use boundary

No composition is installed by default. Import and startup create no legacy
directory, database, WAL, provider call, or network call; health remains public
and every protected route remains fail-closed. Tests construct stores only under
`tmp_path` and explicitly override the composition dependency.

This decision installs no live identity or workload provider, SDK, credential,
cookie issuance, configuration, database path, startup hook, migration,
PostgreSQL target, deployment, cloud resource, or real-data permission. The
SQLite store remains a hermetic concurrency and durability reference, not a
production database claim.

## Verification

Dynamic route inventory contains exactly 29 operations: public health, 21
control operations, three legacy browser reads, and four legacy workload posts.
Hermetic tests cover all control identity/session guards and 11 unsafe
Origin/CSRF checks; browser/workload call separation; one-store identity;
restart/reopen persistence; durable generation/revocation; concurrent one-winner
proof claims; exact replay behavior; scoped generic absence; external ordering;
and bounded provider, locked, unavailable, and corrupt SQLite failures. The
existing six constructor permutations and reopens remain the ADR 0009 evidence.

## Rollback

Before merge, close the draft pull request and retain its private branch. After
a separately governed merge, revert the exact merge commit through a private
pull request and one CI cycle. Because the default is unavailable and all test
databases are disposable synthetic files, this decision has no live provider,
credential, data, or infrastructure recovery action.
