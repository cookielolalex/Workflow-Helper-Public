# ADR 0006: Synthetic tenant/workspace object authorization

- Status: Proposed in a private draft PR
- Date: 2026-08-17
- Decision class: R2, material reversible private authorization change

## Context

The synthetic authenticated control plane previously authorized actions by role
but stored jobs, reviews, audit evidence, retention targets, and idempotency keys
in one global identifier namespace. Identity-only scope would therefore not
prevent one authenticated workspace from addressing another workspace's
objects. A schema migration is outside this checkpoint, and the single shared
database must remain in place so the global active-lease cap remains three.

## Decision

Verified identity evidence carries one immutable exact lowercase pseudonymous
tenant/workspace scope. A server-owned policy binds each exact pseudonymous
subject to exactly one allowed scope. Evidence and policy are revalidated after
authentication; missing, malformed, unknown, case-changed, duplicate, or
ambiguous scope fails closed. HTTP bodies, paths, queries, cookies, and headers
never select scope.

`AuthenticatedPrincipal` may carry the verified scope. An unscoped principal is
still a valid value for project-wide one-way safety controls, but every
`ControlService` operation rejects an absent scope before touching a store.

Before each shared-store access, the service uses a private versioned,
length-prefixed encoder over tenant, workspace, object kind, and public
identifier. Job, review, audit, retention, dataset-derived review, copy, and
idempotency keys are qualified. Length prefixes make the encoding injective even
when a public identifier resembles an internal prefix or contains delimiters.
Every returned record is validated against the caller's exact scope and object
kind and is de-qualified before it reaches a route response.

Audit list/read and overdue-retention queries apply the exact encoded scope
prefix in SQL before numbering, pagination, or object loading. Review pages use
an exact qualified target predicate and target-local sequence numbers. Existing
unqualified synthetic rows are unreachable through `ControlService`. The
SQLite schemas and table definitions are unchanged.

## Consequences

The same public job, review, retention, dataset, and idempotency identifiers may
coexist in different scopes in one database. Cross-scope reads and mutations
produce the existing bounded generic absence, denial, or conflict responses and
do not reveal the other scope's internal keys or pagination gaps. Lease
capacity, fencing, TTL, append-only audit behavior, atomic accepted evidence,
role least privilege, MFA validation, default authentication/service 503, and
one-way safety switches remain unchanged.

This is synthetic source-level evidence only. It adds no migration, deployment,
provider integration, credential, network call, real identity, real data,
Drive/Site connection, or billable resource. Any discovered durable
non-synthetic database requires a separate migration and recovery decision.

## Rollback

Before merge, close the draft PR and retain or discard its branch. After a
future separately approved merge, revert that exact merge commit. No database
rollback or destructive data operation is part of this decision because no
schema or live database is changed.
