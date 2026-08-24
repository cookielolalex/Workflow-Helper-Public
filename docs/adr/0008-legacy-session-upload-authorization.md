# ADR 0008: Provider-neutral legacy session/upload authorization

- Status: accepted for a private, synthetic, code-only package
- Date: 2026-08-17

## Context

The original `/v1/sessions/**` and `/v1/internal/sessions/**` boundary accepted a
static bearer or worker header and bypassed both in development-like
environments. Those mechanisms could not authoritatively bind a request to a
tenant/workspace, owner, role, request body, freshness, generation, revocation,
or replay decision.

PR 35 already established provider-neutral verified identity plus a bounded
browser-session validator. The legacy session routes must preserve the existing
content-addressed AWS package verification, retry/idempotency, LocalStack, queue,
worker, UUID, object-key, and application-schema behavior.

## Decision

The application composes no legacy-session provider by default and is therefore
unavailable until a later separately governed provider composition is installed.
Legacy static bearer and worker-token headers do not authenticate in any
environment.

Browser reviewer GETs use the existing verified principal and PR 35
`validate_session_security` path. The only browser privileges are exact-scope
list, record read, and timeline read.

POSTs use a separate provider-neutral workload seam. Validated contexts contain
no raw credential and must carry an exact scoped principal, one exact role,
audience and transport, canonical method and path, raw-body SHA-256, bounded UTC
issue/expiry times, generation and active generation, revocation, and a provider
one-time/replay decision. Provider absence or failure returns bounded 503;
invalid context returns one generic rejection before repository or AWS gateway
use.

| Role | Allowed legacy operations |
| --- | --- |
| `capture_uploader` | register, create upload URL, complete upload; exact scope and capture owner |
| `reviewer` | list, read, timeline; exact scope only |
| `deterministic_worker` | processing completion; exact scope only |

The in-memory repository privately associates every record with exact
tenant/workspace scope and capture-owner subject. Cross-scope and owner-bound
capture mismatches behave as generic absence. A session UUID remains globally
unique: a duplicate cannot coexist across scopes, and duplicate errors do not
disclose another boundary. Existing object keys remain
`sessions/{uuid}/packages/{sha256}.zip`.

The package-size maximum is 512 MiB and presign-TTL maximum is 900 seconds.
Configuration can lower but cannot raise either cap.

## Consequences and non-goals

This change introduces authorization contracts and hermetic test providers only.
It does not install an identity/workload provider, issue credentials, change
capture or worker configuration, change AWS clients/contracts/schemas, call a
live presign or network service, migrate persisted data, deploy, or enable a
pilot. The complete application remains intentionally fail closed.

Reviewer reads are scope-based, not capture-owner-based. Capture mutations alone
require the stored capture owner; worker completion is scope-based. This is an
explicit least-privilege boundary, not a claim that identical UUIDs may exist in
multiple scopes.

## Rollback

Before merge, close the draft PR and retain or delete its private branch only
under a separate decision. After a separately governed merge, revert that exact
merge commit in a new private PR. No schema or data migration needs reversal.
