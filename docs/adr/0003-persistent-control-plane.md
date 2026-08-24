# ADR 0003: Persistent local control-plane skeleton

- Status: accepted for code-only synthetic development
- Date: 2026-08-17
- Scope: API persistence library only; not wired to routes, cloud storage, or live workers

## Context

The Drive-first architecture needs durable coordination before any live adapter,
OAuth credential, or real recording can be introduced. The existing in-memory
repositories cannot survive a process restart and cannot fence two workers that
race for one job. Review state also needs immutable evidence rather than a
mutable status field alone.

## Decision

Add a standard-library SQLite control store with a filesystem database. SQLite
runs in WAL mode with full synchronous writes. Every mutation opens its own
connection and uses `BEGIN IMMEDIATE`, so the capacity check and corresponding
state transition share one serialized transaction across threads and processes.

### Worker leases

- At most three unexpired active leases may exist. This is a hard application
  bound, not a target for automatic scaling.
- A lease lasts at most 30 minutes and carries owner ID, attempt, and a monotonic
  fencing token.
- An expired job may be reacquired. Reacquisition increments both attempt and
  fencing token, making every earlier worker stale.
- Heartbeat and first completion require the exact current owner, token, and
  attempt and require an unexpired lease.
- Completion is immutable and idempotent only for the lease that completed it.
  The same worker may replay the exact idempotency key and result digest after a
  lost response. A stale worker cannot obtain success by replaying the winner's
  values.
- Lease lifecycle evidence is append-only and protected from update or deletion
  by database triggers.

### Reviews

- Review events are append-only and database triggers reject update or deletion.
- Each event records a pseudonymous actor, decision status, detail, and exact
  provenance: source, artifact ID, source revision, and lowercase SHA-256.
- Review idempotency keys are globally unique. Replaying the same semantic event
  returns the stored event; reusing the key for changed content or another target
  is a conflict.
- A current projection is updated in the same transaction. It is a rebuildable
  query cache; the immutable event sequence remains authoritative.

## Security and operational boundary

This package accepts synthetic fixtures only. It adds no endpoint, identity
provider, OAuth flow, secret, cloud SDK, upload watcher, scheduled process,
deployment, or live-data path. A future service layer must authenticate actors,
authorize job and review actions, isolate tenants, protect the database file,
back it up, expose audit monitoring, and test projection rebuild before a real
pilot. Artifact bytes remain outside this database.

SQLite is intentionally a single-host control store. It is not a shared-drive
database and must not be placed inside a synchronizing Google Drive folder.
Multi-host operation requires a separately reviewed transactional database
adapter that preserves these idempotency and fencing semantics.

## Consequences

Restart, race, expiry, stale-worker, idempotency, conflict, provenance, and
immutability behavior can be tested without new dependencies or billable
infrastructure. The API remains unchanged until authentication and authorization
controls are designed and independently reviewed.

Rollback is removal of the four additive files on the feature branch. No
existing schema, route, cloud state, or real artifact is changed.
