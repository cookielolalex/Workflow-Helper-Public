# ADR 0018: Durable session capture authority resolution

- Status: accepted for dormant synthetic integration evidence
- Date: 2026-08-19
- Decision class: R1, bounded reversible private code change
- Scope: read-only `SQLiteLegacySessionStore` authority seam only; no runtime wiring

## Context

Artifact operations require the tenant/workspace scope and pseudonymous capture owner
that registered an exact legacy session. Worker identity, lease identity, machine and
project metadata, object keys, request headers, and caller-supplied owner values are
not capture authority. Reconstructing authority from any of them would let later
processing state or untrusted request material substitute for the durable registration
provenance.

The existing legacy-session schema already stores `capture_owner_subject` alongside
the globally unique session UUID and exact tenant/workspace scope. The registration
event repeats that composite identity under a foreign key. A narrow resolver can use
this existing durable state without a schema, migration, route, provider, or runtime
change.

## Decision

Add the frozen `ResolvedSessionCaptureAuthority` value, which binds one exact `UUID`
to the existing frozen `ArtifactAuthority`, and add
`SQLiteLegacySessionStore.resolve_session_capture_authority(session_id, *, scope)`.
The method accepts only the exact UUID and an authenticated, server-derived
`TenantWorkspaceScope`.

Resolution performs exactly one `SELECT`. Its SQL predicates the session UUID,
tenant, and workspace before a row can be materialized. The same statement joins the
exact registration provenance identity, including the stored capture owner and
initial registered state. Authority is then constructed only from the selected
session row's stored tenant, workspace, and pseudonymous `capture_owner_subject`.
The record contract version, canonical UUID text, and selected scope are checked
before the value is returned.

Unknown UUIDs, cross-scope UUIDs, malformed UUID or scope contract types, malformed
persisted session/scope values, invalid stored owners (including type, length, and
normalization failures), incompatible record versions, and session/event provenance
mismatch all produce the same `SessionNotFoundError("session unavailable")`. The
error does not disclose which predicate failed or reveal the attempted identifier,
owner, tenant, or workspace. There is no inference or fallback from actor, worker,
lease, machine, project, object-key, header, or other caller-selected identity.

## Persistence and mutation boundary

The resolver is read-only. It opens one ordinary store connection, executes the sole
scoped query, materializes at most one consistent row, and closes the connection. It
does not begin a write transaction, update state, append an event, log authority,
contact a provider or network, or invoke capture. Focused tests compare SQLite
`total_changes`, statement traces, semantic dumps, and the complete main/`-wal`/`-shm`
file inventory before and after every successful, absent, malformed, and corrupt-state
resolution. They prove that the durable main and WAL bytes, logical state, and sidecar
presence do not change, including while a connection holds an active WAL. They also
prove restart persistence and frozen result semantics.

Full SHM byte identity is not a safe or accurate read-only invariant. SQLite's SHM
file is the transient WAL index, not durable database content; it contains reader-mark
and lock-coordination fields. An ordinary correctly locked `SELECT` may update bytes
100 through 119 inclusive in that reader-mark region (the reproduced offset 104 is
within it) while main/WAL bytes and all logical rows remain identical. Preventing that
update by using SQLite immutable mode could ignore uncheckpointed WAL content and
return stale authority. Reading database pages without SQLite coordination would
likewise abandon the consistent scoped query. The resolver therefore retains ordinary
SQLite locking. Tests require equal SHM length and permit differing offsets only in
the exact inclusive range 100..119; every other SHM byte remains identical. Any
main/WAL, semantic, sidecar-presence, SHM-length, or out-of-range SHM-byte change is a
failure.

Worker processing and the independent control-plane lease owner remain actors, not
capture owners. Their existing actions cannot alter or substitute the stored capture
authority. Any future route, runtime dependency, provider adapter, schema change,
owner transfer, or capture activation requires a separate governed decision.

## Consequences

- Artifact authority can be resolved from one durable source of truth without caller
  identity selection.
- Exact SQL scope filtering and generic absence preserve the existing privacy
  boundary.
- Corrupt or inconsistent provenance fails closed rather than guessing authority.
- The package remains dormant: no route, worker, control store, configuration,
  workflow, infrastructure, provider, logging, or network wiring is added.
- Reverting the two code/test additions and this ADR removes the capability without
  migrating or changing stored state.
