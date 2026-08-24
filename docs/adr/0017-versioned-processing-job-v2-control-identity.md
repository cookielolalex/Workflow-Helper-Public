# ADR 0017: Versioned ProcessingJobV2 control identity foundation

- Status: accepted for dormant synthetic migration evidence
- Date: 2026-08-19
- Decision class: R2, material reversible private code change
- Scope: explicit SQLite migration/validation library only; no runtime import or wiring

## Context

The existing SQLite control plane stores `payload_digest` and
`completion_result_digest` as opaque projections. It predates the independently
specified ProcessingJobV2 payload and result-manifest JCS identities. Reinterpreting
those historical strings as newer identities would invent provenance, while adding a
second job ledger would split lease, fencing, capacity, stale-worker, and completion
authority.

The migration therefore needs to preserve every existing `control_jobs` row and its
exact digest storage values while reserving byte-exact canonical identity material for
future, separately authorized writers. It also needs a rollback boundary that is safe
before new identity exists and refuses lossy downgrade afterwards.

## Decision

Add one dormant, explicitly invoked migration with three sidecar tables:

- `control_component_schema` is the single exact schema manifest and compatibility
  seal. Version 1 records the hard-bound deterministic SQL checksum, writer epoch 1,
  and minimum writer epoch 1. The minimum remains 1; this package does not reject an
  existing writer or activate a new runtime writer.
- `control_job_identity` has exactly one foreign-keyed row per authoritative
  `control_jobs` row. It reserves an exact admitted-job JCS BLOB and the payload
  scheme ID. The parent `payload_digest` remains the projection and the existing job
  row remains authoritative.
- `control_completion_identity` likewise has exactly one row per `control_jobs` row
  and reserves an exact result-manifest JCS BLOB and result scheme ID. The existing
  completion digest, idempotency key, lease, and fencing fields remain authoritative.

Every row present during migration is classified only as `legacy-opaque-v0`, with
scheme sentinel `legacy-opaque-sha256`, null canonical bytes, and writer epoch 1.
Payload and result digest values are not parsed, normalized, copied, coerced, or
inferred. This applies equally to queued, currently leased, expired leased, and
completed rows. Scoped internal job keys are copied unchanged into both sidecars, so
the existing injective tenant/workspace qualification remains isolated without the
migration attempting to decode it.

Future v1 identity rows are structurally reserved, not created here. When present,
the read-only validator requires exact scheme IDs and verifies that each parent digest
is the SHA-256 projection of the corresponding domain prefix and stored canonical JCS
bytes. Result identity additionally requires an authoritative completed job. Unknown
versions, checksums, identity classes, writer epochs, partial cardinality, or projection
drift fail closed.

The legacy control-store writer remains compatible without a runtime import: a target
schema trigger classifies every later `control_jobs` insert into both sidecars in the
same transaction. It assigns only the legacy-opaque class and epoch 1. A separately
governed future writer may transition a sidecar once from legacy to a valid v1 row.
Once v1, sidecar update/deletion and its corresponding parent digest rewrite are
blocked by exact triggers, including coordinated parent-plus-sidecar transactions.

## Migration and recovery controls

The public validator performs catalog, table, index, trigger, foreign-key, manifest,
row-cardinality, projection, `integrity_check`, and `foreign_key_check` reads without
changing the database. Migration admits only either:

1. the exact repository legacy control schema (including its explicitly recognized
   runtime-equivalent `review_events` spelling), or
2. the exact v1 target, which returns idempotently without another write.

No `IF NOT EXISTS` statement masks drift. The new SQL file contains exactly three
deterministic `CREATE TABLE` and seven `CREATE TRIGGER` statements and is SHA-256-bound
into the manifest and module constants. The validator compares the complete main
`sqlite_master` catalog, including approved SQLite autoindexes and `sqlite_sequence`,
against the exact repository schemas; only the two exact repository/runtime
`review_events` spellings are admitted. Any extra table, index, trigger, view, or other
catalog object; missing/changed index or trigger; foreign-key drift; partial sidecar;
corrupt row; or changed manifest refuses before schema writes.

For an exact legacy source, the explicit caller must supply a distinct new backup path
and a bounded size cap. The migration:

1. verifies schema and database health;
2. completes a bounded WAL checkpoint;
3. creates a SQLite online backup and verifies its size, health, exact legacy schema,
   and canonical full-catalog/full-row logical digest;
4. acquires `BEGIN IMMEDIATE`, revalidates the source, and proves its authoritative
   post-lock digest still equals the verified backup before the first migration write;
5. runs all ten DDL statements, the manifest insert, and both complete legacy
   classifications in that transaction; and
6. validates the exact target before commit and performs authoritative readback after
   commit.

Every write checkpoint has a synthetic failure-injection test proving atomic rollback.
Backup and database paths reject a symlink at the leaf or any existing ancestor. The
verified backup can restore the legacy database only while all identity rows are still
legacy opaque. Restore holds one destination `BEGIN EXCLUSIVE` lock across eligibility
revalidation and the complete overwrite. Under that lock it uses the attached,
read-only, exact backup; trusted column lists; foreign-key-safe table order; exact
sequence/application metadata; and exact legacy trigger recreation, then validates the
legacy result and digest before commit. Any fault rolls the destination back to v1.
Once any versioned canonical payload or result row exists, downgrade is refused; only
a forward repair may preserve that identity.

## Preserved invariants

This additive schema does not update `control_jobs`, `lease_events`, review state, or
audit evidence. The existing global lease cap of three, 30-minute maximum TTL,
owner/token/attempt fencing, expiry/reacquisition behavior, stale-worker rejection,
immutable/idempotent completion, append-only evidence, and scope qualification are
unchanged. Existing API, worker, and SQLite vertical regressions remain the proof for
those behaviors.

## Security and operational boundary

The package is dormant and standard-library-only. Nothing imports it from a store,
route, worker, constructor, application factory, Compose entry point, or deployment.
It creates no automatic migration, writer, provider adapter, connection, credential,
secret, queue, callback, capture path, artifact publication, or recurring resource.
All fixtures are synthetic. Added spend, real/customer/personal/raw data, provider
exposure, live capture, deployment, release, and public sharing remain zero.

Rollback before v1 identity is the verified restore operation above. Reverting the four
additive repository files removes the dormant capability without affecting an
unmigrated runtime. Any future runtime adoption, old-writer exclusion, provider-backed
write, or production database migration requires a separate governed decision and
tested operational controls.
