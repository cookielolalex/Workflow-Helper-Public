# ADR 0002: Drive-first artifact storage and private review surface

- Status: accepted for a code-only compatibility phase; live pilot blocked
- Date: 2026-08-17
- Canonical decision: accepted architecture decision for this source snapshot

## Context

The initial scaffold used private S3 buckets and SQS because they provide strong
object identity, lifecycle rules, and queue integration. The target design may
use Google storage with a separate private review surface. A direct
folder-driven replacement would weaken concurrency, review authority,
provenance, and rollback behavior.

## Decision

Adopt Google Drive as the intended artifact system of record and a private
presentation/review layer. Keep workflow state, leases,
approval decisions, audit events, and retention records in an authenticated
persistent control plane. Introduce provider-neutral artifact references and
upload-ticket contracts while retaining S3 and LocalStack as an explicit
compatibility/rollback path during migration.

Deterministic processing is capped at three active leased jobs. Model-assisted
analysis is serialized at one job, uses fresh bounded context, and has no
automatic API-key or provider fallback. Approved-dataset promotion remains a
separately controlled human-review action.

## Implementation status

ADR 0003 now provides the synthetic persistent SQLite control-plane boundary,
including durable leases/fencing, immutable completion, append-only review
events, and append-only audit evidence. ADR 0004 now provides the fail-closed
authenticated service boundary and role checks around that store. Those newer
controls supersede the early worker-local in-memory job-ledger prototype from
the original Drive-first compatibility branch.

The current Drive-first compatibility package therefore adds only the still
missing provider-neutral artifact/upload contracts, a hermetic fake artifact
store, serialized analysis boundary, schema validation, and reconciled
architecture/privacy documentation. It does not create a second lease ledger.

No live Google Drive adapter, OAuth/scopes, Drive data-plane folder, workload
identity, review-surface deployment, live capture, real-data flow, provider cutover,
credential change, or billable resource is part of this phase.

## Consequences

- Drive folders are projections, not a queue or state machine.
- Every artifact is addressed by provider ID and revision and verified by hash
  and size.
- The canonical logical Drive layout is `00_Unprocessed/`,
  `10_Review/<job_id>/`, `20_Processed/<job_id>/`, `90_Failed/<job_id>/`, and
  `99_Approved_Datasets/<dataset_version>/`; names never define identity/state.
- Persistent leases/fencing and append-only review/audit evidence live in the
  control plane established by ADR 0003/0004.
- The review surface cannot hold storage credentials or become authoritative state.
- Existing S3 behavior remains available until parity and rollback are proven.
- A live adapter, Google identity/scopes, real-data use, deployment, capture,
  and dataset promotion remain blocked on the prerequisites in the canonical
  Drive decision.
- Provider selection and analysis billing mode must fail closed; no silent
  fallback is permitted.

## Rollback

Keep the existing S3/LocalStack behavior unchanged during this compatibility
phase. The additive provider-neutral contracts and worker primitives can be
reverted normally without changing existing stored artifacts or the persistent
control-plane schema. A later provider cutover must independently verify parity,
rollback, artifact reachability, permissions, and retention before changing any
default. No destructive bucket or Drive removal is part of this decision.
