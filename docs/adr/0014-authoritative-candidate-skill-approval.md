# ADR 0014: Authoritative candidate-skill approval projection

Status: Accepted

## Context

The version 1.0 candidate-skill contract can represent an approved candidate and
human approval evidence. That representation is deliberately exchangeable JSON;
it is not an authority boundary. A producer can populate `approval_status` and
`human_approval_evidence` without an authenticated review decision. Treating
those fields as effective state would allow a self-asserted approval to cross the
Stage E boundary.

The control plane already supplies the required authority primitives:
`AuthenticatedPrincipal`, exact tenant/workspace scope, the `review.append` and
`review.read` actions held by `ControlRole.REVIEWER`, transactional append-only
review and audit events, a durable review projection, scoped identifiers, and
SQLite restart persistence. A separate approval database, reviewer identity, or
authorization policy would split authority and is therefore rejected.

## Decision

Add an isolated domain projection in
`workflow_api.candidate_skill_approval`. It has no route, dependency wiring,
runtime default, provider, migration, or deployment effect.

### Candidate admission and digest

The projection accepts a mapping and normalizes only strict JSON values. Before
any control-service call it rejects cycles; non-string object keys; non-JSON
types; NaN and infinities; non-canonical UUIDs; schema versions other than exact
`1.0`; and structures exceeding these fixed limits:

- depth: 12;
- items per object or array: 512;
- total values: 4,096;
- key length: 256 characters;
- string length: 16,384 characters;
- integer magnitude: `10^100`;
- complete candidate and canonical approval content: 256 KiB of UTF-8 JSON.

After those defensive bounds, an embedded fail-closed validator enforces the
complete candidate-skill 1.0 and referenced artifact-ref contract semantics:
the exact closed top-level shape and every required field; all closed nested
objects; string and array ranges; unique-item requirements; enums; scalar
types, including Draft 2020-12 integral-number integer semantics; numeric
bounds; UUID, SHA-256, reviewer-ID and case-insensitive RFC 3339 `T`/`Z` formats;
supporting-example artifact evidence; and the conditional requirement for
non-null evidence when inline status is `approved`. The validator is maintained
in this module from the versioned contract design truth. Runtime approval does
not load a repository-relative schema, import an optional validator, or depend
on the current working directory. Contract-incomplete or contract-invalid JSON
therefore reaches neither authorization reads nor review mutations.

The approval envelope is exactly `approval_status` and
`human_approval_evidence`. Both fields remain bounded on input but are removed
before hashing. The remaining mapping is encoded with sorted keys, compact
separators, UTF-8, Unicode preserved, and `allow_nan=False`; its SHA-256 is the
authoritative content digest. Consequently, changing or forging the producer
envelope cannot change or create effective authority.

### Binding and idempotency

The public review target has this injective form:

`candidate-skill:1.0:<canonical-skill-uuid>:sha256:<content-sha256>`

The only accepted idempotency key is deterministic for the immutable logical
skill:

`candidate-skill-approval:1.0:<canonical-skill-uuid>`

`candidate_skill_approval_idempotency_key` exposes that value to callers. The
control service qualifies both values with the authenticated tenant/workspace
scope. This deliberately uses the existing review store's unique idempotency
constraint as the durable one-skill binding: the first approval stores a target
that includes the exact digest, while a later approval for the same schema and
skill has the same scoped idempotency key. Changed content therefore conflicts
inside the append transaction instead of replacing or inheriting approval. An
attempted caller-selected second key fails closed before mutation. The same
public IDs remain independent in different scopes because qualification occurs
inside `ControlService`.

Before append, the domain reads the exact scoped projection. An exact replay is
materialized from its one stored event and returns without calling append. This
is important because the lower-level store intentionally audits every append
request, including a store-level idempotent replay.

That read-before-append sequence is not itself a durable-store atomic primitive.
To close the concurrent replay race across independent `ControlService` and
`SQLiteControlStore` instances, the domain places a bounded advisory operating-
system lock around the read, append, projection verification and event
readback. It verifies the exact service/store types and derives the lock name
from the resolved SQLite database file's device/inode identity, so alternate
paths to the same file coordinate on the same lock. After acquiring the lock it
rechecks that identity before any control-service call. POSIX uses non-blocking
`flock`; Windows uses non-blocking
`msvcrt.locking`; both retry for at most ten seconds and fail closed on timeout
or identity uncertainty.

The mechanism uses a regular one-byte coordination file in the operating-
system temporary directory so Windows does not place a byte-range lock on live
SQLite content. Its name is a SHA-256 of the exact store identity and it may
remain for ordinary OS temporary-file cleanup; the byte has no domain or
authority meaning. This adds no authority record, data store, database schema,
migration, dependency, or alternate decision state. SQLite review and audit
rows remain the sole authority. The lock only serializes this domain critical
section so a waiting exact replay observes the accepted projection and returns
without invoking the store replay path.

### Authority evidence

One authenticated reviewer is sufficient. This decision does not reuse the
separate two-human dataset-promotion policy. `ControlService` enforces the exact
review actions and scope, and the actor passed to the store is only
`principal.subject`. Because the version 1.0 evidence contract requires a
pseudonymous `reviewer_...` identifier, a reviewer subject that cannot be used
verbatim in that contract is denied; it is never rewritten or replaced with a
caller field.

The appended review has status `approved` and deterministic provenance binding
schema version, canonical skill UUID, and canonical SHA-256. Its detail carries
a deterministic approval basis for that same binding. Effective
`human_approval_evidence` is reconstructed only after verifying the durable
projection and its single append-only event agree exactly:

- `reviewer_id` comes from the stored event actor;
- `decision_event_id` comes from the stored canonical event UUID;
- `decided_at` comes from the stored event timestamp and is rendered in UTC;
- `approval_basis` comes from the stored event detail that was appended by this
  authenticated domain operation.

Producer-supplied reviewer, event UUID, timestamp, and basis are never read for
authority. An absent projection always produces effective `unreviewed` with
null evidence, even when inline JSON claims `approved`. Ambiguous, malformed,
multi-event, mismatched, or non-version-one authority fails closed.

Public state contains only the schema version, canonical skill UUID, content
digest, unqualified public target, effective status, and contract-compatible
evidence. Internal `whscope1` qualified keys never leave the service boundary.

## Consequences

- Approval is content-addressed, scoped, append-only, auditable, and durable
  across a rebuilt `ControlService` and `SQLiteControlStore` over the same file.
- Exact replay returns the same event-derived state without another review or
  accepted audit event, including concurrent callers using separate service and
  store instances over the same SQLite file.
- Changed content for an already decided skill cannot silently inherit or
  replace its authority.
- No producer approval envelope can become authoritative by being well formed.
- The package adds no live data path, provider call, schema migration, route,
  deployment, permission, external or billable recurring resource, or cost;
  its only coordination artifact is the one-byte local OS-temporary lock file.
- Rejection is additive and reversible: remove this module, its tests, and this
  ADR. Existing control-plane records and schemas need no rollback.

## Alternatives rejected

- Trusting schema-valid inline evidence: syntax is not authenticated authority.
- A new candidate-approval table or identity type: duplicates the control-plane
  authority seam and creates cross-scope drift risk.
- Reusing dual-human dataset promotion: candidate-skill approval requires one
  reviewer and has a different decision model.
- A digest-free target: permits changed content to inherit prior approval.
- A caller-selected idempotency namespace: cannot durably enforce one immutable
  digest per schema, skill, and scope using the existing three-path boundary.
- An in-process mutex: does not coordinate separate processes or service
  instances and would leave the accepted-audit replay race open.
