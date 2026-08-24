# ADR 0009: Durable legacy session and workload-security state

- Status: accepted; hermetic SQLite reference implemented, live use blocked
- Date: 2026-08-17
- Decision boundary: private, synthetic, implemented reference; default unwired
- Supersedes: no prior schema; refines the durability limits recorded by ADR 0008

## Context

ADR 0008 makes the legacy session surface fail closed and binds accepted requests
to an exact principal, tenant/workspace scope, role, audience, transport, method,
canonical path, raw-body digest, bounded timestamps, workload generation,
revocation, and replay decision. Before the implemented-but-unwired composition
recorded by ADR 0010, the legacy repository stored session records,
tenant/workspace ownership, and capture-owner identity in one process-local
dictionary, while the workload provider supplied the active generation,
revocation, and replay decision. The implemented reference instead injects one
durable SQLite store through one composition; that store is authoritative for
those session and workload-security fields. No default provider or database path
is installed.

Those historical in-memory authorities were insufficient. A process restart
lost session ownership and state. Two API processes could accept conflicting
updates because their locks and dictionaries were independent. A
provider-supplied replay answer cannot make a one-time proof globally one-time
unless every concurrent process claims the same durable key. Provider-supplied
generation and revocation values also cannot be authoritative if a stale process
can validate them without consulting one serialized state transition.

The additive component-local design is implemented by
`legacy_session_schema.py` and `legacy_session_store.py` and verified with only
disposable synthetic databases. ADR 0010 composes that store into the legacy
route boundary without installing a default database path or live provider.
The PostgreSQL and live-use gates in this record remain unmet.

## Decision

The implemented route composition replaces the legacy in-memory repository only
when explicitly injected with a store implementing this exact v1 contract.
SQLite is the hermetic reference
implementation. PostgreSQL is the required separately verified live target.
Existing globally unique session UUIDs, object keys, request authorization,
S3/LocalStack verification, queue behavior, completion idempotency, and
Drive-first artifact boundaries remain unchanged.

All timestamps below are signed 64-bit UTC microseconds since the Unix epoch.
UUIDs are canonical lowercase hyphenated text. JSON is UTF-8, sorted-key,
separator-free canonical JSON. Digests are lowercase 64-character SHA-256 hex.
All identifiers and scope values are nonempty after the existing contract
validation. Database foreign-key enforcement is mandatory.

### Component schema identity

The component ID is `workflow-helper.legacy-session-security`, schema version is
integer `1`, and record contract version is text `1.0`.

The exact v1 manifest string is:

```text
legacy-session-security/v1|legacy_session_component_schema:component_id,schema_version,schema_checksum,installed_at_us|legacy_sessions:session_id,tenant_id,workspace_id,capture_owner_subject,record_contract_version,machine_id,project_id,started_at_us,ended_at_us,active_duration_seconds,approved_process,package_sha256,package_size_bytes,processing_status,review_status,raw_object_key,processed_prefix,processing_output_json,processing_completion_id,processing_completed_at_us,raw_expires_at_us,state_version,created_at_us,updated_at_us|legacy_session_events:sequence,event_id,session_id,tenant_id,workspace_id,capture_owner_subject,event_type,from_state,to_state,state_version,actor_subject,actor_role,idempotency_key,request_digest,detail_json,occurred_at_us|legacy_workload_principals:principal_subject,tenant_id,workspace_id,audience,role,transport,active_generation,revoked_at_us,state_version,created_at_us,updated_at_us|legacy_workload_proof_claims:proof_identifier_digest,principal_subject,tenant_id,workspace_id,audience,role,transport,generation,method,canonical_path,body_sha256,issued_at_us,expires_at_us,claimed_at_us,retain_until_us
```

Its SHA-256 is
`d660e0586b3672d530cb751972ef88deead9f74863094a8b1b5882c87f591550`.
An implementation must also compare the normalized table, index, trigger, and
foreign-key definitions below; the manifest row alone is not evidence that a
file is compatible. `PRAGMA user_version` is shared global state and must not
be read or written for this component.

### Normative additive SQLite v1 schema

The following names and shapes are reserved to this component. Enum-like values
are validated by the versioned application contract rather than by widening
another component's `CHECK` clauses.

```sql
create table legacy_session_component_schema (
    component_id text primary key,
    schema_version integer not null,
    schema_checksum text not null,
    installed_at_us integer not null
);

create table legacy_sessions (
    session_id text primary key,
    tenant_id text not null,
    workspace_id text not null,
    capture_owner_subject text not null,
    record_contract_version text not null,
    machine_id text not null,
    project_id text,
    started_at_us integer not null,
    ended_at_us integer not null,
    active_duration_seconds integer not null,
    approved_process text not null,
    package_sha256 text not null,
    package_size_bytes integer not null,
    processing_status text not null,
    review_status text not null,
    raw_object_key text unique,
    processed_prefix text,
    processing_output_json text,
    processing_completion_id text unique,
    processing_completed_at_us integer,
    raw_expires_at_us integer not null,
    state_version integer not null,
    created_at_us integer not null,
    updated_at_us integer not null,
    unique (session_id, tenant_id, workspace_id, capture_owner_subject)
);

create index legacy_sessions_scope_started_idx
    on legacy_sessions (tenant_id, workspace_id, started_at_us desc, session_id);
create index legacy_sessions_owner_idx
    on legacy_sessions (
        tenant_id, workspace_id, capture_owner_subject, session_id
    );
create index legacy_sessions_scope_processing_idx
    on legacy_sessions (
        tenant_id, workspace_id, processing_status, updated_at_us, session_id
    );
create index legacy_sessions_raw_expiry_idx
    on legacy_sessions (raw_expires_at_us, session_id);

create table legacy_session_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    session_id text not null,
    tenant_id text not null,
    workspace_id text not null,
    capture_owner_subject text not null,
    event_type text not null,
    from_state text,
    to_state text not null,
    state_version integer not null,
    actor_subject text not null,
    actor_role text not null,
    idempotency_key text,
    request_digest text not null,
    detail_json text not null,
    occurred_at_us integer not null,
    foreign key (
        session_id, tenant_id, workspace_id, capture_owner_subject
    ) references legacy_sessions (
        session_id, tenant_id, workspace_id, capture_owner_subject
    ) on delete restrict,
    unique (session_id, state_version)
);

create unique index legacy_session_events_idempotency_idx
    on legacy_session_events (session_id, event_type, idempotency_key)
    where idempotency_key is not null;
create index legacy_session_events_scope_sequence_idx
    on legacy_session_events (
        tenant_id, workspace_id, session_id, sequence
    );

create trigger legacy_session_events_no_update
before update on legacy_session_events
begin
    select raise(abort, 'legacy session events are immutable');
end;

create trigger legacy_session_events_no_delete
before delete on legacy_session_events
begin
    select raise(abort, 'legacy session events are immutable');
end;

create table legacy_workload_principals (
    principal_subject text not null,
    tenant_id text not null,
    workspace_id text not null,
    audience text not null,
    role text not null,
    transport text not null,
    active_generation integer not null,
    revoked_at_us integer,
    state_version integer not null,
    created_at_us integer not null,
    updated_at_us integer not null,
    primary key (principal_subject, tenant_id, workspace_id, audience)
);

create index legacy_workload_principals_scope_idx
    on legacy_workload_principals (
        tenant_id, workspace_id, audience, principal_subject
    );

create table legacy_workload_proof_claims (
    proof_identifier_digest text primary key,
    principal_subject text not null,
    tenant_id text not null,
    workspace_id text not null,
    audience text not null,
    role text not null,
    transport text not null,
    generation integer not null,
    method text not null,
    canonical_path text not null,
    body_sha256 text not null,
    issued_at_us integer not null,
    expires_at_us integer not null,
    claimed_at_us integer not null,
    retain_until_us integer not null,
    foreign key (
        principal_subject, tenant_id, workspace_id, audience
    ) references legacy_workload_principals (
        principal_subject, tenant_id, workspace_id, audience
    ) on delete restrict
);

create index legacy_workload_proof_claims_retention_idx
    on legacy_workload_proof_claims (
        retain_until_us, proof_identifier_digest
    );
create index legacy_workload_proof_claims_principal_idx
    on legacy_workload_proof_claims (
        principal_subject, tenant_id, workspace_id, audience, claimed_at_us
    );

create trigger legacy_workload_proof_claims_no_update
before update on legacy_workload_proof_claims
begin
    select raise(abort, 'legacy workload proof claims are immutable');
end;
```

The only valid `processing_status` values in v1 are `registered`, `uploaded`,
`processing`, `processed`, and `failed`. The only valid `review_status`
values are `not_ready`, `pending`, `approved`, `rejected`, and
`needs_changes`. Workload rows accept only the exact ADR 0008 pairings:
`capture_uploader` / `workflow-helper:capture-upload` /
`capture_workload`, and `deterministic_worker` /
`workflow-helper:processing-completion` / `worker_workload`.
`active_generation`, `state_version`, and event `state_version` start at
one and increase monotonically. Session registration inserts state version one
and its `registered` event in the same transaction.

A `session_id` remains globally unique. It cannot coexist in two scopes. A
collision in any scope returns generic unavailability and never discloses the
stored scope or owner.

## Scoped query contract

Authorization must be enforced in SQL before a row is materialized. Reviewer and
worker reads use exactly:

```sql
select <explicit record columns>
from legacy_sessions
where session_id = ? and tenant_id = ? and workspace_id = ?;
```

Capture-owner operations add:

```sql
and capture_owner_subject = ?
```

Lists use `where tenant_id = ? and workspace_id = ?` and an explicit bounded
order/limit. Code must not load by UUID and compare scope or owner afterward.
Zero rows, cross-tenant, cross-workspace, cross-owner, and unknown UUID all map
to the same generic absence. No response or log may reveal which predicate
failed.

## Authoritative proof claim, generation, and revocation

For every workload POST, after provider-specific credential verification but
before repository, S3, Drive, queue, or other side effects:

1. Validate the provider-neutral shape, exact method/path/body digest, audience,
   transport, role, UTC freshness, and five-minute lifetime cap.
2. Begin one SQLite `IMMEDIATE` transaction (PostgreSQL:
   `SERIALIZABLE` or an equivalent row lock plus retry).
3. Select `legacy_workload_principals` by the complete primary key. In that
   transaction require exact role and transport, `revoked_at_us is null`, and
   `active_generation = supplied generation`.
4. Insert the complete proof into `legacy_workload_proof_claims`. The global
   primary key makes every proof identifier one-time across processes and
   scopes. A uniqueness conflict is replay.
5. Commit before returning an authorized request to the route.

Any missing, stale, revoked, malformed, expired, or already-claimed proof receives
one generic rejection. An identical retry is replay and rejects; it does not
return a prior successful response. Revocation and generation rotation update
the principal row under the same writer serialization used by proof claims, so
a claim cannot race an authoritative change.

`retain_until_us` must be at least `expires_at_us + 60,000,000`. Claims must
not be deleted before that time. A future compactor is a separately dispatched,
time/data-bounded feature with concurrency, clock-skew, backup, and negative
tests; this design installs none.

A provider is still required to validate credentials and supply a pseudonymous
subject, but provider-supplied `active_generation`, `revoked`, and replay
fields are not authoritative in this implemented store. No provider is installed
by this ADR.

## Atomic session mutations and external ordering

Every accepted session state change uses one transaction that:

1. selects the session with the exact SQL scope/owner predicates and expected
   `state_version`;
2. validates the current state and idempotency contract;
3. updates the record and increments `state_version`; and
4. appends one `legacy_session_events` row with that same new version.

The event is component-local and append-only. It must never be written to, reuse,
rebuild, widen, or depend on the shared `audit_events` table. A failed update or
event insert rolls back both. An exact idempotent processing-completion replay
using a *new* valid proof returns the already stored result without another
mutation event; a conflicting completion remains a generic conflict.

No database transaction may span S3, Drive, any network verification, or queue
submission. Upload completion keeps this order:

1. authenticate and durably claim the proof;
2. read the scoped session;
3. perform the existing S3/LocalStack head/get/hash/size/ZIP/metadata verification
   with no database transaction open;
4. in one transaction, reselect the exact scoped owner plus expected version,
   mark uploaded, and append the event;
5. commit; then submit to the queue.

Thus verification still precedes `mark_uploaded`, and queue submission remains
after commit. The existing content-addressed object key, retry behavior, and
processing-completion idempotency are preserved. Queue failure never rolls back
a committed session mutation. A retry must use a new proof and follows the
existing safe retry path; an outbox would be a separate design.

## Initialization and constructor-order compatibility

The implemented `SQLiteLegacySessionStore` uses the same filesystem path,
`foreign_keys = on`, WAL, full synchronous durability, bounded busy timeout,
and connection-per-transaction pattern as the current synthetic stores.

For an empty/new synthetic file, initialization runs in one `IMMEDIATE`
transaction. If none of the five component tables exists, it creates exactly the
v1 objects, inserts the one component row, validates normalized
`sqlite_master` definitions and foreign keys, and commits. If all objects
exist, initialization succeeds only when the component ID, version, checksum,
columns, keys, indexes, triggers, and foreign keys match exactly. Partial
presence, an unknown version, a checksum mismatch, a name collision, disabled
foreign keys, or any shape drift rolls back and fails closed. It never attempts
repair.

The new constructor must be tested in every ordering with
`SQLiteControlStore` and `RetentionLedger` against a fresh single file, and
against reopening each completed ordering. The legacy initializer may create or
inspect only its five tables, three listed triggers, and listed indexes. It
must not rebuild, drop, rename, alter, copy, or widen a `CHECK` on any table,
including `audit_events`, and must not change either existing store's
`sqlite_master` SQL or data.

The current `RetentionLedger` contains historical shared-`audit_events`
expansion behavior. Constructor-order acceptance is not satisfied merely because
that rebuild succeeds. Before activating this reference, the test matrix must prove
that all three constructors can open the same new file without any
`DROP`, table-copy/`RENAME`, or `CHECK` widening. If the current constructors
cannot meet that test, correcting them is a separate source-code dispatch and is
a stop trigger for legacy-store activation, not permission to modify them here.

Existing nonempty database files are never auto-adopted. A file without the exact
component manifest is incompatible even if similarly named tables exist.
Inspection, backup, backfill, or migration of any existing file requires a
separate authorized package.

## PostgreSQL reference migration prerequisites

SQLite evidence is not the live PostgreSQL gate. Before a PostgreSQL migration
may be proposed, all of the following must be recorded and independently
verified:

- exact PostgreSQL version, database/cluster, owner, application roles, TLS,
  isolation behavior, credential source, connection pool, and least privileges;
- a new numbered additive migration separate from
  `apps/api/sql/0001_initial.sql`; that reference file is not compliant with
  this scoped/replay design and must not be rewritten in place;
- PostgreSQL-native UUID, `timestamptz`, `jsonb`, byte/count constraints,
  composite foreign keys, proof uniqueness, append-only event permissions or
  triggers, and equivalent indexes;
- authoritative inventory of existing session/principal state, a tested backup,
  restore proof, recorded RPO/RTO and cost bound, maintenance/concurrency plan,
  and exact pre/post row counts and checksums;
- deterministic tenant/workspace/capture-owner provenance for every backfilled
  row. Missing or ambiguous scope or owner aborts; it is never guessed;
- concurrency tests proving one winner for a proof claim, generation rotation
  and revocation races, scoped generic absence, optimistic session versioning,
  and append-only event atomicity;
- rollback/roll-forward, monitoring, alerting, incident ownership, audit
  retention, and authoritative post-migration verification.

No real or existing database is inspected, created, changed, backed up,
backfilled, or migrated under this ADR.

## Acceptance evidence for the reference implementation

At minimum, hermetic tests must prove:

- exact new/empty initialization and exact reopen; every constructor ordering and
  no forbidden schema rewrite;
- fail-closed partial tables, missing/wrong manifest, checksum or shape drift,
  unknown version, disabled foreign keys, and incompatible existing file;
- globally unique UUID collision gives generic absence across scope boundaries;
- list/read/timeline and every mutation apply tenant/workspace and, where
  required, capture owner in SQL before materialization;
- concurrent proof claims have one winner; identical retry rejects; stale
  generation, revoked principal, wrong role/audience/transport/method/path/body,
  future, expired, and cross-scope proofs reject generically;
- claim retention is never shorter than expiry plus 60 seconds;
- registration and each state mutation atomically update the row and append
  exactly one immutable component event with monotonic version;
- conflicting and exact processing-completion cases preserve current
  idempotency;
- no transaction remains open during S3/LocalStack verification, Drive/network
  activity, or queue submission; verification precedes uploaded state and queue
  follows commit;
- existing S3 signed headers, package verification, content-addressed keys,
  LocalStack behavior, queue retry, worker processing, and control/retention data
  remain unchanged;
- PostgreSQL concurrency and restore evidence passes independently before any
  live gate.

## Rollback and recovery

This implemented-but-unwired reference has no live data or infrastructure
recovery. Before merge, close the draft pull request and retain the private
branch. After a separately governed merge, revert its exact merge commit in a
private pull request; recovery is one Git revert plus one CI cycle at USD 0.

For the synthetic v1 schema implementation, stop writers, preserve the
database and WAL files, and restore the independently verified pre-change copy
or roll forward with a new additive component version. Dropping component tables
is destructive and is not authorized by this ADR. A live PostgreSQL recovery
objective must be measured and approved from tested backup/restore evidence; no
RPO or RTO is invented here.

## Residual risks, exclusions, and stop triggers

SQLite remains a synthetic concurrency oracle, not evidence of multi-node
PostgreSQL behavior. A committed upload state followed by queue failure retains
the existing retry dependency. Proof-claim growth is bounded only after a
separately verified compactor exists. Global UUID collision is an availability
event, not permission for same-UUID coexistence. Live provider installation,
credential issuance, provider-specific configuration, runtime wiring, and live
identity integration remain unsatisfied prerequisites.

The accepted reference implementation is Python-only, additive, and exercised
only with disposable synthetic SQLite files. ADR 0010 adds route composition but
still installs no provider, database path, credential, migration, network
service, deployment, permission, sharing setting, or billable resource. Neither
package claims production readiness or Drive-first artifact migration.

Stop before any future runtime or live activation, further implementation, or
wiring that would require reusing or widening shared `audit_events`, modifying
`0001_initial.sql`, changing global UUID semantics, holding a transaction across
an external call, auto-adopting an existing file, inferring scope or owner,
weakening generic absence, bypassing provider/security controls, or acting on
real database/provider/data/deployment state without its separate governance
package.
