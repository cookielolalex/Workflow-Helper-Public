-- Reference SQLite schema for the durable synthetic control-plane skeleton.
-- The application initializes this schema itself; this file is the reviewable
-- migration source for a later migration runner. It creates no cloud resource.
-- All timestamps are UTC Unix microseconds and all identifiers are pseudonymous.

create table if not exists control_jobs (
    job_id text primary key,
    payload_digest text not null,
    state text not null check (state in ('queued', 'leased', 'completed')),
    current_owner_id text,
    current_fencing_token integer not null default 0,
    current_attempt integer not null default 0,
    lease_acquired_at integer,
    lease_expires_at integer,
    heartbeat_at integer,
    completion_idempotency_key text,
    completion_result_digest text,
    completed_at integer,
    created_at integer not null,
    updated_at integer not null,
    check (
        (state = 'leased' and current_owner_id is not null and lease_expires_at is not null)
        or state != 'leased'
    ),
    check (
        (state = 'completed' and completion_idempotency_key is not null
            and completion_result_digest is not null and completed_at is not null)
        or state != 'completed'
    )
);

create index if not exists control_jobs_active_lease_idx
    on control_jobs (state, lease_expires_at);

-- Lease history is append-only evidence. BEGIN IMMEDIATE serializes acquisition,
-- capacity checks, fencing-token changes, heartbeats, and completion.
create table if not exists lease_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    job_id text not null references control_jobs(job_id),
    event_type text not null check (
        event_type in ('acquired', 'reacquired', 'heartbeat', 'completed')
    ),
    owner_id text not null,
    fencing_token integer not null check (fencing_token > 0),
    attempt integer not null check (attempt > 0),
    occurred_at integer not null,
    lease_expires_at integer,
    result_digest text
);

create trigger if not exists lease_events_no_update
before update on lease_events
begin
    select raise(abort, 'lease events are immutable');
end;

create trigger if not exists lease_events_no_delete
before delete on lease_events
begin
    select raise(abort, 'lease events are immutable');
end;

-- Review idempotency keys are globally unique. Provenance JSON is validated by
-- the application and must name source, artifact_id, revision, and lowercase
-- SHA-256. Events can only be appended; the projection is a rebuildable cache.
create table if not exists review_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    target_id text not null,
    idempotency_key text not null unique,
    content_digest text not null,
    actor_id text not null,
    status text not null check (
        status in ('pending', 'approved', 'rejected', 'needs_changes')
    ),
    provenance_json text not null,
    detail_json text not null,
    occurred_at integer not null
);

create trigger if not exists review_events_no_update
before update on review_events
begin
    select raise(abort, 'review events are immutable');
end;

create trigger if not exists review_events_no_delete
before delete on review_events
begin
    select raise(abort, 'review events are immutable');
end;

create table if not exists review_projection (
    target_id text primary key,
    status text not null,
    version integer not null check (version > 0),
    last_event_id text not null references review_events(event_id),
    actor_id text not null,
    provenance_json text not null,
    detail_json text not null,
    occurred_at integer not null
);

-- Authenticated action evidence is append-only. Accepted mutation evidence is
-- inserted inside the same BEGIN IMMEDIATE transaction as the state change.
create table if not exists audit_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    correlation_id text not null,
    idempotency_key text,
    subject_id text not null,
    roles_json text not null,
    action text not null check (action in (
        'audit.read', 'job.acquire', 'job.complete', 'job.heartbeat',
        'job.register', 'retention.attest_delete', 'retention.hold',
        'retention.read', 'retention.register', 'retention.stage_trash',
        'review.append', 'review.read'
    )),
    target_id text not null,
    result text not null check (result in ('accepted', 'denied')),
    occurred_at integer not null
);

create index if not exists audit_events_sequence_idx
    on audit_events (sequence);

create trigger if not exists audit_events_no_update
before update on audit_events
begin
    select raise(abort, 'audit events are immutable');
end;

create trigger if not exists audit_events_no_delete
before delete on audit_events
begin
    select raise(abort, 'audit events are immutable');
end;
