-- Reference schema for the PostgreSQL adapter. It is not applied automatically.
-- Use UUIDs and pseudonymous identities only; large artifacts remain in S3.

create extension if not exists pgcrypto;

create table sessions (
    session_id uuid primary key,
    schema_version text not null,
    machine_id text not null,
    project_id text,
    started_at timestamptz not null,
    ended_at timestamptz not null,
    active_duration_seconds integer not null check (active_duration_seconds >= 0),
    approved_process text not null,
    package_sha256 char(64) not null,
    package_size_bytes bigint not null check (package_size_bytes >= 0),
    processing_status text not null,
    review_status text not null,
    raw_object_key text,
    processed_prefix text,
    processing_output jsonb,
    processing_completion_id text,
    processing_completed_at timestamptz,
    raw_expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint sessions_processing_status_check check (
        processing_status in ('registered', 'uploaded', 'processing', 'processed', 'failed')
    ),
    constraint sessions_review_status_check check (
        review_status in ('not_ready', 'pending', 'approved', 'rejected', 'needs_changes')
    )
);

create index sessions_started_at_idx on sessions (started_at desc);
create index sessions_processing_status_idx on sessions (processing_status);
create index sessions_review_status_idx on sessions (review_status);
create index sessions_raw_expires_at_idx on sessions (raw_expires_at);

create table labels (
    label_id uuid primary key,
    session_id uuid not null references sessions(session_id) on delete cascade,
    category text not null,
    provenance text not null,
    confidence numeric(4, 3) not null check (confidence between 0 and 1),
    approval_status text not null,
    start_offset_seconds numeric,
    end_offset_seconds numeric,
    reviewer_note text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint labels_provenance_check check (
        provenance in ('observed', 'deterministic', 'ai_inferred', 'human_supplied')
    ),
    constraint labels_approval_status_check check (
        approval_status in ('unreviewed', 'approved', 'rejected', 'needs_changes')
    )
);

create index labels_session_id_idx on labels (session_id);
create index labels_category_idx on labels (category);

create table candidate_skills (
    skill_id uuid primary key default gen_random_uuid(),
    name text not null,
    description text not null,
    definition jsonb not null,
    confidence numeric(4, 3) not null check (confidence between 0 and 1),
    approval_status text not null default 'unreviewed',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint candidate_skills_approval_status_check check (
        approval_status in ('unreviewed', 'approved', 'rejected', 'needs_changes')
    )
);

create table skill_evidence (
    skill_id uuid not null references candidate_skills(skill_id) on delete cascade,
    session_id uuid not null references sessions(session_id) on delete restrict,
    evidence_ref text not null,
    primary key (skill_id, session_id, evidence_ref)
);

-- Production review actions require actor identity and an append-only audit log.
create table review_audit (
    audit_id uuid primary key default gen_random_uuid(),
    actor_id text not null,
    action text not null,
    target_type text not null,
    target_id uuid not null,
    before_value jsonb,
    after_value jsonb,
    occurred_at timestamptz not null default now()
);
