-- Dormant ProcessingJobV2 control-identity sidecars.
--
-- This deterministic DDL is executed only by the explicit migration function in
-- workflow_api.control_identity_schema.  It does not alter control_jobs, wire a
-- runtime, or admit provider data.  Dynamic manifest and classification rows are
-- inserted separately inside the same BEGIN IMMEDIATE transaction.

create table control_component_schema (
    component_id text primary key
        check (component_id = 'workflow-helper.processing-job-v2-control-identity'),
    schema_version integer not null check (schema_version = 1),
    schema_checksum text not null,
    installed_at_us integer not null,
    writer_epoch integer not null check (writer_epoch = 1),
    minimum_writer_epoch integer not null
        check (minimum_writer_epoch = 1 and minimum_writer_epoch <= writer_epoch)
);

create table control_job_identity (
    job_id text primary key
        references control_jobs(job_id) on update restrict on delete restrict,
    identity_class text not null check (
        identity_class in ('legacy-opaque-v0', 'processing-job-v2-jcs-v1')
    ),
    payload_digest_scheme_id text not null,
    admitted_job_jcs blob,
    writer_epoch integer not null check (writer_epoch = 1),
    check (
        (
            identity_class = 'legacy-opaque-v0'
            and payload_digest_scheme_id = 'legacy-opaque-sha256'
            and admitted_job_jcs is null
            and writer_epoch = 1
        )
        or (
            identity_class = 'processing-job-v2-jcs-v1'
            and payload_digest_scheme_id =
                'workflow-helper.processing-job-v2.payload.sha256-jcs.v1'
            and typeof(admitted_job_jcs) = 'blob'
            and length(admitted_job_jcs) > 0
        )
    )
);

create table control_completion_identity (
    job_id text primary key
        references control_jobs(job_id) on update restrict on delete restrict,
    identity_class text not null check (
        identity_class in ('legacy-opaque-v0', 'processing-job-v2-jcs-v1')
    ),
    result_digest_scheme_id text not null,
    result_manifest_jcs blob,
    writer_epoch integer not null check (writer_epoch = 1),
    check (
        (
            identity_class = 'legacy-opaque-v0'
            and result_digest_scheme_id = 'legacy-opaque-sha256'
            and result_manifest_jcs is null
            and writer_epoch = 1
        )
        or (
            identity_class = 'processing-job-v2-jcs-v1'
            and result_digest_scheme_id =
                'workflow-helper.processing-job-v2.result.sha256-jcs.v1'
            and typeof(result_manifest_jcs) = 'blob'
            and length(result_manifest_jcs) > 0
        )
    )
);

-- The unchanged legacy writer remains admitted. Every later control_jobs insert
-- is classified in both sidecars inside that writer's own transaction.
create trigger control_jobs_identity_sidecars_after_insert
after insert on control_jobs
begin
    insert into control_job_identity (
        job_id, identity_class, payload_digest_scheme_id,
        admitted_job_jcs, writer_epoch
    ) values (
        new.job_id, 'legacy-opaque-v0', 'legacy-opaque-sha256', null, 1
    );
    insert into control_completion_identity (
        job_id, identity_class, result_digest_scheme_id,
        result_manifest_jcs, writer_epoch
    ) values (
        new.job_id, 'legacy-opaque-v0', 'legacy-opaque-sha256', null, 1
    );
end;

-- A separately governed future writer may transition one legacy row to v1 once.
-- After that transition neither sidecar nor its parent projection may change.
create trigger control_job_identity_v1_no_update
before update on control_job_identity
when old.identity_class = 'processing-job-v2-jcs-v1'
begin
    select raise(abort, 'v1 control job identity is immutable');
end;

create trigger control_job_identity_v1_no_delete
before delete on control_job_identity
when old.identity_class = 'processing-job-v2-jcs-v1'
begin
    select raise(abort, 'v1 control job identity is immutable');
end;

create trigger control_completion_identity_v1_no_update
before update on control_completion_identity
when old.identity_class = 'processing-job-v2-jcs-v1'
begin
    select raise(abort, 'v1 control completion identity is immutable');
end;

create trigger control_completion_identity_v1_no_delete
before delete on control_completion_identity
when old.identity_class = 'processing-job-v2-jcs-v1'
begin
    select raise(abort, 'v1 control completion identity is immutable');
end;

create trigger control_jobs_v1_payload_projection_no_update
before update of payload_digest on control_jobs
when exists (
    select 1 from control_job_identity
    where job_id = old.job_id
      and identity_class = 'processing-job-v2-jcs-v1'
)
and (
    typeof(new.payload_digest) != typeof(old.payload_digest)
    or new.payload_digest is not old.payload_digest
)
begin
    select raise(abort, 'v1 control job identity is immutable');
end;

create trigger control_jobs_v1_result_projection_no_update
before update of completion_result_digest on control_jobs
when exists (
    select 1 from control_completion_identity
    where job_id = old.job_id
      and identity_class = 'processing-job-v2-jcs-v1'
)
and (
    typeof(new.completion_result_digest) != typeof(old.completion_result_digest)
    or new.completion_result_digest is not old.completion_result_digest
)
begin
    select raise(abort, 'v1 control completion identity is immutable');
end;
