import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from workflow_api.control_identity_schema import (
    CONTROL_IDENTITY_COMPONENT_ID,
    CONTROL_IDENTITY_MIGRATION_SQL_SHA256,
    CONTROL_IDENTITY_SCHEMA_CHECKSUM,
    CONTROL_IDENTITY_SCHEMA_MANIFEST,
    LEGACY_IDENTITY_CLASS,
    LEGACY_OPAQUE_DIGEST_SCHEME_ID,
    MIGRATION_FAILURE_STEPS,
    PAYLOAD_DIGEST_SCHEME_ID,
    RESTORE_FAILURE_STEPS,
    RESULT_DIGEST_SCHEME_ID,
    VERSIONED_IDENTITY_CLASS,
    ControlIdentityDowngradeError,
    ControlIdentitySchemaError,
    migrate_control_identity_schema,
    restore_legacy_control_identity_backup,
    validate_control_identity_schema,
)
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_store import SQLiteControlStore

_API_ROOT = Path(__file__).parents[1]
_LEGACY_SQL = (_API_ROOT / "sql" / "0002_control_plane.sql").read_text()
_PAYLOAD_PREFIX = b"workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0"
_RESULT_PREFIX = b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"


def _legacy_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        connection.executescript(_LEGACY_SQL)


def _validate(path: Path) -> str:
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        return validate_control_identity_schema(connection)


def _controlled_snapshot(path: Path) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    with sqlite3.connect(path) as connection:
        catalog = connection.execute(
            """
            select type, name, tbl_name, sql from sqlite_master
            where name like 'control_%' or tbl_name like 'control_%'
               or name like 'lease_events%' or tbl_name = 'lease_events'
               or name like 'review_events%' or tbl_name = 'review_events'
               or name like 'review_projection%' or tbl_name = 'review_projection'
               or name like 'audit_events%' or tbl_name = 'audit_events'
            order by type, name
            """
        ).fetchall()
        jobs = connection.execute(
            """
            select job_id, typeof(payload_digest), payload_digest, state,
                   typeof(completion_result_digest), completion_result_digest,
                   current_owner_id, current_fencing_token, current_attempt,
                   lease_acquired_at, lease_expires_at, heartbeat_at,
                   completion_idempotency_key, completed_at, created_at, updated_at
            from control_jobs order by job_id
            """
        ).fetchall()
    return catalog, jobs


def _legacy_contents(path: Path) -> dict[str, list[tuple[object, ...]]]:
    tables = (
        "control_jobs",
        "lease_events",
        "review_events",
        "review_projection",
        "audit_events",
        "sqlite_sequence",
    )
    with sqlite3.connect(path) as connection:
        return {
            table: sorted(connection.execute(f"select * from {table}").fetchall(), key=repr)
            for table in tables
        }


def _insert_state_fixtures(path: Path) -> tuple[list[tuple[object, ...]], list[str]]:
    scope_a = TenantWorkspaceScope("tenant-aaa", "workspace-one")
    scope_b = TenantWorkspaceScope("tenant-bbb", "workspace-one")
    job_ids = [
        _qualify(scope_a, "job", "same-public-job"),
        _qualify(scope_b, "job", "same-public-job"),
        _qualify(scope_a, "job", "expired-job"),
        _qualify(scope_a, "job", "completed-job"),
    ]
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        connection.executemany(
            """
            insert into control_jobs (
                job_id, payload_digest, state, current_owner_id,
                current_fencing_token, current_attempt, lease_acquired_at,
                lease_expires_at, heartbeat_at, completion_idempotency_key,
                completion_result_digest, completed_at, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    job_ids[0],
                    "A" * 64,
                    "queued",
                    None,
                    0,
                    0,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    1,
                    1,
                ),
                (
                    job_ids[1],
                    sqlite3.Binary(b"payload-bytes-exact"),
                    "leased",
                    "worker-current",
                    7,
                    3,
                    10,
                    20,
                    11,
                    None,
                    None,
                    None,
                    2,
                    11,
                ),
                (
                    job_ids[2],
                    "c" * 64,
                    "leased",
                    "worker-expired",
                    8,
                    4,
                    10,
                    10,
                    10,
                    None,
                    None,
                    None,
                    3,
                    10,
                ),
                (
                    job_ids[3],
                    "d" * 64,
                    "completed",
                    "worker-complete",
                    9,
                    5,
                    10,
                    20,
                    11,
                    "completion-exact",
                    sqlite3.Binary(b"result-bytes-exact"),
                    12,
                    4,
                    12,
                ),
            ),
        )
        connection.execute(
            """
            insert into lease_events (
                sequence, event_id, job_id, event_type, owner_id, fencing_token,
                attempt, occurred_at, lease_expires_at, result_digest
            ) values (7, 'lease-synthetic', ?, 'completed', 'worker-complete',
                      9, 5, 12, null, ?)
            """,
            (job_ids[3], sqlite3.Binary(b"result-bytes-exact")),
        )
        connection.execute(
            """
            insert into review_events (
                sequence, event_id, target_id, idempotency_key, content_digest,
                actor_id, status, provenance_json, detail_json, occurred_at
            ) values (8, 'review-synthetic', 'target-synthetic', 'review-key',
                      'review-digest', 'reviewer-synthetic', 'approved', '{}', '{}', 13)
            """
        )
        connection.execute(
            """
            insert into review_projection (
                target_id, status, version, last_event_id, actor_id,
                provenance_json, detail_json, occurred_at
            ) values ('target-synthetic', 'approved', 1, 'review-synthetic',
                      'reviewer-synthetic', '{}', '{}', 13)
            """
        )
        connection.execute(
            """
            insert into audit_events (
                sequence, event_id, correlation_id, idempotency_key, subject_id,
                roles_json, action, target_id, result, occurred_at
                ) values (9, 'audit-synthetic', 'correlation-synthetic', 'audit-key',
                      'subject-synthetic', '[]', 'job.complete',
                      'target-synthetic', 'accepted', 14)
            """
        )
    return _controlled_snapshot(path)[1], job_ids


def test_manifest_and_deterministic_sql_are_hard_bound() -> None:
    migration_bytes = (
        _API_ROOT / "sql" / "0003_processing_job_v2_control_identity.sql"
    ).read_bytes()
    assert hashlib.sha256(migration_bytes).hexdigest() == CONTROL_IDENTITY_MIGRATION_SQL_SHA256
    assert (
        hashlib.sha256(CONTROL_IDENTITY_SCHEMA_MANIFEST.encode()).hexdigest()
        == CONTROL_IDENTITY_SCHEMA_CHECKSUM
    )


def test_empty_exact_legacy_migrates_and_reopens_idempotently(tmp_path: Path) -> None:
    database = tmp_path / "empty.sqlite3"
    backup = tmp_path / "empty.backup.sqlite3"
    _legacy_database(database)

    report = migrate_control_identity_schema(database, backup, installed_at_us=123)

    assert report.result == "migrated"
    assert report.classified_jobs == 0
    assert report.backup_bytes == backup.stat().st_size
    assert _validate(database) == "v1"
    assert _validate(backup) == "legacy"
    with sqlite3.connect(database) as connection:
        assert connection.execute("select * from control_component_schema").fetchone() == (
            CONTROL_IDENTITY_COMPONENT_ID,
            1,
            CONTROL_IDENTITY_SCHEMA_CHECKSUM,
            123,
            1,
            1,
        )
    second = migrate_control_identity_schema(database, backup, installed_at_us=999)
    assert second.result == "existing"
    assert second.backup_bytes == 0
    assert _validate(database) == "v1"


def test_all_legacy_states_and_digest_storage_classes_are_preserved_exactly(
    tmp_path: Path,
) -> None:
    database = tmp_path / "states.sqlite3"
    backup = tmp_path / "states.backup.sqlite3"
    _legacy_database(database)
    before, job_ids = _insert_state_fixtures(database)

    report = migrate_control_identity_schema(database, backup, installed_at_us=456)

    assert report.classified_jobs == 4
    assert _controlled_snapshot(database)[1] == before
    assert _controlled_snapshot(backup)[1] == before
    with sqlite3.connect(database) as connection:
        jobs = connection.execute(
            """
            select job_id, identity_class, payload_digest_scheme_id,
                   admitted_job_jcs, writer_epoch
            from control_job_identity order by job_id
            """
        ).fetchall()
        completions = connection.execute(
            """
            select job_id, identity_class, result_digest_scheme_id,
                   result_manifest_jcs, writer_epoch
            from control_completion_identity order by job_id
            """
        ).fetchall()
    expected = [
        (job_id, LEGACY_IDENTITY_CLASS, LEGACY_OPAQUE_DIGEST_SCHEME_ID, None, 1)
        for job_id in sorted(job_ids)
    ]
    assert jobs == expected
    assert completions == expected
    assert len({job_ids[0], job_ids[1]}) == 2


def test_runtime_generated_legacy_variant_is_explicitly_admitted(tmp_path: Path) -> None:
    database = tmp_path / "runtime-legacy.sqlite3"
    backup = tmp_path / "runtime-legacy.backup.sqlite3"
    SQLiteControlStore(database).register_job("synthetic-job", "a" * 64)

    assert _validate(database) == "legacy"
    migrate_control_identity_schema(database, backup, installed_at_us=789)
    assert _validate(database) == "v1"

    SQLiteControlStore(database).register_job("post-migration-job", "b" * 64)
    with sqlite3.connect(database) as connection:
        for table in ("control_job_identity", "control_completion_identity"):
            assert connection.execute(
                f"select identity_class, writer_epoch from {table} where job_id = ?",
                ("post-migration-job",),
            ).fetchone() == (LEGACY_IDENTITY_CLASS, 1)
    assert _validate(database) == "v1"


def test_source_change_after_backup_refuses_before_migration_write(tmp_path: Path) -> None:
    database = tmp_path / "source-change.sqlite3"
    backup = tmp_path / "source-change.backup.sqlite3"
    _legacy_database(database)

    def insert_after_backup(step: str) -> None:
        if step == "after_verified_backup":
            with sqlite3.connect(database) as concurrent:
                concurrent.execute(
                    """
                    insert into control_jobs (
                        job_id, payload_digest, state, created_at, updated_at
                    ) values ('after-backup', 'digest-after-backup', 'queued', 1, 1)
                    """
                )

    with pytest.raises(ControlIdentitySchemaError, match="changed after the verified backup"):
        migrate_control_identity_schema(
            database,
            backup,
            installed_at_us=1,
            failure_injector=insert_after_backup,
        )

    assert _validate(database) == "legacy"
    assert _validate(backup) == "legacy"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "select count(*) from control_jobs where job_id = 'after-backup'"
        ).fetchone() == (1,)
    with sqlite3.connect(backup) as connection:
        assert connection.execute(
            "select count(*) from control_jobs where job_id = 'after-backup'"
        ).fetchone() == (0,)


@pytest.mark.parametrize("failure_step", MIGRATION_FAILURE_STEPS)
def test_every_migration_failure_step_rolls_back_atomically(
    tmp_path: Path,
    failure_step: str,
) -> None:
    database = tmp_path / f"fault-{failure_step}.sqlite3"
    backup = tmp_path / f"fault-{failure_step}.backup.sqlite3"
    _legacy_database(database)
    _insert_state_fixtures(database)
    before = _controlled_snapshot(database)

    def fail(step: str) -> None:
        if step == failure_step:
            raise RuntimeError("synthetic migration fault")

    with pytest.raises(RuntimeError, match="synthetic migration fault"):
        migrate_control_identity_schema(
            database,
            backup,
            installed_at_us=1,
            failure_injector=fail,
        )

    assert backup.is_file()
    assert _validate(backup) == "legacy"
    assert _validate(database) == "legacy"
    assert _controlled_snapshot(database) == before


@pytest.mark.parametrize(
    "drift", ("partial", "index", "trigger", "foreign_key", "extra_table", "extra_view")
)
def test_drift_and_corruption_refuse_before_backup(
    tmp_path: Path,
    drift: str,
) -> None:
    database = tmp_path / f"drift-{drift}.sqlite3"
    backup = tmp_path / f"drift-{drift}.backup.sqlite3"
    _legacy_database(database)
    with sqlite3.connect(database) as connection:
        if drift == "partial":
            connection.execute("create table control_component_schema (value text)")
        elif drift == "index":
            connection.execute("drop index control_jobs_active_lease_idx")
        elif drift == "trigger":
            connection.execute("drop trigger lease_events_no_delete")
            connection.execute(
                "create trigger lease_events_no_delete before delete on lease_events begin select 1; end"
            )
        elif drift == "foreign_key":
            connection.execute("pragma foreign_keys = off")
            connection.execute(
                """
                insert into lease_events (
                    event_id, job_id, event_type, owner_id, fencing_token,
                    attempt, occurred_at
                ) values ('orphan', 'missing', 'acquired', 'worker', 1, 1, 1)
                """
            )
        elif drift == "extra_table":
            connection.execute("create table arbitrary_extra (value text)")
        else:
            connection.execute("create view arbitrary_extra as select 1 as value")

    with pytest.raises(ControlIdentitySchemaError):
        migrate_control_identity_schema(database, backup, installed_at_us=1)
    assert not backup.exists()


@pytest.mark.parametrize(
    "field",
    ("schema_version", "schema_checksum", "writer_epoch", "minimum_writer_epoch"),
)
def test_unknown_manifest_version_checksum_or_writer_seal_refuses(
    tmp_path: Path,
    field: str,
) -> None:
    database = tmp_path / f"manifest-{field}.sqlite3"
    backup = tmp_path / f"manifest-{field}.backup.sqlite3"
    _legacy_database(database)
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    with sqlite3.connect(database) as connection:
        value: object = 2 if field != "schema_checksum" else "0" * 64
        connection.execute("pragma ignore_check_constraints = on")
        connection.execute(f"update control_component_schema set {field} = ?", (value,))
    with pytest.raises(ControlIdentitySchemaError):
        _validate(database)


@pytest.mark.parametrize(
    "object_sql",
    (
        "create table arbitrary_target (value text)",
        "create view arbitrary_target as select 1 as value",
        "create index arbitrary_target on control_jobs (state)",
        "create trigger arbitrary_target after update on control_jobs begin select 1; end",
    ),
)
def test_target_catalog_rejects_every_unapproved_object(tmp_path: Path, object_sql: str) -> None:
    database = tmp_path / "target-extra.sqlite3"
    backup = tmp_path / "target-extra.backup.sqlite3"
    _legacy_database(database)
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    with sqlite3.connect(database) as connection:
        connection.execute(object_sql)

    with pytest.raises(ControlIdentitySchemaError, match="partial, drifted"):
        _validate(database)


@pytest.mark.parametrize(
    "trigger",
    (
        "control_jobs_identity_sidecars_after_insert",
        "control_job_identity_v1_no_update",
        "control_job_identity_v1_no_delete",
        "control_completion_identity_v1_no_update",
        "control_completion_identity_v1_no_delete",
        "control_jobs_v1_payload_projection_no_update",
        "control_jobs_v1_result_projection_no_update",
    ),
)
def test_identity_trigger_drift_is_rejected(tmp_path: Path, trigger: str) -> None:
    database = tmp_path / f"trigger-{trigger}.sqlite3"
    backup = tmp_path / f"trigger-{trigger}.backup.sqlite3"
    _legacy_database(database)
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    with sqlite3.connect(database) as connection:
        connection.execute(f"drop trigger {trigger}")

    with pytest.raises(ControlIdentitySchemaError, match="partial, drifted"):
        _validate(database)


def test_backup_size_cap_fails_before_backup_or_schema_write(tmp_path: Path) -> None:
    database = tmp_path / "bounded.sqlite3"
    backup = tmp_path / "bounded.backup.sqlite3"
    _legacy_database(database)
    before = _controlled_snapshot(database)

    with pytest.raises(ControlIdentitySchemaError, match="bounded backup policy"):
        migrate_control_identity_schema(
            database,
            backup,
            installed_at_us=1,
            max_database_bytes=4096,
        )

    assert not backup.exists()
    assert _controlled_snapshot(database) == before
    assert _validate(database) == "legacy"


def test_corrupt_database_refuses_before_backup(tmp_path: Path) -> None:
    database = tmp_path / "corrupt.sqlite3"
    backup = tmp_path / "corrupt.backup.sqlite3"
    database.write_bytes(b"not a sqlite database; synthetic corruption")

    with pytest.raises(ControlIdentitySchemaError, match="failed closed"):
        migrate_control_identity_schema(database, backup, installed_at_us=1)

    assert not backup.exists()


def test_verified_backup_restores_only_before_v1_identity(tmp_path: Path) -> None:
    database = tmp_path / "restore.sqlite3"
    backup = tmp_path / "restore.backup.sqlite3"
    _legacy_database(database)
    _insert_state_fixtures(database)
    before = _legacy_contents(database)
    migrate_control_identity_schema(database, backup, installed_at_us=1)

    SQLiteControlStore(database).register_job("post-migration", "e" * 64)

    restore_legacy_control_identity_backup(database, backup)

    assert _validate(database) == "legacy"
    assert _legacy_contents(database) == before


@pytest.mark.parametrize("failure_step", RESTORE_FAILURE_STEPS)
def test_every_restore_failure_step_rolls_back_to_exact_v1(
    tmp_path: Path, failure_step: str
) -> None:
    database = tmp_path / f"restore-fault-{failure_step}.sqlite3"
    backup = tmp_path / f"restore-fault-{failure_step}.backup.sqlite3"
    _legacy_database(database)
    _insert_state_fixtures(database)
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    before = _controlled_snapshot(database)

    def fail(step: str) -> None:
        if step == failure_step:
            raise RuntimeError("synthetic restore fault")

    with pytest.raises(RuntimeError, match="synthetic restore fault"):
        restore_legacy_control_identity_backup(
            database,
            backup,
            failure_injector=fail,
        )

    assert _validate(database) == "v1"
    assert _controlled_snapshot(database) == before
    assert _validate(backup) == "legacy"


def test_restore_holds_exclusive_writer_lock_across_eligibility_and_overwrite(
    tmp_path: Path,
) -> None:
    database = tmp_path / "restore-lock.sqlite3"
    backup = tmp_path / "restore-lock.backup.sqlite3"
    _legacy_database(database)
    _insert_state_fixtures(database)
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    observed_locked = False

    def probe(step: str) -> None:
        nonlocal observed_locked
        if step == "under_exclusive_lock_before_restore":
            with sqlite3.connect(database, timeout=0.01) as concurrent:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    concurrent.execute(
                        """
                        insert into control_jobs (
                            job_id, payload_digest, state, created_at, updated_at
                        ) values ('concurrent-restore', 'digest', 'queued', 1, 1)
                        """
                    )
                observed_locked = True

    restore_legacy_control_identity_backup(database, backup, failure_injector=probe)
    assert observed_locked
    assert _validate(database) == "legacy"


def test_nested_symlink_ancestor_is_refused_for_backup(tmp_path: Path) -> None:
    database = tmp_path / "symlink-source.sqlite3"
    _legacy_database(database)
    real = tmp_path / "real"
    nested = real / "nested"
    nested.mkdir(parents=True)
    link = tmp_path / "link"
    os.symlink(real, link)
    backup = link / "nested" / "backup.sqlite3"

    with pytest.raises(ControlIdentitySchemaError, match="must not use symlinks"):
        migrate_control_identity_schema(database, backup, installed_at_us=1)

    assert not (nested / "backup.sqlite3").exists()
    assert _validate(database) == "legacy"


def test_valid_v1_payload_and_result_projections_validate_and_block_downgrade(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v1.sqlite3"
    backup = tmp_path / "v1.backup.sqlite3"
    _legacy_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            insert into control_jobs (
                job_id, payload_digest, state, current_owner_id,
                current_fencing_token, current_attempt, lease_acquired_at,
                lease_expires_at, heartbeat_at, completion_idempotency_key,
                completion_result_digest, completed_at, created_at, updated_at
            ) values ('job-v1', ?, 'completed', 'worker', 1, 1, 1, 2, 1,
                      'completion-v1', ?, 2, 1, 2)
            """,
            (
                hashlib.sha256(_PAYLOAD_PREFIX + b'{"synthetic":1}').hexdigest(),
                hashlib.sha256(_RESULT_PREFIX + b'{"outputs":[]}').hexdigest(),
            ),
        )
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            update control_job_identity
            set identity_class = ?, payload_digest_scheme_id = ?,
                admitted_job_jcs = ?, writer_epoch = 1
            where job_id = 'job-v1'
            """,
            (VERSIONED_IDENTITY_CLASS, PAYLOAD_DIGEST_SCHEME_ID, b'{"synthetic":1}'),
        )
        connection.execute(
            """
            update control_completion_identity
            set identity_class = ?, result_digest_scheme_id = ?,
                result_manifest_jcs = ?, writer_epoch = 1
            where job_id = 'job-v1'
            """,
            (VERSIONED_IDENTITY_CLASS, RESULT_DIGEST_SCHEME_ID, b'{"outputs":[]}'),
        )

    assert _validate(database) == "v1"
    mutations = (
        "update control_job_identity set admitted_job_jcs = x'01' where job_id = 'job-v1'",
        "delete from control_job_identity where job_id = 'job-v1'",
        "update control_completion_identity set result_manifest_jcs = x'01' where job_id = 'job-v1'",
        "delete from control_completion_identity where job_id = 'job-v1'",
        "update control_jobs set payload_digest = 'rewritten' where job_id = 'job-v1'",
        "update control_jobs set completion_result_digest = 'rewritten' where job_id = 'job-v1'",
    )
    for mutation in mutations:
        with (
            sqlite3.connect(database) as connection,
            pytest.raises(sqlite3.IntegrityError, match="immutable"),
        ):
            connection.execute(mutation)

    for statements in (
        (
            "update control_jobs set payload_digest = 'coordinated' where job_id = 'job-v1'",
            "update control_job_identity set admitted_job_jcs = x'02' where job_id = 'job-v1'",
        ),
        (
            "update control_job_identity set admitted_job_jcs = x'02' where job_id = 'job-v1'",
            "update control_jobs set payload_digest = 'coordinated' where job_id = 'job-v1'",
        ),
    ):
        with (
            sqlite3.connect(database) as connection,
            pytest.raises(sqlite3.IntegrityError, match="immutable"),
            connection,
        ):
            for statement in statements:
                connection.execute(statement)

    assert _validate(database) == "v1"
    with pytest.raises(ControlIdentityDowngradeError, match="forward repair"):
        restore_legacy_control_identity_backup(database, backup)
    assert _validate(database) == "v1"


def test_projection_drift_and_sidecar_cardinality_refuse(tmp_path: Path) -> None:
    database = tmp_path / "row-drift.sqlite3"
    backup = tmp_path / "row-drift.backup.sqlite3"
    _legacy_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            insert into control_jobs (job_id, payload_digest, state, created_at, updated_at)
            values ('job-drift', ?, 'queued', 1, 1)
            """,
            (hashlib.sha256(_PAYLOAD_PREFIX + b"canonical").hexdigest(),),
        )
    migrate_control_identity_schema(database, backup, installed_at_us=1)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            update control_job_identity
            set identity_class = ?, payload_digest_scheme_id = ?, admitted_job_jcs = ?
            where job_id = 'job-drift'
            """,
            (VERSIONED_IDENTITY_CLASS, PAYLOAD_DIGEST_SCHEME_ID, b"different"),
        )
    with pytest.raises(ControlIdentitySchemaError, match="payload projection"):
        _validate(database)

    cardinality_database = tmp_path / "cardinality-drift.sqlite3"
    cardinality_backup = tmp_path / "cardinality-drift.backup.sqlite3"
    _legacy_database(cardinality_database)
    SQLiteControlStore(cardinality_database).register_job("job-cardinality", "f" * 64)
    migrate_control_identity_schema(
        cardinality_database,
        cardinality_backup,
        installed_at_us=1,
    )
    with sqlite3.connect(cardinality_database) as connection:
        connection.execute(
            "delete from control_completion_identity where job_id = 'job-cardinality'"
        )
    with pytest.raises(ControlIdentitySchemaError, match="one-to-one"):
        _validate(cardinality_database)
