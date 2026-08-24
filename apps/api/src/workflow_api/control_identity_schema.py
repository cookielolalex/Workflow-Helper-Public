"""Dormant, exact migration for versioned ProcessingJobV2 control identity.

The module is intentionally not imported by the control store or any runtime.
Its public validator is read-only.  The migration and restore entry points act
only when explicitly called with filesystem paths and accept only an exact
repository legacy schema or the exact v1 target schema.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, Protocol

CONTROL_IDENTITY_COMPONENT_ID = "workflow-helper.processing-job-v2-control-identity"
CONTROL_IDENTITY_SCHEMA_VERSION = 1
CONTROL_IDENTITY_WRITER_EPOCH = 1
CONTROL_IDENTITY_MINIMUM_WRITER_EPOCH = 1
LEGACY_IDENTITY_CLASS = "legacy-opaque-v0"
VERSIONED_IDENTITY_CLASS = "processing-job-v2-jcs-v1"
LEGACY_OPAQUE_DIGEST_SCHEME_ID = "legacy-opaque-sha256"
PAYLOAD_DIGEST_SCHEME_ID = "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
RESULT_DIGEST_SCHEME_ID = "workflow-helper.processing-job-v2.result.sha256-jcs.v1"

CONTROL_IDENTITY_MIGRATION_SQL_SHA256 = (
    "b218e06f343091b01ee221667a000fa8a5037f6109caf8f3e220e3e346c34774"
)
LEGACY_CONTROL_SQL_SHA256 = "a96f2c632ee318038d13b7a98547c016a4b2e2ca3c3ef7adc26dad97275b6b50"
CONTROL_IDENTITY_SCHEMA_MANIFEST = (
    "workflow-helper.processing-job-v2-control-identity/v1|"
    f"ddl-sha256:{CONTROL_IDENTITY_MIGRATION_SQL_SHA256}|"
    "control_component_schema:component_id,schema_version,schema_checksum,"
    "installed_at_us,writer_epoch,minimum_writer_epoch|"
    "control_job_identity:job_id,identity_class,payload_digest_scheme_id,"
    "admitted_job_jcs,writer_epoch|"
    "control_completion_identity:job_id,identity_class,result_digest_scheme_id,"
    "result_manifest_jcs,writer_epoch"
)
CONTROL_IDENTITY_SCHEMA_CHECKSUM = (
    "dca0aea7a62c94d1cf76a935f263d11c64d6013059735561aa681fd10d1da960"
)

DEFAULT_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_DDL_FAILURE_STEPS = (
    "after_control_component_schema_ddl",
    "after_control_job_identity_ddl",
    "after_control_completion_identity_ddl",
    "after_legacy_writer_trigger_ddl",
    "after_job_v1_no_update_trigger_ddl",
    "after_job_v1_no_delete_trigger_ddl",
    "after_completion_v1_no_update_trigger_ddl",
    "after_completion_v1_no_delete_trigger_ddl",
    "after_payload_projection_trigger_ddl",
    "after_result_projection_trigger_ddl",
)
MIGRATION_FAILURE_STEPS = (
    "after_verified_backup",
    "after_stable_source_equivalence",
    *_DDL_FAILURE_STEPS,
    "after_manifest_insert",
    "after_job_classification",
    "after_completion_classification",
    "after_target_validation",
)

_PAYLOAD_PREFIX = b"workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0"
_RESULT_PREFIX = b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
_SPACE = re.compile(r"\s+")
_PUNCTUATION_SPACE = re.compile(r"\s*([(),])\s*")
_BASE_TABLES = (
    "control_jobs",
    "lease_events",
    "review_events",
    "review_projection",
    "audit_events",
)
_IDENTITY_TABLES = (
    "control_component_schema",
    "control_job_identity",
    "control_completion_identity",
)
_KNOWN_TABLES = (*_BASE_TABLES, *_IDENTITY_TABLES)
_IDENTITY_TRIGGER_NAMES = (
    "control_jobs_identity_sidecars_after_insert",
    "control_job_identity_v1_no_update",
    "control_job_identity_v1_no_delete",
    "control_completion_identity_v1_no_update",
    "control_completion_identity_v1_no_delete",
    "control_jobs_v1_payload_projection_no_update",
    "control_jobs_v1_result_projection_no_update",
)
_BASE_TRIGGER_NAMES = (
    "lease_events_no_update",
    "lease_events_no_delete",
    "review_events_no_update",
    "review_events_no_delete",
    "audit_events_no_update",
    "audit_events_no_delete",
)
_RESTORE_COLUMNS = {
    "control_jobs": (
        "job_id",
        "payload_digest",
        "state",
        "current_owner_id",
        "current_fencing_token",
        "current_attempt",
        "lease_acquired_at",
        "lease_expires_at",
        "heartbeat_at",
        "completion_idempotency_key",
        "completion_result_digest",
        "completed_at",
        "created_at",
        "updated_at",
    ),
    "lease_events": (
        "sequence",
        "event_id",
        "job_id",
        "event_type",
        "owner_id",
        "fencing_token",
        "attempt",
        "occurred_at",
        "lease_expires_at",
        "result_digest",
    ),
    "review_events": (
        "sequence",
        "event_id",
        "target_id",
        "idempotency_key",
        "content_digest",
        "actor_id",
        "status",
        "provenance_json",
        "detail_json",
        "occurred_at",
    ),
    "review_projection": (
        "target_id",
        "status",
        "version",
        "last_event_id",
        "actor_id",
        "provenance_json",
        "detail_json",
        "occurred_at",
    ),
    "audit_events": (
        "sequence",
        "event_id",
        "correlation_id",
        "idempotency_key",
        "subject_id",
        "roles_json",
        "action",
        "target_id",
        "result",
        "occurred_at",
    ),
}
_RESTORE_DELETE_ORDER = (
    "review_projection",
    "lease_events",
    "review_events",
    "audit_events",
    "control_jobs",
)
_RESTORE_INSERT_ORDER = (
    "control_jobs",
    "lease_events",
    "review_events",
    "review_projection",
    "audit_events",
)
_AUTOINCREMENT_TABLES = ("lease_events", "review_events", "audit_events")
RESTORE_FAILURE_STEPS = (
    "under_exclusive_lock_before_restore",
    "after_identity_schema_removal",
    "after_legacy_data_copy",
    "after_restore_validation",
)
_ALTERNATE_REVIEW_EVENTS_SQL = """
create table review_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    target_id text not null,
    idempotency_key text not null,
    content_digest text not null,
    actor_id text not null,
    status text not null check (
        status in ('pending', 'approved', 'rejected', 'needs_changes')
    ),
    provenance_json text not null,
    detail_json text not null,
    occurred_at integer not null,
    unique (idempotency_key)
)
"""


class ControlIdentitySchemaError(RuntimeError):
    """The control database, migration, backup, or compatibility seal is invalid."""


class ControlIdentityDowngradeError(ControlIdentitySchemaError):
    """A verified backup cannot replace a database containing v1 identity."""


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


@dataclass(frozen=True, slots=True)
class ControlIdentityMigrationReport:
    """Bounded non-sensitive evidence from an explicit migration call."""

    result: Literal["migrated", "existing"]
    classified_jobs: int
    backup_bytes: int
    schema_checksum: str


def validate_control_identity_schema(
    connection: sqlite3.Connection,
) -> Literal["legacy", "v1"]:
    """Read-only validation of the exact legacy or exact v1 controlled schema."""

    _require_foreign_keys(connection)
    _verify_static_checksums()
    actual = _controlled_catalog(connection)
    legacy_catalogs, target_catalogs = _expected_catalogs()
    if actual in legacy_catalogs:
        _validate_expected_facts(connection, target=False)
        _validate_database_health(connection)
        _validate_legacy_rows(connection)
        return "legacy"
    if actual in target_catalogs:
        _validate_expected_facts(connection, target=True)
        _validate_database_health(connection)
        _validate_target_rows(connection)
        return "v1"
    raise ControlIdentitySchemaError(
        "control identity schema is partial, drifted, or not an approved version"
    )


def _validate_attached_legacy_schema(connection: sqlite3.Connection) -> None:
    """Validate the locked, attached rollback source without mutating either DB."""

    _require_foreign_keys(connection)
    _verify_static_checksums()
    legacy_catalogs, _target_catalogs = _expected_catalogs()
    if _controlled_catalog(connection, schema="legacy_backup") not in legacy_catalogs:
        raise ControlIdentitySchemaError("attached rollback source is not exact legacy schema")
    _validate_expected_facts(connection, target=False, schema="legacy_backup")
    _validate_database_health(connection, schema="legacy_backup")
    _validate_legacy_rows(connection, schema="legacy_backup")


def migrate_control_identity_schema(
    database_path: str | Path,
    backup_path: str | Path,
    *,
    installed_at_us: int,
    max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
    failure_injector: Callable[[str], None] | None = None,
) -> ControlIdentityMigrationReport:
    """Explicitly migrate one exact legacy database after a verified bounded backup.

    The migration is restart-idempotent.  An exact target is validated and returned
    without creating or changing a backup.  All DDL and classification inserts are
    one ``BEGIN IMMEDIATE`` transaction; injected failures therefore roll back.
    """

    database = _require_database_path(database_path)
    backup = _require_distinct_backup_path(database, backup_path)
    _require_signed_int64(installed_at_us, "installed_at_us")
    _require_size_cap(max_database_bytes)
    callback = failure_injector or _no_failure
    if not callable(callback):
        raise TypeError("failure_injector must be callable")

    with _open_database(database) as connection:
        state = validate_control_identity_schema(connection)
        _require_bounded_database(connection, database, max_database_bytes)
        if state == "v1":
            count = connection.execute("select count(*) from control_jobs").fetchone()[0]
            return ControlIdentityMigrationReport(
                "existing", count, 0, CONTROL_IDENTITY_SCHEMA_CHECKSUM
            )
        _checkpoint_wal(connection)
        validate_control_identity_schema(connection)
        source_digest = _logical_digest(connection)
        backup_bytes = _create_verified_backup(
            connection,
            backup,
            expected_digest=source_digest,
            max_database_bytes=max_database_bytes,
        )
        callback("after_verified_backup")

        statements = _migration_statements()
        try:
            connection.execute("begin immediate")
            if validate_control_identity_schema(connection) != "legacy":
                raise ControlIdentitySchemaError("migration source changed before transaction")
            if _logical_digest(connection) != source_digest:
                raise ControlIdentitySchemaError(
                    "migration source changed after the verified backup"
                )
            callback("after_stable_source_equivalence")
            for statement, step in zip(
                statements,
                _DDL_FAILURE_STEPS,
                strict=True,
            ):
                connection.execute(statement)
                callback(step)
            connection.execute(
                """
                insert into control_component_schema (
                    component_id, schema_version, schema_checksum, installed_at_us,
                    writer_epoch, minimum_writer_epoch
                ) values (?, ?, ?, ?, ?, ?)
                """,
                (
                    CONTROL_IDENTITY_COMPONENT_ID,
                    CONTROL_IDENTITY_SCHEMA_VERSION,
                    CONTROL_IDENTITY_SCHEMA_CHECKSUM,
                    installed_at_us,
                    CONTROL_IDENTITY_WRITER_EPOCH,
                    CONTROL_IDENTITY_MINIMUM_WRITER_EPOCH,
                ),
            )
            callback("after_manifest_insert")
            connection.execute(
                """
                insert into control_job_identity (
                    job_id, identity_class, payload_digest_scheme_id,
                    admitted_job_jcs, writer_epoch
                )
                select job_id, ?, ?, null, ? from control_jobs
                """,
                (
                    LEGACY_IDENTITY_CLASS,
                    LEGACY_OPAQUE_DIGEST_SCHEME_ID,
                    CONTROL_IDENTITY_WRITER_EPOCH,
                ),
            )
            callback("after_job_classification")
            connection.execute(
                """
                insert into control_completion_identity (
                    job_id, identity_class, result_digest_scheme_id,
                    result_manifest_jcs, writer_epoch
                )
                select job_id, ?, ?, null, ? from control_jobs
                """,
                (
                    LEGACY_IDENTITY_CLASS,
                    LEGACY_OPAQUE_DIGEST_SCHEME_ID,
                    CONTROL_IDENTITY_WRITER_EPOCH,
                ),
            )
            callback("after_completion_classification")
            validate_control_identity_schema(connection)
            callback("after_target_validation")
            classified = connection.execute("select count(*) from control_jobs").fetchone()[0]
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

        if validate_control_identity_schema(connection) != "v1":
            raise ControlIdentitySchemaError("post-migration authoritative readback failed")
        return ControlIdentityMigrationReport(
            "migrated", classified, backup_bytes, CONTROL_IDENTITY_SCHEMA_CHECKSUM
        )


def restore_legacy_control_identity_backup(
    database_path: str | Path,
    backup_path: str | Path,
    *,
    max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
    failure_injector: Callable[[str], None] | None = None,
) -> None:
    """Atomically restore exact legacy rows only before any v1 identity exists."""

    database = _require_database_path(database_path)
    backup = _require_existing_backup_path(database, backup_path)
    _require_size_cap(max_database_bytes)
    callback = failure_injector or _no_failure
    if not callable(callback):
        raise TypeError("failure_injector must be callable")

    with _open_database(backup, read_only=True) as source:
        source.execute("begin")
        if validate_control_identity_schema(source) != "legacy":
            raise ControlIdentitySchemaError("rollback source is not exact legacy schema")
        _require_bounded_database(source, backup, max_database_bytes)
        backup_digest = _logical_digest(source)

        with _open_database(database) as destination:
            _checkpoint_wal(destination)
            attached = False
            try:
                destination.execute("begin exclusive")
                if validate_control_identity_schema(destination) != "v1":
                    raise ControlIdentitySchemaError("rollback destination is not exact v1 schema")
                _require_bounded_database(destination, database, max_database_bytes)
                if _has_versioned_identity(destination):
                    raise ControlIdentityDowngradeError(
                        "v1 identity exists; downgrade is refused and forward repair is required"
                    )
                callback("under_exclusive_lock_before_restore")
                destination.execute(
                    "attach database ? as legacy_backup",
                    (f"{backup.as_uri()}?mode=ro",),
                )
                attached = True
                _validate_attached_legacy_schema(destination)
                _restore_legacy_rows_under_lock(destination, callback)
                callback("after_restore_validation")
                if _logical_digest(destination) != backup_digest:
                    raise ControlIdentitySchemaError(
                        "restored database does not match verified backup"
                    )
                destination.commit()
            except BaseException:
                destination.rollback()
                raise
            finally:
                if attached:
                    destination.execute("detach database legacy_backup")
        source.rollback()

    with _open_database(database) as restored:
        _checkpoint_wal(restored)
        if validate_control_identity_schema(restored) != "legacy":
            raise ControlIdentitySchemaError("restored database is not exact legacy schema")
        if _logical_digest(restored) != backup_digest:
            raise ControlIdentitySchemaError("restored database does not match verified backup")


def _restore_legacy_rows_under_lock(
    connection: sqlite3.Connection, callback: Callable[[str], None]
) -> None:
    if not connection.in_transaction:
        raise ControlIdentitySchemaError("legacy restore requires the exclusive transaction")

    trigger_rows = connection.execute(
        """
        select name, sql from legacy_backup.sqlite_master
        where type = 'trigger'
        order by name
        """
    ).fetchall()
    if {row[0] for row in trigger_rows} != set(_BASE_TRIGGER_NAMES):
        raise ControlIdentitySchemaError("rollback source trigger set is invalid")

    for trigger in _IDENTITY_TRIGGER_NAMES:
        connection.execute(f"drop trigger {trigger}")
    for table in (
        "control_completion_identity",
        "control_job_identity",
        "control_component_schema",
    ):
        connection.execute(f"drop table {table}")
    for trigger in _BASE_TRIGGER_NAMES:
        connection.execute(f"drop trigger {trigger}")
    callback("after_identity_schema_removal")

    for table in _RESTORE_DELETE_ORDER:
        connection.execute(f"delete from {table}")
    for table in _RESTORE_INSERT_ORDER:
        columns = ", ".join(_RESTORE_COLUMNS[table])
        connection.execute(
            f"insert into {table} ({columns}) select {columns} from legacy_backup.{table}"
        )

    placeholders = ", ".join("?" for _ in _AUTOINCREMENT_TABLES)
    connection.execute(
        f"delete from sqlite_sequence where name in ({placeholders})",
        _AUTOINCREMENT_TABLES,
    )
    connection.execute(
        f"""
        insert into sqlite_sequence (name, seq)
        select name, seq from legacy_backup.sqlite_sequence
        where name in ({placeholders})
        """,
        _AUTOINCREMENT_TABLES,
    )
    application_id = connection.execute("pragma legacy_backup.application_id").fetchone()[0]
    user_version = connection.execute("pragma legacy_backup.user_version").fetchone()[0]
    connection.execute(f"pragma application_id = {int(application_id)}")
    connection.execute(f"pragma user_version = {int(user_version)}")

    for _name, trigger_sql in trigger_rows:
        if not isinstance(trigger_sql, str):
            raise ControlIdentitySchemaError("rollback source trigger SQL is unavailable")
        connection.execute(trigger_sql)

    callback("after_legacy_data_copy")

    _validate_database_health(connection)
    if validate_control_identity_schema(connection) != "legacy":
        raise ControlIdentitySchemaError("transactional legacy restore validation failed")


def _validate_legacy_rows(connection: sqlite3.Connection, *, schema: str = "main") -> None:
    _require_schema_name(schema)
    bad_key = connection.execute(
        f"""
        select 1 from {schema}.control_jobs
        where typeof(job_id) != 'text' or length(job_id) = 0
        limit 1
        """
    ).fetchone()
    if bad_key is not None:
        raise ControlIdentitySchemaError("legacy control job identity is invalid")


def _validate_target_rows(connection: sqlite3.Connection) -> None:
    if hashlib.sha256(CONTROL_IDENTITY_SCHEMA_MANIFEST.encode()).hexdigest() != (
        CONTROL_IDENTITY_SCHEMA_CHECKSUM
    ):
        raise ControlIdentitySchemaError("control identity manifest checksum is invalid")
    rows = connection.execute(
        """
        select component_id, schema_version, schema_checksum, installed_at_us,
               writer_epoch, minimum_writer_epoch
        from control_component_schema
        """
    ).fetchall()
    if len(rows) != 1:
        raise ControlIdentitySchemaError("control identity requires one manifest row")
    component, version, checksum, installed, writer_epoch, minimum_writer = rows[0]
    if (
        component != CONTROL_IDENTITY_COMPONENT_ID
        or type(version) is not int
        or version != CONTROL_IDENTITY_SCHEMA_VERSION
        or checksum != CONTROL_IDENTITY_SCHEMA_CHECKSUM
        or type(installed) is not int
        or type(writer_epoch) is not int
        or writer_epoch != CONTROL_IDENTITY_WRITER_EPOCH
        or type(minimum_writer) is not int
        or minimum_writer != CONTROL_IDENTITY_MINIMUM_WRITER_EPOCH
        or writer_epoch != minimum_writer
    ):
        raise ControlIdentitySchemaError("control identity manifest row is invalid")

    parent_ids = {row[0] for row in connection.execute("select job_id from control_jobs")}
    job_ids = {row[0] for row in connection.execute("select job_id from control_job_identity")}
    completion_ids = {
        row[0] for row in connection.execute("select job_id from control_completion_identity")
    }
    if parent_ids != job_ids or parent_ids != completion_ids:
        raise ControlIdentitySchemaError("identity sidecars do not map one-to-one to control jobs")

    job_rows = connection.execute(
        """
        select j.payload_digest, i.identity_class, i.payload_digest_scheme_id,
               i.admitted_job_jcs, i.writer_epoch
        from control_jobs j join control_job_identity i using (job_id)
        """
    ).fetchall()
    for projection, identity_class, scheme, canonical, row_epoch in job_rows:
        _validate_row_epoch(row_epoch, minimum_writer, writer_epoch)
        if identity_class == LEGACY_IDENTITY_CLASS:
            if scheme != LEGACY_OPAQUE_DIGEST_SCHEME_ID or canonical is not None or row_epoch != 1:
                raise ControlIdentitySchemaError("legacy payload identity classification drift")
        elif identity_class == VERSIONED_IDENTITY_CLASS:
            if (
                scheme != PAYLOAD_DIGEST_SCHEME_ID
                or type(canonical) is not bytes
                or not canonical
                or projection != hashlib.sha256(_PAYLOAD_PREFIX + canonical).hexdigest()
            ):
                raise ControlIdentitySchemaError("v1 payload projection is invalid")
        else:
            raise ControlIdentitySchemaError("unknown payload identity class")

    result_rows = connection.execute(
        """
        select j.state, j.completion_result_digest, i.identity_class,
               i.result_digest_scheme_id, i.result_manifest_jcs, i.writer_epoch
        from control_jobs j join control_completion_identity i using (job_id)
        """
    ).fetchall()
    for state, projection, identity_class, scheme, canonical, row_epoch in result_rows:
        _validate_row_epoch(row_epoch, minimum_writer, writer_epoch)
        if identity_class == LEGACY_IDENTITY_CLASS:
            if scheme != LEGACY_OPAQUE_DIGEST_SCHEME_ID or canonical is not None or row_epoch != 1:
                raise ControlIdentitySchemaError("legacy result identity classification drift")
        elif identity_class == VERSIONED_IDENTITY_CLASS:
            if (
                state != "completed"
                or scheme != RESULT_DIGEST_SCHEME_ID
                or type(canonical) is not bytes
                or not canonical
                or projection != hashlib.sha256(_RESULT_PREFIX + canonical).hexdigest()
            ):
                raise ControlIdentitySchemaError("v1 result projection is invalid")
        else:
            raise ControlIdentitySchemaError("unknown result identity class")


def _validate_row_epoch(row_epoch: object, minimum: int, current: int) -> None:
    if (
        type(row_epoch) is not int
        or row_epoch != CONTROL_IDENTITY_WRITER_EPOCH
        or minimum != CONTROL_IDENTITY_MINIMUM_WRITER_EPOCH
        or current != CONTROL_IDENTITY_WRITER_EPOCH
    ):
        raise ControlIdentitySchemaError("identity writer epoch is outside compatibility seal")


def _has_versioned_identity(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            """
        select 1 from control_job_identity
        where identity_class = ? or admitted_job_jcs is not null
        union all
        select 1 from control_completion_identity
        where identity_class = ? or result_manifest_jcs is not null
        limit 1
        """,
            (VERSIONED_IDENTITY_CLASS, VERSIONED_IDENTITY_CLASS),
        ).fetchone()
        is not None
    )


def _validate_database_health(connection: sqlite3.Connection, *, schema: str = "main") -> None:
    _require_schema_name(schema)
    integrity = connection.execute(f"pragma {schema}.integrity_check").fetchall()
    if integrity != [("ok",)]:
        raise ControlIdentitySchemaError("SQLite integrity_check failed")
    if connection.execute(f"pragma {schema}.foreign_key_check").fetchall():
        raise ControlIdentitySchemaError("SQLite foreign_key_check failed")


def _checkpoint_wal(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        raise ControlIdentitySchemaError("WAL checkpoint requires an idle connection")
    row = connection.execute("pragma wal_checkpoint(truncate)").fetchone()
    if row is None or row[0] != 0:
        raise ControlIdentitySchemaError("bounded WAL checkpoint could not complete")


def _create_verified_backup(
    source: sqlite3.Connection,
    backup_path: Path,
    *,
    expected_digest: str,
    max_database_bytes: int,
) -> int:
    if backup_path.exists() or backup_path.is_symlink():
        raise ControlIdentitySchemaError("backup path must not already exist")
    if not backup_path.parent.is_dir() or backup_path.parent.is_symlink():
        raise ControlIdentitySchemaError("backup parent must be an existing real directory")
    try:
        with sqlite3.connect(backup_path, isolation_level=None) as destination:
            source.backup(destination, pages=256)
        if backup_path.is_symlink() or not backup_path.is_file():
            raise ControlIdentitySchemaError("backup is not a regular file")
        backup_bytes = backup_path.stat().st_size
        if backup_bytes < 1 or backup_bytes > max_database_bytes:
            raise ControlIdentitySchemaError("backup violates the bounded size policy")
        with _open_database(backup_path, read_only=True) as verified:
            if validate_control_identity_schema(verified) != "legacy":
                raise ControlIdentitySchemaError("backup schema verification failed")
            _require_bounded_database(verified, backup_path, max_database_bytes)
            if _logical_digest(verified) != expected_digest:
                raise ControlIdentitySchemaError("backup logical verification failed")
        return backup_bytes
    except BaseException as error:
        if isinstance(error, ControlIdentitySchemaError):
            raise
        raise ControlIdentitySchemaError("bounded SQLite backup failed") from error


def _logical_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    _digest_value(digest, connection.execute("pragma application_id").fetchone()[0])
    _digest_value(digest, connection.execute("pragma user_version").fetchone()[0])
    catalog = sorted(_controlled_catalog(connection), key=repr)
    for item in catalog:
        for value in item:
            _digest_value(digest, value)
    tables = sorted(name for object_type, name, _table, _sql in catalog if object_type == "table")
    try:
        for table in tables:
            _digest_value(digest, table)
            rows = connection.execute(f'select * from "{table}"').fetchall()
            encoded_rows = sorted(_encode_row(row) for row in rows)
            for row in encoded_rows:
                digest.update(row)
    except (UnicodeError, sqlite3.Error) as error:
        raise ControlIdentitySchemaError("database cannot be logically verified") from error
    return digest.hexdigest()


def _encode_row(row: tuple[object, ...]) -> bytes:
    digest = hashlib.sha256()
    for value in row:
        _digest_value(digest, value)
    return digest.digest()


def _digest_value(digest: _Digest, value: object) -> None:
    if value is None:
        payload = b""
        tag = b"n"
    elif type(value) is int:
        payload = str(value).encode("ascii")
        tag = b"i"
    elif type(value) is float:
        payload = value.hex().encode("ascii")
        tag = b"f"
    elif type(value) is str:
        payload = value.encode("utf-8")
        tag = b"t"
    elif isinstance(value, bytes):
        payload = bytes(value)
        tag = b"b"
    else:
        raise ControlIdentitySchemaError("database contains an unsupported SQLite value")
    digest.update(tag)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def _require_bounded_database(
    connection: sqlite3.Connection,
    path: Path,
    maximum: int,
) -> None:
    page_size = connection.execute("pragma page_size").fetchone()[0]
    page_count = connection.execute("pragma page_count").fetchone()[0]
    freelist = connection.execute("pragma freelist_count").fetchone()[0]
    if (
        type(page_size) is not int
        or type(page_count) is not int
        or type(freelist) is not int
        or page_size <= 0
        or page_count <= 0
        or freelist < 0
        or page_count * page_size > maximum
        or path.stat().st_size > maximum
    ):
        raise ControlIdentitySchemaError("database violates the bounded backup policy")


@lru_cache(maxsize=1)
def _expected_catalogs() -> tuple[
    frozenset[frozenset[tuple[str, str, str, str | None]]],
    frozenset[frozenset[tuple[str, str, str, str | None]]],
]:
    legacy_sql = _read_verified_sql(_legacy_sql_path(), LEGACY_CONTROL_SQL_SHA256)
    migration_sql = _read_verified_sql(_migration_sql_path(), CONTROL_IDENTITY_MIGRATION_SQL_SHA256)
    with sqlite3.connect(":memory:") as connection:
        connection.execute("pragma foreign_keys = on")
        connection.executescript(legacy_sql)
        legacy = _controlled_catalog(connection)
        for statement in _split_sql(migration_sql):
            connection.execute(statement)
        target = _controlled_catalog(connection)
    alternate_legacy = _with_alternate_review_events(legacy)
    alternate_target = _with_alternate_review_events(target)
    return frozenset((legacy, alternate_legacy)), frozenset((target, alternate_target))


def _with_alternate_review_events(
    catalog: frozenset[tuple[str, str, str, str | None]],
) -> frozenset[tuple[str, str, str, str | None]]:
    replaced = {item for item in catalog if not (item[0] == "table" and item[1] == "review_events")}
    replaced.add(
        (
            "table",
            "review_events",
            "review_events",
            _normalize_sql(_ALTERNATE_REVIEW_EVENTS_SQL),
        )
    )
    return frozenset(replaced)


def _validate_expected_facts(
    connection: sqlite3.Connection, *, target: bool, schema: str = "main"
) -> None:
    _require_schema_name(schema)
    expected = _expected_facts(target)
    for table, facts in expected.items():
        if _table_facts(connection, table, schema=schema) != facts:
            raise ControlIdentitySchemaError(f"controlled table/index/FK drift: {table}")


@lru_cache(maxsize=2)
def _expected_facts(target: bool) -> dict[str, tuple[object, ...]]:
    legacy_sql = _read_verified_sql(_legacy_sql_path(), LEGACY_CONTROL_SQL_SHA256)
    with sqlite3.connect(":memory:") as connection:
        connection.execute("pragma foreign_keys = on")
        connection.executescript(legacy_sql)
        if target:
            for statement in _migration_statements():
                connection.execute(statement)
        tables = _KNOWN_TABLES if target else _BASE_TABLES
        return {table: _table_facts(connection, table) for table in tables}


def _table_facts(
    connection: sqlite3.Connection, table: str, *, schema: str = "main"
) -> tuple[object, ...]:
    _require_schema_name(schema)
    xinfo = tuple(
        tuple(row) for row in connection.execute(f"pragma {schema}.table_xinfo('{table}')")
    )
    index_list = tuple(
        sorted(
            tuple(row[1:]) for row in connection.execute(f"pragma {schema}.index_list('{table}')")
        )
    )
    indexes = tuple(
        (
            row[0],
            tuple(
                tuple(value)
                for value in connection.execute(f"pragma {schema}.index_xinfo('{row[0]}')")
            ),
        )
        for row in index_list
    )
    foreign_keys = tuple(
        tuple(row) for row in connection.execute(f"pragma {schema}.foreign_key_list('{table}')")
    )
    return xinfo, index_list, indexes, foreign_keys


def _controlled_catalog(
    connection: sqlite3.Connection, *, schema: str = "main"
) -> frozenset[tuple[str, str, str, str | None]]:
    _require_schema_name(schema)
    rows = connection.execute(
        f"select type, name, tbl_name, sql from {schema}.sqlite_master"
    ).fetchall()
    return frozenset(
        (object_type, name, table, _normalize_sql(sql) if sql else None)
        for object_type, name, table, sql in rows
    )


def _require_schema_name(schema: str) -> None:
    if schema not in {"main", "legacy_backup"}:
        raise ControlIdentitySchemaError("unapproved SQLite schema name")


def _normalize_sql(sql: str) -> str:
    collapsed = _SPACE.sub(" ", sql.strip().rstrip(";")).casefold()
    return _PUNCTUATION_SPACE.sub(r"\1", collapsed)


@lru_cache(maxsize=1)
def _migration_statements() -> tuple[str, ...]:
    statements = tuple(
        _split_sql(_read_verified_sql(_migration_sql_path(), CONTROL_IDENTITY_MIGRATION_SQL_SHA256))
    )
    if len(statements) != len(_DDL_FAILURE_STEPS):
        raise ControlIdentitySchemaError(
            "migration SQL does not match the exact governed DDL statement count"
        )
    return statements


def _split_sql(script: str) -> Iterator[str]:
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement:
                yield statement
            pending = ""
    if pending.strip():
        raise ControlIdentitySchemaError("migration SQL has an incomplete statement")


def _verify_static_checksums() -> None:
    if hashlib.sha256(CONTROL_IDENTITY_SCHEMA_MANIFEST.encode()).hexdigest() != (
        CONTROL_IDENTITY_SCHEMA_CHECKSUM
    ):
        raise ControlIdentitySchemaError("compiled control identity manifest drift")
    _read_verified_sql(_migration_sql_path(), CONTROL_IDENTITY_MIGRATION_SQL_SHA256)
    _read_verified_sql(_legacy_sql_path(), LEGACY_CONTROL_SQL_SHA256)


def _read_verified_sql(path: Path, checksum: str) -> str:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ControlIdentitySchemaError("required schema SQL is unavailable") from error
    if hashlib.sha256(payload).hexdigest() != checksum:
        raise ControlIdentitySchemaError("required schema SQL checksum mismatch")
    try:
        return payload.decode("utf-8")
    except UnicodeError as error:
        raise ControlIdentitySchemaError("required schema SQL is not UTF-8") from error


def _api_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _migration_sql_path() -> Path:
    return _api_root() / "sql" / "0003_processing_job_v2_control_identity.sql"


def _legacy_sql_path() -> Path:
    return _api_root() / "sql" / "0002_control_plane.sql"


def _require_foreign_keys(connection: sqlite3.Connection) -> None:
    row = connection.execute("pragma foreign_keys").fetchone()
    if row is None or row[0] != 1:
        raise ControlIdentitySchemaError("SQLite foreign-key enforcement must be enabled")


@contextmanager
def _open_database(path: Path, *, read_only: bool = False) -> Iterator[sqlite3.Connection]:
    mode = "ro" if read_only else "rw"
    uri = f"{path.as_uri()}?mode={mode}"
    connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=5.0)
    try:
        connection.execute("pragma foreign_keys = on")
        connection.execute("pragma busy_timeout = 5000")
        if not read_only:
            connection.execute("pragma synchronous = full")
        yield connection
    except sqlite3.Error as error:
        raise ControlIdentitySchemaError("SQLite operation failed closed") from error
    finally:
        connection.close()


def _require_database_path(value: str | Path) -> Path:
    path = Path(os.path.abspath(Path(value)))
    _require_no_symlink_components(path)
    if not path.is_file():
        raise ControlIdentitySchemaError("database path must be an existing regular file")
    return path


def _require_distinct_backup_path(database: Path, value: str | Path) -> Path:
    backup = Path(os.path.abspath(Path(value)))
    _require_no_symlink_components(backup)
    if backup == database:
        raise ControlIdentitySchemaError("backup path must differ from database path")
    return backup


def _require_existing_backup_path(database: Path, value: str | Path) -> Path:
    backup = Path(os.path.abspath(Path(value)))
    _require_no_symlink_components(backup)
    if not backup.is_file():
        raise ControlIdentitySchemaError("backup path must be an existing regular file")
    if backup == database:
        raise ControlIdentitySchemaError("backup path must differ from database path")
    return backup


def _require_no_symlink_components(path: Path) -> None:
    current = path
    while True:
        if current.is_symlink():
            raise ControlIdentitySchemaError("database and backup paths must not use symlinks")
        if current.parent == current:
            return
        current = current.parent


def _require_signed_int64(value: object, name: str) -> None:
    if type(value) is not int or not -(2**63) <= value < 2**63:
        raise ValueError(f"{name} must be a signed 64-bit integer")


def _require_size_cap(value: object) -> None:
    if type(value) is not int or not 4096 <= value <= DEFAULT_MAX_DATABASE_BYTES:
        raise ValueError(
            f"max_database_bytes must be between 4096 and {DEFAULT_MAX_DATABASE_BYTES}"
        )


def _no_failure(_step: str) -> None:
    return None
