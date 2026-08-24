"""Canonical SQLite schema ownership for the shared append-only audit log."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping

from .legacy_session_schema import (
    LegacySessionSchemaError,
    validate_legacy_session_schema,
)

CONTROL_AUDIT_ACTIONS = frozenset(
    {
        "job.register",
        "job.acquire",
        "job.heartbeat",
        "job.complete",
        "review.append",
        "review.read",
        "audit.read",
    }
)
RETENTION_AUDIT_ACTIONS = frozenset(
    {
        "retention.register",
        "retention.read",
        "retention.hold",
        "retention.stage_trash",
        "retention.attest_delete",
    }
)
SHARED_AUDIT_ACTIONS = CONTROL_AUDIT_ACTIONS | RETENTION_AUDIT_ACTIONS

CONTROL_AUDIT_ROLES = frozenset(
    {"deterministic_worker", "reviewer", "audit_reader"}
)
SHARED_AUDIT_ROLES = CONTROL_AUDIT_ROLES | {"retention_steward"}

AUDIT_TABLE_SQL = """
create table audit_events (
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
)
"""

LEGACY_CONTROL_AUDIT_TABLE_SQL = """
create table audit_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    correlation_id text not null,
    idempotency_key text,
    subject_id text not null,
    roles_json text not null,
    action text not null check (action in (
        'job.register', 'job.acquire', 'job.heartbeat', 'job.complete',
        'review.append', 'review.read', 'audit.read'
    )),
    target_id text not null,
    result text not null check (result in ('accepted', 'denied')),
    occurred_at integer not null
)
"""

AUDIT_SEQUENCE_INDEX_SQL = """
create index audit_events_sequence_idx on audit_events (sequence)
"""

AUDIT_NO_UPDATE_TRIGGER_SQL = """
create trigger audit_events_no_update
before update on audit_events
begin
    select raise(abort, 'audit events are immutable');
end
"""

AUDIT_NO_DELETE_TRIGGER_SQL = """
create trigger audit_events_no_delete
before delete on audit_events
begin
    select raise(abort, 'audit events are immutable');
end
"""

AUDIT_SCHEMA_SQL = (
    AUDIT_TABLE_SQL,
    AUDIT_SEQUENCE_INDEX_SQL,
    AUDIT_NO_UPDATE_TRIGGER_SQL,
    AUDIT_NO_DELETE_TRIGGER_SQL,
)

_EXPECTED_OBJECT_NAMES = frozenset(
    {
        "audit_events",
        "audit_events_sequence_idx",
        "audit_events_no_update",
        "audit_events_no_delete",
    }
)
_SPACE = re.compile(r"\s+")
_PUNCTUATION_SPACE = re.compile(r"\s*([(),])\s*")


class AuditSchemaError(RuntimeError):
    """The existing shared audit schema is absent from a non-empty DB or drifted."""


def ensure_shared_audit_schema(
    connection: sqlite3.Connection,
    *,
    allow_legacy_control_schema: bool,
) -> str:
    """Create the canonical schema in an empty DB or validate an existing one.

    Exact expanded schemas are always accepted without writes. The exact legacy
    control-only schema is accepted only for ControlStore compatibility; it is
    never widened or repaired.
    """

    relevant = _relevant_objects(connection)
    table = relevant.get(("table", "audit_events"))
    if table is None:
        if _database_has_user_schema(connection):
            try:
                validate_legacy_session_schema(connection, require_exclusive=True)
            except LegacySessionSchemaError as error:
                raise AuditSchemaError(
                    "shared audit schema is missing from an incompatible non-empty database"
                ) from error
        for statement in AUDIT_SCHEMA_SQL:
            connection.execute(statement)
        return "created"

    signature = _normalized_signature(relevant)
    if signature == _expected_signature(AUDIT_TABLE_SQL):
        return "expanded"
    if signature == _expected_signature(LEGACY_CONTROL_AUDIT_TABLE_SQL):
        if allow_legacy_control_schema:
            return "legacy_control"
        raise AuditSchemaError(
            "legacy control-only audit schema is incompatible with retention"
        )
    raise AuditSchemaError("shared audit schema does not match an approved definition")


def normalized_audit_schema(connection: sqlite3.Connection) -> Mapping[str, str]:
    """Return the normalized persistent audit objects for hermetic verification."""

    return {
        f"{object_type}:{name}": sql
        for (object_type, name), sql in sorted(
            _normalized_signature(_relevant_objects(connection)).items()
        )
    }


def _database_has_user_schema(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            """
            select 1 from sqlite_master
            where name not like 'sqlite_%' and sql is not null
            limit 1
            """
        ).fetchone()
        is not None
    )


def _relevant_objects(
    connection: sqlite3.Connection,
) -> dict[tuple[str, str], str]:
    placeholders = ", ".join("?" for _ in _EXPECTED_OBJECT_NAMES)
    rows = connection.execute(
        f"""
        select type, name, tbl_name, sql from sqlite_master
        where sql is not null
          and (name in ({placeholders}) or tbl_name = 'audit_events')
        order by type, name
        """,
        tuple(sorted(_EXPECTED_OBJECT_NAMES)),
    ).fetchall()
    return {(row[0], row[1]): row[3] for row in rows}


def _normalized_signature(
    objects: Mapping[tuple[str, str], str],
) -> dict[tuple[str, str], str]:
    return {key: _normalize_sql(sql) for key, sql in objects.items()}


def _expected_signature(table_sql: str) -> dict[tuple[str, str], str]:
    return {
        ("table", "audit_events"): _normalize_sql(table_sql),
        ("index", "audit_events_sequence_idx"): _normalize_sql(
            AUDIT_SEQUENCE_INDEX_SQL
        ),
        ("trigger", "audit_events_no_update"): _normalize_sql(
            AUDIT_NO_UPDATE_TRIGGER_SQL
        ),
        ("trigger", "audit_events_no_delete"): _normalize_sql(
            AUDIT_NO_DELETE_TRIGGER_SQL
        ),
    }


def _normalize_sql(sql: str) -> str:
    collapsed = _SPACE.sub(" ", sql.strip().rstrip(";")).casefold()
    return _PUNCTUATION_SPACE.sub(r"\1", collapsed)
