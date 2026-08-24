"""Exact SQLite schema facts for the ADR 0009 legacy-session component.

This leaf module deliberately has no dependency on any store or on the shared
audit schema.  It can install the component in a hermetic SQLite file and can
validate the component without changing the connection or database.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Mapping

LEGACY_SESSION_COMPONENT_ID = "workflow-helper.legacy-session-security"
LEGACY_SESSION_SCHEMA_VERSION = 1
LEGACY_SESSION_RECORD_CONTRACT_VERSION = "1.0"
LEGACY_SESSION_SCHEMA_MANIFEST = (
    "legacy-session-security/v1|legacy_session_component_schema:component_id,"
    "schema_version,schema_checksum,installed_at_us|legacy_sessions:session_id,"
    "tenant_id,workspace_id,capture_owner_subject,record_contract_version,machine_id,"
    "project_id,started_at_us,ended_at_us,active_duration_seconds,approved_process,"
    "package_sha256,package_size_bytes,processing_status,review_status,raw_object_key,"
    "processed_prefix,processing_output_json,processing_completion_id,"
    "processing_completed_at_us,raw_expires_at_us,state_version,created_at_us,"
    "updated_at_us|legacy_session_events:sequence,event_id,session_id,tenant_id,"
    "workspace_id,capture_owner_subject,event_type,from_state,to_state,state_version,"
    "actor_subject,actor_role,idempotency_key,request_digest,detail_json,occurred_at_us|"
    "legacy_workload_principals:principal_subject,tenant_id,workspace_id,audience,role,"
    "transport,active_generation,revoked_at_us,state_version,created_at_us,updated_at_us|"
    "legacy_workload_proof_claims:proof_identifier_digest,principal_subject,tenant_id,"
    "workspace_id,audience,role,transport,generation,method,canonical_path,body_sha256,"
    "issued_at_us,expires_at_us,claimed_at_us,retain_until_us"
)
LEGACY_SESSION_SCHEMA_CHECKSUM = "d660e0586b3672d530cb751972ef88deead9f74863094a8b1b5882c87f591550"

LEGACY_SESSION_TABLE_SQL = (
    """
    create table legacy_session_component_schema (
        component_id text primary key,
        schema_version integer not null,
        schema_checksum text not null,
        installed_at_us integer not null
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
)

LEGACY_SESSION_INDEX_SQL = (
    """create index legacy_sessions_scope_started_idx
       on legacy_sessions (tenant_id, workspace_id, started_at_us desc, session_id)""",
    """create index legacy_sessions_owner_idx
       on legacy_sessions (tenant_id, workspace_id, capture_owner_subject, session_id)""",
    """create index legacy_sessions_scope_processing_idx
       on legacy_sessions
          (tenant_id, workspace_id, processing_status, updated_at_us, session_id)""",
    """create index legacy_sessions_raw_expiry_idx
       on legacy_sessions (raw_expires_at_us, session_id)""",
    """create unique index legacy_session_events_idempotency_idx
       on legacy_session_events (session_id, event_type, idempotency_key)
       where idempotency_key is not null""",
    """create index legacy_session_events_scope_sequence_idx
       on legacy_session_events (tenant_id, workspace_id, session_id, sequence)""",
    """create index legacy_workload_principals_scope_idx
       on legacy_workload_principals
          (tenant_id, workspace_id, audience, principal_subject)""",
    """create index legacy_workload_proof_claims_retention_idx
       on legacy_workload_proof_claims (retain_until_us, proof_identifier_digest)""",
    """create index legacy_workload_proof_claims_principal_idx
       on legacy_workload_proof_claims
          (principal_subject, tenant_id, workspace_id, audience, claimed_at_us)""",
)

LEGACY_SESSION_TRIGGER_SQL = (
    """
    create trigger legacy_session_events_no_update
    before update on legacy_session_events
    begin
        select raise(abort, 'legacy session events are immutable');
    end
    """,
    """
    create trigger legacy_session_events_no_delete
    before delete on legacy_session_events
    begin
        select raise(abort, 'legacy session events are immutable');
    end
    """,
    """
    create trigger legacy_workload_proof_claims_no_update
    before update on legacy_workload_proof_claims
    begin
        select raise(abort, 'legacy workload proof claims are immutable');
    end
    """,
)

LEGACY_SESSION_SCHEMA_SQL = (
    *LEGACY_SESSION_TABLE_SQL,
    *LEGACY_SESSION_INDEX_SQL,
    *LEGACY_SESSION_TRIGGER_SQL,
)

_TABLE_NAMES = (
    "legacy_session_component_schema",
    "legacy_sessions",
    "legacy_session_events",
    "legacy_workload_principals",
    "legacy_workload_proof_claims",
)
_INDEX_NAMES = (
    "legacy_sessions_scope_started_idx",
    "legacy_sessions_owner_idx",
    "legacy_sessions_scope_processing_idx",
    "legacy_sessions_raw_expiry_idx",
    "legacy_session_events_idempotency_idx",
    "legacy_session_events_scope_sequence_idx",
    "legacy_workload_principals_scope_idx",
    "legacy_workload_proof_claims_retention_idx",
    "legacy_workload_proof_claims_principal_idx",
)
_TRIGGER_NAMES = (
    "legacy_session_events_no_update",
    "legacy_session_events_no_delete",
    "legacy_workload_proof_claims_no_update",
)
_RESERVED_NAMES = frozenset((*_TABLE_NAMES, *_INDEX_NAMES, *_TRIGGER_NAMES))

_SPACE = re.compile(r"\s+")
_PUNCTUATION_SPACE = re.compile(r"\s*([(),])\s*")


class LegacySessionSchemaError(RuntimeError):
    """The ADR 0009 component schema is absent, partial, or drifted."""


def initialize_legacy_session_schema(
    connection: sqlite3.Connection,
    *,
    installed_at_us: int,
) -> str:
    """Atomically create or validate the exact ADR 0009 v1 component schema.

    The connection must not already have a transaction.  Existing unrelated
    component objects are left untouched; any legacy-component presence is
    treated as an exact-schema claim and validated rather than repaired.
    """

    if connection.in_transaction:
        raise LegacySessionSchemaError("legacy schema initialization needs an idle connection")
    _require_foreign_keys(connection)
    if (
        not isinstance(installed_at_us, int)
        or isinstance(installed_at_us, bool)
        or not -(2**63) <= installed_at_us < 2**63
    ):
        raise ValueError("installed_at_us must be a signed 64-bit integer")

    try:
        connection.execute("begin immediate")
        if _component_objects(connection):
            validate_legacy_session_schema(connection)
            result = "existing"
        else:
            for statement in LEGACY_SESSION_SCHEMA_SQL:
                connection.execute(statement)
            connection.execute(
                """
                insert into legacy_session_component_schema (
                    component_id, schema_version, schema_checksum, installed_at_us
                ) values (?, ?, ?, ?)
                """,
                (
                    LEGACY_SESSION_COMPONENT_ID,
                    LEGACY_SESSION_SCHEMA_VERSION,
                    LEGACY_SESSION_SCHEMA_CHECKSUM,
                    installed_at_us,
                ),
            )
            validate_legacy_session_schema(connection)
            result = "created"
        connection.commit()
        return result
    except BaseException:
        connection.rollback()
        raise


def validate_legacy_session_schema(
    connection: sqlite3.Connection,
    *,
    require_exclusive: bool = False,
) -> None:
    """Validate the exact v1 schema using read-only catalog and pragma queries."""

    _require_foreign_keys(connection)
    if _manifest_checksum() != LEGACY_SESSION_SCHEMA_CHECKSUM:
        raise LegacySessionSchemaError("legacy schema manifest checksum is invalid")
    if _component_objects(connection) != _expected_component_objects():
        raise LegacySessionSchemaError("legacy session sqlite_master objects do not match v1")
    if require_exclusive and _all_user_objects(connection) != _expected_exclusive_objects():
        raise LegacySessionSchemaError("database is not an exclusive legacy v1 schema")

    for table_name, expected in _EXPECTED_TABLE_XINFO.items():
        if _table_xinfo(connection, table_name) != expected:
            raise LegacySessionSchemaError(f"legacy table shape drift: {table_name}")
    for table_name, expected in _EXPECTED_INDEX_LIST.items():
        if _index_list(connection, table_name) != expected:
            raise LegacySessionSchemaError(f"legacy index set drift: {table_name}")
    for index_name, expected in _EXPECTED_INDEX_XINFO.items():
        if _index_xinfo(connection, index_name) != expected:
            raise LegacySessionSchemaError(f"legacy index shape drift: {index_name}")
    for table_name, expected in _EXPECTED_FOREIGN_KEYS.items():
        if _foreign_keys(connection, table_name) != expected:
            raise LegacySessionSchemaError(f"legacy foreign key drift: {table_name}")
    if connection.execute("pragma foreign_key_check").fetchall():
        raise LegacySessionSchemaError("legacy foreign key check failed")

    rows = connection.execute(
        """
        select component_id, schema_version, schema_checksum, installed_at_us
        from legacy_session_component_schema
        """
    ).fetchall()
    if len(rows) != 1:
        raise LegacySessionSchemaError("legacy schema requires exactly one manifest row")
    component_id, version, checksum, installed_at_us = rows[0]
    if (
        component_id != LEGACY_SESSION_COMPONENT_ID
        or type(version) is not int
        or version != LEGACY_SESSION_SCHEMA_VERSION
        or checksum != _manifest_checksum()
        or type(installed_at_us) is not int
    ):
        raise LegacySessionSchemaError("legacy schema manifest row does not match v1")


def _require_foreign_keys(connection: sqlite3.Connection) -> None:
    row = connection.execute("pragma foreign_keys").fetchone()
    if row is None or row[0] != 1:
        raise LegacySessionSchemaError("SQLite foreign-key enforcement must be enabled")


def _manifest_checksum() -> str:
    return hashlib.sha256(LEGACY_SESSION_SCHEMA_MANIFEST.encode("utf-8")).hexdigest()


def _normalize_sql(sql: str) -> str:
    collapsed = _SPACE.sub(" ", sql.strip().rstrip(";")).casefold()
    return _PUNCTUATION_SPACE.sub(r"\1", collapsed)


def _component_objects(
    connection: sqlite3.Connection,
) -> frozenset[tuple[str, str, str, str | None]]:
    placeholders = ", ".join("?" for _ in _RESERVED_NAMES)
    table_placeholders = ", ".join("?" for _ in _TABLE_NAMES)
    rows = connection.execute(
        f"""
        select type, name, tbl_name, sql from sqlite_master
        where name in ({placeholders}) or tbl_name in ({table_placeholders})
        """,
        (*sorted(_RESERVED_NAMES), *_TABLE_NAMES),
    ).fetchall()
    return frozenset(
        (row[0], row[1], row[2], _normalize_sql(row[3]) if row[3] else None) for row in rows
    )


def _all_user_objects(
    connection: sqlite3.Connection,
) -> frozenset[tuple[str, str, str, str | None]]:
    rows = connection.execute(
        """
        select type, name, tbl_name, sql from sqlite_master
        where name not like 'sqlite_%'
        """
    ).fetchall()
    return frozenset(
        (row[0], row[1], row[2], _normalize_sql(row[3]) if row[3] else None) for row in rows
    )


def _expected_component_objects() -> frozenset[tuple[str, str, str, str | None]]:
    explicit: list[tuple[str, str, str, str | None]] = []
    for statement, name in zip(LEGACY_SESSION_TABLE_SQL, _TABLE_NAMES, strict=True):
        explicit.append(("table", name, name, _normalize_sql(statement)))
    index_tables = (
        "legacy_sessions",
        "legacy_sessions",
        "legacy_sessions",
        "legacy_sessions",
        "legacy_session_events",
        "legacy_session_events",
        "legacy_workload_principals",
        "legacy_workload_proof_claims",
        "legacy_workload_proof_claims",
    )
    for statement, name, table in zip(
        LEGACY_SESSION_INDEX_SQL, _INDEX_NAMES, index_tables, strict=True
    ):
        explicit.append(("index", name, table, _normalize_sql(statement)))
    trigger_tables = (
        "legacy_session_events",
        "legacy_session_events",
        "legacy_workload_proof_claims",
    )
    for statement, name, table in zip(
        LEGACY_SESSION_TRIGGER_SQL, _TRIGGER_NAMES, trigger_tables, strict=True
    ):
        explicit.append(("trigger", name, table, _normalize_sql(statement)))
    implicit = (
        (
            "index",
            "sqlite_autoindex_legacy_session_component_schema_1",
            "legacy_session_component_schema",
            None,
        ),
        ("index", "sqlite_autoindex_legacy_sessions_1", "legacy_sessions", None),
        ("index", "sqlite_autoindex_legacy_sessions_2", "legacy_sessions", None),
        ("index", "sqlite_autoindex_legacy_sessions_3", "legacy_sessions", None),
        ("index", "sqlite_autoindex_legacy_sessions_4", "legacy_sessions", None),
        ("index", "sqlite_autoindex_legacy_session_events_1", "legacy_session_events", None),
        ("index", "sqlite_autoindex_legacy_session_events_2", "legacy_session_events", None),
        (
            "index",
            "sqlite_autoindex_legacy_workload_principals_1",
            "legacy_workload_principals",
            None,
        ),
        (
            "index",
            "sqlite_autoindex_legacy_workload_proof_claims_1",
            "legacy_workload_proof_claims",
            None,
        ),
    )
    return frozenset((*explicit, *implicit))


def _expected_exclusive_objects() -> frozenset[tuple[str, str, str, str | None]]:
    return frozenset(
        object_signature
        for object_signature in _expected_component_objects()
        if not object_signature[1].startswith("sqlite_")
    )


def _table_xinfo(connection: sqlite3.Connection, table: str) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(f"pragma table_xinfo('{table}')"))


def _index_list(connection: sqlite3.Connection, table: str) -> frozenset[tuple[object, ...]]:
    return frozenset(tuple(row[1:]) for row in connection.execute(f"pragma index_list('{table}')"))


def _index_xinfo(connection: sqlite3.Connection, index: str) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(f"pragma index_xinfo('{index}')"))


def _foreign_keys(connection: sqlite3.Connection, table: str) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(f"pragma foreign_key_list('{table}')"))


def _columns(*items: tuple[str, str, int, object, int]) -> tuple[tuple[object, ...], ...]:
    return tuple((position, *item, 0) for position, item in enumerate(items))


_EXPECTED_TABLE_XINFO: Mapping[str, tuple[tuple[object, ...], ...]] = {
    "legacy_session_component_schema": _columns(
        ("component_id", "TEXT", 0, None, 1),
        ("schema_version", "INTEGER", 1, None, 0),
        ("schema_checksum", "TEXT", 1, None, 0),
        ("installed_at_us", "INTEGER", 1, None, 0),
    ),
    "legacy_sessions": _columns(
        ("session_id", "TEXT", 0, None, 1),
        ("tenant_id", "TEXT", 1, None, 0),
        ("workspace_id", "TEXT", 1, None, 0),
        ("capture_owner_subject", "TEXT", 1, None, 0),
        ("record_contract_version", "TEXT", 1, None, 0),
        ("machine_id", "TEXT", 1, None, 0),
        ("project_id", "TEXT", 0, None, 0),
        ("started_at_us", "INTEGER", 1, None, 0),
        ("ended_at_us", "INTEGER", 1, None, 0),
        ("active_duration_seconds", "INTEGER", 1, None, 0),
        ("approved_process", "TEXT", 1, None, 0),
        ("package_sha256", "TEXT", 1, None, 0),
        ("package_size_bytes", "INTEGER", 1, None, 0),
        ("processing_status", "TEXT", 1, None, 0),
        ("review_status", "TEXT", 1, None, 0),
        ("raw_object_key", "TEXT", 0, None, 0),
        ("processed_prefix", "TEXT", 0, None, 0),
        ("processing_output_json", "TEXT", 0, None, 0),
        ("processing_completion_id", "TEXT", 0, None, 0),
        ("processing_completed_at_us", "INTEGER", 0, None, 0),
        ("raw_expires_at_us", "INTEGER", 1, None, 0),
        ("state_version", "INTEGER", 1, None, 0),
        ("created_at_us", "INTEGER", 1, None, 0),
        ("updated_at_us", "INTEGER", 1, None, 0),
    ),
    "legacy_session_events": _columns(
        ("sequence", "INTEGER", 0, None, 1),
        ("event_id", "TEXT", 1, None, 0),
        ("session_id", "TEXT", 1, None, 0),
        ("tenant_id", "TEXT", 1, None, 0),
        ("workspace_id", "TEXT", 1, None, 0),
        ("capture_owner_subject", "TEXT", 1, None, 0),
        ("event_type", "TEXT", 1, None, 0),
        ("from_state", "TEXT", 0, None, 0),
        ("to_state", "TEXT", 1, None, 0),
        ("state_version", "INTEGER", 1, None, 0),
        ("actor_subject", "TEXT", 1, None, 0),
        ("actor_role", "TEXT", 1, None, 0),
        ("idempotency_key", "TEXT", 0, None, 0),
        ("request_digest", "TEXT", 1, None, 0),
        ("detail_json", "TEXT", 1, None, 0),
        ("occurred_at_us", "INTEGER", 1, None, 0),
    ),
    "legacy_workload_principals": _columns(
        ("principal_subject", "TEXT", 1, None, 1),
        ("tenant_id", "TEXT", 1, None, 2),
        ("workspace_id", "TEXT", 1, None, 3),
        ("audience", "TEXT", 1, None, 4),
        ("role", "TEXT", 1, None, 0),
        ("transport", "TEXT", 1, None, 0),
        ("active_generation", "INTEGER", 1, None, 0),
        ("revoked_at_us", "INTEGER", 0, None, 0),
        ("state_version", "INTEGER", 1, None, 0),
        ("created_at_us", "INTEGER", 1, None, 0),
        ("updated_at_us", "INTEGER", 1, None, 0),
    ),
    "legacy_workload_proof_claims": _columns(
        ("proof_identifier_digest", "TEXT", 0, None, 1),
        ("principal_subject", "TEXT", 1, None, 0),
        ("tenant_id", "TEXT", 1, None, 0),
        ("workspace_id", "TEXT", 1, None, 0),
        ("audience", "TEXT", 1, None, 0),
        ("role", "TEXT", 1, None, 0),
        ("transport", "TEXT", 1, None, 0),
        ("generation", "INTEGER", 1, None, 0),
        ("method", "TEXT", 1, None, 0),
        ("canonical_path", "TEXT", 1, None, 0),
        ("body_sha256", "TEXT", 1, None, 0),
        ("issued_at_us", "INTEGER", 1, None, 0),
        ("expires_at_us", "INTEGER", 1, None, 0),
        ("claimed_at_us", "INTEGER", 1, None, 0),
        ("retain_until_us", "INTEGER", 1, None, 0),
    ),
}


def _index_terms(*terms: tuple[int, str | None, int, int]) -> tuple[tuple[object, ...], ...]:
    rows = [
        (seq, cid, name, desc, "BINARY", key) for seq, (cid, name, desc, key) in enumerate(terms)
    ]
    rows.append((len(terms), -1, None, 0, "BINARY", 0))
    return tuple(rows)


_EXPECTED_INDEX_LIST: Mapping[str, frozenset[tuple[object, ...]]] = {
    "legacy_session_component_schema": frozenset(
        {("sqlite_autoindex_legacy_session_component_schema_1", 1, "pk", 0)}
    ),
    "legacy_sessions": frozenset(
        {
            ("legacy_sessions_scope_started_idx", 0, "c", 0),
            ("legacy_sessions_owner_idx", 0, "c", 0),
            ("legacy_sessions_scope_processing_idx", 0, "c", 0),
            ("legacy_sessions_raw_expiry_idx", 0, "c", 0),
            ("sqlite_autoindex_legacy_sessions_1", 1, "pk", 0),
            ("sqlite_autoindex_legacy_sessions_2", 1, "u", 0),
            ("sqlite_autoindex_legacy_sessions_3", 1, "u", 0),
            ("sqlite_autoindex_legacy_sessions_4", 1, "u", 0),
        }
    ),
    "legacy_session_events": frozenset(
        {
            ("legacy_session_events_idempotency_idx", 1, "c", 1),
            ("legacy_session_events_scope_sequence_idx", 0, "c", 0),
            ("sqlite_autoindex_legacy_session_events_1", 1, "u", 0),
            ("sqlite_autoindex_legacy_session_events_2", 1, "u", 0),
        }
    ),
    "legacy_workload_principals": frozenset(
        {
            ("legacy_workload_principals_scope_idx", 0, "c", 0),
            ("sqlite_autoindex_legacy_workload_principals_1", 1, "pk", 0),
        }
    ),
    "legacy_workload_proof_claims": frozenset(
        {
            ("legacy_workload_proof_claims_retention_idx", 0, "c", 0),
            ("legacy_workload_proof_claims_principal_idx", 0, "c", 0),
            ("sqlite_autoindex_legacy_workload_proof_claims_1", 1, "pk", 0),
        }
    ),
}

# Exact index_xinfo rows are assigned below from column positions.  Explicit
# inclusion avoids accepting expression, collation, direction, or covering drift.
_COLUMN_POSITIONS = {
    table: {row[1]: row[0] for row in rows} for table, rows in _EXPECTED_TABLE_XINFO.items()
}


def _terms(
    table: str, *columns: str, descending: frozenset[str] = frozenset()
) -> tuple[tuple[object, ...], ...]:
    return _index_terms(
        *((_COLUMN_POSITIONS[table][name], name, int(name in descending), 1) for name in columns)
    )


_EXPECTED_INDEX_XINFO: dict[str, tuple[tuple[object, ...], ...]] = {
    "legacy_sessions_scope_started_idx": _terms(
        "legacy_sessions",
        "tenant_id",
        "workspace_id",
        "started_at_us",
        "session_id",
        descending=frozenset({"started_at_us"}),
    ),
    "legacy_sessions_owner_idx": _terms(
        "legacy_sessions", "tenant_id", "workspace_id", "capture_owner_subject", "session_id"
    ),
    "legacy_sessions_scope_processing_idx": _terms(
        "legacy_sessions",
        "tenant_id",
        "workspace_id",
        "processing_status",
        "updated_at_us",
        "session_id",
    ),
    "legacy_sessions_raw_expiry_idx": _terms("legacy_sessions", "raw_expires_at_us", "session_id"),
    "legacy_session_events_idempotency_idx": _terms(
        "legacy_session_events", "session_id", "event_type", "idempotency_key"
    ),
    "legacy_session_events_scope_sequence_idx": _terms(
        "legacy_session_events", "tenant_id", "workspace_id", "session_id", "sequence"
    ),
    "legacy_workload_principals_scope_idx": _terms(
        "legacy_workload_principals", "tenant_id", "workspace_id", "audience", "principal_subject"
    ),
    "legacy_workload_proof_claims_retention_idx": _terms(
        "legacy_workload_proof_claims", "retain_until_us", "proof_identifier_digest"
    ),
    "legacy_workload_proof_claims_principal_idx": _terms(
        "legacy_workload_proof_claims",
        "principal_subject",
        "tenant_id",
        "workspace_id",
        "audience",
        "claimed_at_us",
    ),
    "sqlite_autoindex_legacy_session_component_schema_1": _terms(
        "legacy_session_component_schema", "component_id"
    ),
    "sqlite_autoindex_legacy_sessions_1": _terms("legacy_sessions", "session_id"),
    "sqlite_autoindex_legacy_sessions_2": _terms("legacy_sessions", "raw_object_key"),
    "sqlite_autoindex_legacy_sessions_3": _terms("legacy_sessions", "processing_completion_id"),
    "sqlite_autoindex_legacy_sessions_4": _terms(
        "legacy_sessions", "session_id", "tenant_id", "workspace_id", "capture_owner_subject"
    ),
    "sqlite_autoindex_legacy_session_events_1": _terms("legacy_session_events", "event_id"),
    "sqlite_autoindex_legacy_session_events_2": _terms(
        "legacy_session_events", "session_id", "state_version"
    ),
    "sqlite_autoindex_legacy_workload_principals_1": _terms(
        "legacy_workload_principals", "principal_subject", "tenant_id", "workspace_id", "audience"
    ),
    "sqlite_autoindex_legacy_workload_proof_claims_1": _terms(
        "legacy_workload_proof_claims", "proof_identifier_digest"
    ),
}

_EXPECTED_FOREIGN_KEYS: Mapping[str, tuple[tuple[object, ...], ...]] = {
    "legacy_session_component_schema": (),
    "legacy_sessions": (),
    "legacy_session_events": (
        (0, 0, "legacy_sessions", "session_id", "session_id", "NO ACTION", "RESTRICT", "NONE"),
        (0, 1, "legacy_sessions", "tenant_id", "tenant_id", "NO ACTION", "RESTRICT", "NONE"),
        (0, 2, "legacy_sessions", "workspace_id", "workspace_id", "NO ACTION", "RESTRICT", "NONE"),
        (
            0,
            3,
            "legacy_sessions",
            "capture_owner_subject",
            "capture_owner_subject",
            "NO ACTION",
            "RESTRICT",
            "NONE",
        ),
    ),
    "legacy_workload_principals": (),
    "legacy_workload_proof_claims": (
        (
            0,
            0,
            "legacy_workload_principals",
            "principal_subject",
            "principal_subject",
            "NO ACTION",
            "RESTRICT",
            "NONE",
        ),
        (
            0,
            1,
            "legacy_workload_principals",
            "tenant_id",
            "tenant_id",
            "NO ACTION",
            "RESTRICT",
            "NONE",
        ),
        (
            0,
            2,
            "legacy_workload_principals",
            "workspace_id",
            "workspace_id",
            "NO ACTION",
            "RESTRICT",
            "NONE",
        ),
        (
            0,
            3,
            "legacy_workload_principals",
            "audience",
            "audience",
            "NO ACTION",
            "RESTRICT",
            "NONE",
        ),
    ),
}
