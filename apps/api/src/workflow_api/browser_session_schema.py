"""Exact component-local SQLite schema for durable browser sessions.

The schema is intentionally exclusive: a browser-session store may initialize
an empty SQLite file or reopen this exact version, but it never shares, adopts,
repairs, or migrates another component's objects.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Mapping

BROWSER_SESSION_COMPONENT_ID = "workflow-helper.browser-session-lifecycle"
BROWSER_SESSION_SCHEMA_VERSION = 1
BROWSER_SESSION_SCHEMA_MANIFEST = (
    "browser-session-lifecycle/v1|browser_session_component_schema:component_id,"
    "schema_version,schema_checksum,installed_at_us|browser_sessions:"
    "session_identifier_digest,csrf_token_digest,principal_subject,roles_json,"
    "tenant_id,workspace_id,allowed_browser_origin,generation,issued_at_us,"
    "authenticated_at_us,last_seen_at_us,idle_expires_at_us,absolute_expires_at_us,"
    "revoked_at_us,state_version|browser_session_digest_allocations:digest,"
    "digest_kind,allocated_at_us"
)
BROWSER_SESSION_SCHEMA_CHECKSUM = "8b06d0f50bcc4d62a4f54fb65f739608bbd51f4dc669267a5ba1347c275399d0"

BROWSER_SESSION_TABLE_SQL = (
    """
    create table browser_session_component_schema (
        component_id text primary key,
        schema_version integer not null,
        schema_checksum text not null,
        installed_at_us integer not null
    )
    """,
    """
    create table browser_sessions (
        session_identifier_digest text primary key,
        csrf_token_digest text not null unique,
        principal_subject text not null,
        roles_json text not null,
        tenant_id text not null,
        workspace_id text not null,
        allowed_browser_origin text not null,
        generation integer not null,
        issued_at_us integer not null,
        authenticated_at_us integer not null,
        last_seen_at_us integer not null,
        idle_expires_at_us integer not null,
        absolute_expires_at_us integer not null,
        revoked_at_us integer,
        state_version integer not null
    )
    """,
    """
    create table browser_session_digest_allocations (
        digest text primary key,
        digest_kind text not null,
        allocated_at_us integer not null
    )
    """,
)

BROWSER_SESSION_INDEX_SQL = (
    """create index browser_sessions_principal_scope_idx
       on browser_sessions (tenant_id, workspace_id, principal_subject)""",
)

BROWSER_SESSION_TRIGGER_SQL = (
    """
    create trigger browser_session_digest_allocations_no_update
    before update on browser_session_digest_allocations
    begin
        select raise(abort, 'browser session digest allocations are immutable');
    end
    """,
    """
    create trigger browser_session_digest_allocations_no_delete
    before delete on browser_session_digest_allocations
    begin
        select raise(abort, 'browser session digest allocations are immutable');
    end
    """,
)

BROWSER_SESSION_SCHEMA_SQL = (
    *BROWSER_SESSION_TABLE_SQL,
    *BROWSER_SESSION_INDEX_SQL,
    *BROWSER_SESSION_TRIGGER_SQL,
)

_TABLE_NAMES = (
    "browser_session_component_schema",
    "browser_sessions",
    "browser_session_digest_allocations",
)
_INDEX_NAMES = ("browser_sessions_principal_scope_idx",)
_TRIGGER_NAMES = (
    "browser_session_digest_allocations_no_update",
    "browser_session_digest_allocations_no_delete",
)
_SPACE = re.compile(r"\s+")
_PUNCTUATION_SPACE = re.compile(r"\s*([(),])\s*")


class BrowserSessionSchemaError(RuntimeError):
    """The browser-session database is not the exact component v1 schema."""


def initialize_browser_session_schema(
    connection: sqlite3.Connection,
    *,
    installed_at_us: int,
) -> str:
    """Atomically create an exact empty component or validate an exact reopen."""

    if connection.in_transaction:
        raise BrowserSessionSchemaError("browser session schema requires an idle connection")
    _require_foreign_keys(connection)
    if type(installed_at_us) is not int or not -(2**63) <= installed_at_us < 2**63:
        raise ValueError("installed_at_us must be a signed 64-bit integer")

    try:
        connection.execute("begin immediate")
        if _all_user_objects(connection):
            validate_browser_session_schema(connection)
            result = "existing"
        else:
            for statement in BROWSER_SESSION_SCHEMA_SQL:
                connection.execute(statement)
            connection.execute(
                """
                insert into browser_session_component_schema (
                    component_id, schema_version, schema_checksum, installed_at_us
                ) values (?, ?, ?, ?)
                """,
                (
                    BROWSER_SESSION_COMPONENT_ID,
                    BROWSER_SESSION_SCHEMA_VERSION,
                    BROWSER_SESSION_SCHEMA_CHECKSUM,
                    installed_at_us,
                ),
            )
            validate_browser_session_schema(connection)
            result = "created"
        connection.commit()
        return result
    except BaseException:
        connection.rollback()
        raise


def validate_browser_session_schema(connection: sqlite3.Connection) -> None:
    """Validate the complete v1 catalog and manifest without changing state."""

    _require_foreign_keys(connection)
    if _manifest_checksum() != BROWSER_SESSION_SCHEMA_CHECKSUM:
        raise BrowserSessionSchemaError("browser session schema manifest is invalid")
    if _all_user_objects(connection) != _expected_user_objects():
        raise BrowserSessionSchemaError("browser session schema objects do not match v1")
    for table_name, expected in _EXPECTED_TABLE_XINFO.items():
        if _table_xinfo(connection, table_name) != expected:
            raise BrowserSessionSchemaError("browser session table shape does not match v1")
    for table_name, expected in _EXPECTED_INDEX_LIST.items():
        if _index_list(connection, table_name) != expected:
            raise BrowserSessionSchemaError("browser session index set does not match v1")
    for index_name, expected in _EXPECTED_INDEX_XINFO.items():
        if _index_xinfo(connection, index_name) != expected:
            raise BrowserSessionSchemaError("browser session index shape does not match v1")

    rows = connection.execute(
        """
        select component_id, schema_version, schema_checksum, installed_at_us
        from browser_session_component_schema
        """
    ).fetchall()
    if len(rows) != 1:
        raise BrowserSessionSchemaError("browser session schema manifest does not match v1")
    component_id, version, checksum, installed_at_us = rows[0]
    if (
        component_id != BROWSER_SESSION_COMPONENT_ID
        or type(version) is not int
        or version != BROWSER_SESSION_SCHEMA_VERSION
        or checksum != BROWSER_SESSION_SCHEMA_CHECKSUM
        or type(installed_at_us) is not int
    ):
        raise BrowserSessionSchemaError("browser session schema manifest does not match v1")


def _require_foreign_keys(connection: sqlite3.Connection) -> None:
    row = connection.execute("pragma foreign_keys").fetchone()
    if row is None or row[0] != 1:
        raise BrowserSessionSchemaError("SQLite foreign-key enforcement must be enabled")


def _manifest_checksum() -> str:
    return hashlib.sha256(BROWSER_SESSION_SCHEMA_MANIFEST.encode("utf-8")).hexdigest()


def _normalize_sql(sql: str) -> str:
    collapsed = _SPACE.sub(" ", sql.strip().rstrip(";")).casefold()
    return _PUNCTUATION_SPACE.sub(r"\1", collapsed)


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


def _expected_user_objects() -> frozenset[tuple[str, str, str, str | None]]:
    return frozenset(
        {
            (
                "table",
                "browser_session_component_schema",
                "browser_session_component_schema",
                _normalize_sql(BROWSER_SESSION_TABLE_SQL[0]),
            ),
            (
                "table",
                "browser_sessions",
                "browser_sessions",
                _normalize_sql(BROWSER_SESSION_TABLE_SQL[1]),
            ),
            (
                "table",
                "browser_session_digest_allocations",
                "browser_session_digest_allocations",
                _normalize_sql(BROWSER_SESSION_TABLE_SQL[2]),
            ),
            (
                "index",
                "browser_sessions_principal_scope_idx",
                "browser_sessions",
                _normalize_sql(BROWSER_SESSION_INDEX_SQL[0]),
            ),
            (
                "trigger",
                "browser_session_digest_allocations_no_update",
                "browser_session_digest_allocations",
                _normalize_sql(BROWSER_SESSION_TRIGGER_SQL[0]),
            ),
            (
                "trigger",
                "browser_session_digest_allocations_no_delete",
                "browser_session_digest_allocations",
                _normalize_sql(BROWSER_SESSION_TRIGGER_SQL[1]),
            ),
        }
    )


def _table_xinfo(connection: sqlite3.Connection, table: str) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(f"pragma table_xinfo('{table}')"))


def _index_list(connection: sqlite3.Connection, table: str) -> frozenset[tuple[object, ...]]:
    return frozenset(tuple(row[1:]) for row in connection.execute(f"pragma index_list('{table}')"))


def _index_xinfo(connection: sqlite3.Connection, index: str) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(f"pragma index_xinfo('{index}')"))


def _columns(*items: tuple[str, str, int, object, int]) -> tuple[tuple[object, ...], ...]:
    return tuple((position, *item, 0) for position, item in enumerate(items))


_EXPECTED_TABLE_XINFO: Mapping[str, tuple[tuple[object, ...], ...]] = {
    "browser_session_component_schema": _columns(
        ("component_id", "TEXT", 0, None, 1),
        ("schema_version", "INTEGER", 1, None, 0),
        ("schema_checksum", "TEXT", 1, None, 0),
        ("installed_at_us", "INTEGER", 1, None, 0),
    ),
    "browser_sessions": _columns(
        ("session_identifier_digest", "TEXT", 0, None, 1),
        ("csrf_token_digest", "TEXT", 1, None, 0),
        ("principal_subject", "TEXT", 1, None, 0),
        ("roles_json", "TEXT", 1, None, 0),
        ("tenant_id", "TEXT", 1, None, 0),
        ("workspace_id", "TEXT", 1, None, 0),
        ("allowed_browser_origin", "TEXT", 1, None, 0),
        ("generation", "INTEGER", 1, None, 0),
        ("issued_at_us", "INTEGER", 1, None, 0),
        ("authenticated_at_us", "INTEGER", 1, None, 0),
        ("last_seen_at_us", "INTEGER", 1, None, 0),
        ("idle_expires_at_us", "INTEGER", 1, None, 0),
        ("absolute_expires_at_us", "INTEGER", 1, None, 0),
        ("revoked_at_us", "INTEGER", 0, None, 0),
        ("state_version", "INTEGER", 1, None, 0),
    ),
    "browser_session_digest_allocations": _columns(
        ("digest", "TEXT", 0, None, 1),
        ("digest_kind", "TEXT", 1, None, 0),
        ("allocated_at_us", "INTEGER", 1, None, 0),
    ),
}


_EXPECTED_INDEX_LIST: Mapping[str, frozenset[tuple[object, ...]]] = {
    "browser_session_component_schema": frozenset(
        {("sqlite_autoindex_browser_session_component_schema_1", 1, "pk", 0)}
    ),
    "browser_sessions": frozenset(
        {
            ("browser_sessions_principal_scope_idx", 0, "c", 0),
            ("sqlite_autoindex_browser_sessions_1", 1, "pk", 0),
            ("sqlite_autoindex_browser_sessions_2", 1, "u", 0),
        }
    ),
    "browser_session_digest_allocations": frozenset(
        {("sqlite_autoindex_browser_session_digest_allocations_1", 1, "pk", 0)}
    ),
}


def _index_terms(*terms: tuple[int, str]) -> tuple[tuple[object, ...], ...]:
    rows = [(seq, cid, name, 0, "BINARY", 1) for seq, (cid, name) in enumerate(terms)]
    rows.append((len(terms), -1, None, 0, "BINARY", 0))
    return tuple(rows)


_COLUMN_POSITIONS = {
    table: {row[1]: row[0] for row in rows} for table, rows in _EXPECTED_TABLE_XINFO.items()
}


def _terms(table: str, *columns: str) -> tuple[tuple[object, ...], ...]:
    return _index_terms(*((_COLUMN_POSITIONS[table][name], name) for name in columns))


_EXPECTED_INDEX_XINFO = {
    "browser_sessions_principal_scope_idx": _terms(
        "browser_sessions", "tenant_id", "workspace_id", "principal_subject"
    ),
    "sqlite_autoindex_browser_session_component_schema_1": _terms(
        "browser_session_component_schema", "component_id"
    ),
    "sqlite_autoindex_browser_sessions_1": _terms("browser_sessions", "session_identifier_digest"),
    "sqlite_autoindex_browser_sessions_2": _terms("browser_sessions", "csrf_token_digest"),
    "sqlite_autoindex_browser_session_digest_allocations_1": _terms(
        "browser_session_digest_allocations", "digest"
    ),
}
