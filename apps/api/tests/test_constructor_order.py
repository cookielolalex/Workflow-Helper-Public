from __future__ import annotations

import hashlib
import itertools
import re
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from workflow_api.audit_schema import (
    AUDIT_NO_DELETE_TRIGGER_SQL,
    AUDIT_NO_UPDATE_TRIGGER_SQL,
    AUDIT_SEQUENCE_INDEX_SQL,
    AUDIT_TABLE_SQL,
    LEGACY_CONTROL_AUDIT_TABLE_SQL,
    AuditSchemaError,
    normalized_audit_schema,
)
from workflow_api.control_store import (
    _SCHEMA as CONTROL_SCHEMA,
)
from workflow_api.control_store import (
    AuditContext,
    SQLiteControlStore,
)
from workflow_api.legacy_session_schema import (
    LEGACY_SESSION_COMPONENT_ID,
    LEGACY_SESSION_SCHEMA_CHECKSUM,
    LegacySessionSchemaError,
    initialize_legacy_session_schema,
    validate_legacy_session_schema,
)
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.retention_store import RetentionLedger

NOW = datetime(2026, 8, 17, 8, 0, tzinfo=UTC)


def _audit(
    action: str,
    *,
    role: str,
    suffix: str,
    occurred_at: datetime = NOW,
) -> AuditContext:
    return AuditContext(
        correlation_id=f"corr-{suffix}",
        idempotency_key=f"idem-{suffix}",
        subject_id=f"subject-{suffix}",
        roles=(role,),
        action=action,
        target_id=f"target-{suffix}",
        result="accepted",
        occurred_at=occurred_at,
    )


def _audit_schema(path: Path) -> dict[str, str]:
    with sqlite3.connect(path) as connection:
        return dict(normalized_audit_schema(connection))


def _snapshot(path: Path) -> tuple[bytes, list[tuple], list[tuple], list[tuple]]:
    with sqlite3.connect(path) as connection:
        schema = connection.execute(
            """
            select type, name, tbl_name, sql from sqlite_master
            where sql is not null order by type, name
            """
        ).fetchall()
        rows = connection.execute("select * from audit_events order by sequence").fetchall()
        sequence = connection.execute(
            "select name, seq from sqlite_sequence order by name"
        ).fetchall()
    return path.read_bytes(), schema, rows, sequence


def _create_narrow_control_fixture(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("pragma journal_mode = wal")
        connection.executescript(CONTROL_SCHEMA)
        for statement in (
            LEGACY_CONTROL_AUDIT_TABLE_SQL,
            AUDIT_SEQUENCE_INDEX_SQL,
            AUDIT_NO_UPDATE_TRIGGER_SQL,
            AUDIT_NO_DELETE_TRIGGER_SQL,
        ):
            object_type = statement.lstrip().split(maxsplit=2)[1]
            connection.execute(
                statement.replace(
                    f"create {object_type}",
                    f"create {object_type} if not exists",
                    1,
                )
            )
        connection.execute(
            """
            insert into audit_events (
                event_id, correlation_id, idempotency_key, subject_id, roles_json,
                action, target_id, result, occurred_at
            ) values ('legacy-event', 'legacy-corr', null, 'legacy-subject',
                      '["reviewer"]', 'review.append', 'legacy-target',
                      'accepted', 1)
            """
        )


def _create_invalid_fixture(path: Path, kind: str) -> None:
    with sqlite3.connect(path) as connection:
        if kind == "partial":
            connection.execute(AUDIT_TABLE_SQL)
        elif kind == "drifted":
            connection.execute(
                AUDIT_TABLE_SQL.replace(
                    "result in ('accepted', 'denied')",
                    "result in ('accepted', 'denied', 'unknown')",
                )
            )
            connection.execute(AUDIT_SEQUENCE_INDEX_SQL)
            connection.execute(AUDIT_NO_UPDATE_TRIGGER_SQL)
            connection.execute(AUDIT_NO_DELETE_TRIGGER_SQL)
        elif kind == "missing_trigger":
            connection.execute(AUDIT_TABLE_SQL)
            connection.execute(AUDIT_SEQUENCE_INDEX_SQL)
            connection.execute(AUDIT_NO_UPDATE_TRIGGER_SQL)
        elif kind == "extra_index":
            connection.execute(AUDIT_TABLE_SQL)
            connection.execute(AUDIT_SEQUENCE_INDEX_SQL)
            connection.execute(AUDIT_NO_UPDATE_TRIGGER_SQL)
            connection.execute(AUDIT_NO_DELETE_TRIGGER_SQL)
            connection.execute("create index audit_events_subject_idx on audit_events(subject_id)")
        elif kind == "extra_trigger":
            connection.execute(AUDIT_TABLE_SQL)
            connection.execute(AUDIT_SEQUENCE_INDEX_SQL)
            connection.execute(AUDIT_NO_UPDATE_TRIGGER_SQL)
            connection.execute(AUDIT_NO_DELETE_TRIGGER_SQL)
            connection.execute(
                """
                create trigger audit_events_extra before insert on audit_events
                begin select raise(abort, 'extra'); end
                """
            )
        elif kind == "name_collision":
            connection.execute("create table unrelated (value text)")
            connection.execute(
                "create index audit_events_sequence_idx on unrelated (value)"
            )
            connection.execute("insert into unrelated values ('preserve-me')")
        elif kind == "unknown":
            connection.execute("create table unrelated (value text)")
            connection.execute("insert into unrelated values ('preserve-me')")
        else:  # pragma: no cover - test helper guard
            raise AssertionError(kind)


def _initialize_legacy(path: Path) -> None:
    with sqlite3.connect(path, isolation_level=None) as connection:
        connection.execute("pragma foreign_keys = on")
        initialize_legacy_session_schema(connection, installed_at_us=1_777_777)


def _complete_snapshot(path: Path) -> tuple[list[tuple], dict[str, list[tuple]], int]:
    with sqlite3.connect(path) as connection:
        schema = connection.execute(
            "select type, name, tbl_name, sql from sqlite_master order by type, name"
        ).fetchall()
        data = {
            name: connection.execute(f'select * from "{name}"').fetchall()
            for (name,) in connection.execute(
                """
                select name from sqlite_master
                where type = 'table' and name not like 'sqlite_%'
                order by name
                """
            )
        }
        user_version = connection.execute("pragma user_version").fetchone()[0]
    return schema, data, user_version


def test_both_constructor_orders_and_reopens_share_one_exact_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []
    connect = sqlite3.connect

    def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    signatures: list[dict[str, str]] = []
    for name, constructors in (
        ("control-first.sqlite3", (SQLiteControlStore, RetentionLedger)),
        ("retention-first.sqlite3", (RetentionLedger, SQLiteControlStore)),
    ):
        path = tmp_path / name
        for constructor in (*constructors, *constructors):
            constructor(path)
        signatures.append(_audit_schema(path))

    assert signatures[0] == signatures[1]
    assert set(signatures[0]) == {
        "index:audit_events_sequence_idx",
        "table:audit_events",
        "trigger:audit_events_no_delete",
        "trigger:audit_events_no_update",
    }
    assert all(action in signatures[0]["table:audit_events"] for action in (
        "job.register",
        "review.append",
        "retention.register",
        "retention.attest_delete",
    ))

    trace = "\n".join(statements).casefold()
    for prohibited in (
        r"\bdrop\b",
        r"\balter\b",
        r"\brename\b",
        r"insert\s+into[\s\S]+select",
        r"audit_events_retention_migration",
        r"sqlite_sequence",
    ):
        assert re.search(prohibited, trace) is None


def test_expanded_reopens_preserve_file_rows_schema_support_and_sequence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "expanded.sqlite3"
    store = SQLiteControlStore(path)
    retention = RetentionLedger(path)
    assert store.append_audit_event(
        _audit("review.append", role="reviewer", suffix="control")
    ).sequence == 1
    assert retention.append_audit_event(
        _audit(
            "retention.register",
            role="retention_steward",
            suffix="retention",
            occurred_at=NOW + timedelta(seconds=1),
        )
    ) == 2
    before = _snapshot(path)

    RetentionLedger(path)
    SQLiteControlStore(path)

    assert _snapshot(path) == before


def test_legacy_narrow_control_opens_unchanged_and_retention_fails_atomically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "narrow.sqlite3"
    _create_narrow_control_fixture(path)
    before = _snapshot(path)

    SQLiteControlStore(path)
    assert _snapshot(path) == before
    with pytest.raises(AuditSchemaError, match="incompatible with retention"):
        RetentionLedger(path)
    # WAL rollback/checkpoint activity may change bytes; logical state must not change.
    assert _snapshot(path)[1:] == before[1:]


@pytest.mark.parametrize(
    "kind",
    (
        "partial",
        "drifted",
        "missing_trigger",
        "extra_index",
        "extra_trigger",
        "name_collision",
        "unknown",
    ),
)
@pytest.mark.parametrize("constructor", (SQLiteControlStore, RetentionLedger))
def test_incompatible_schemas_fail_closed_without_mutation(
    tmp_path: Path,
    kind: str,
    constructor: Callable[[Path], object],
) -> None:
    path = tmp_path / f"{kind}-{constructor.__name__}.sqlite3"
    _create_invalid_fixture(path, kind)
    before_hash = hashlib.sha256(path.read_bytes()).digest()
    with sqlite3.connect(path) as connection:
        before_schema = connection.execute(
            "select type, name, tbl_name, sql from sqlite_master order by type, name"
        ).fetchall()
        before_data = {
            name: connection.execute(f"select * from {name}").fetchall()
            for (name,) in connection.execute(
                """
                select name from sqlite_master
                where type = 'table' and name not like 'sqlite_%'
                order by name
                """
            )
        }

    with pytest.raises(AuditSchemaError):
        constructor(path)

    assert hashlib.sha256(path.read_bytes()).digest() == before_hash
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "select type, name, tbl_name, sql from sqlite_master order by type, name"
        ).fetchall() == before_schema
        assert {
            name: connection.execute(f"select * from {name}").fetchall()
            for name in before_data
        } == before_data


def test_action_families_immutability_sequence_and_control_boundary(
    tmp_path: Path,
) -> None:
    path = tmp_path / "append.sqlite3"
    store = SQLiteControlStore(path)
    retention = RetentionLedger(path)

    first = store.append_audit_event(
        _audit("job.register", role="deterministic_worker", suffix="first")
    )
    second = retention.append_audit_event(
        _audit(
            "retention.hold",
            role="retention_steward",
            suffix="second",
            occurred_at=NOW + timedelta(seconds=1),
        )
    )
    assert (first.sequence, second) == (1, 2)

    with pytest.raises(ValueError, match="unsupported audit action"):
        store.append_audit_event(
            _audit("retention.register", role="reviewer", suffix="bad-action")
        )
    with pytest.raises(ValueError, match="unsupported audit role"):
        store.append_audit_event(
            _audit("review.read", role="retention_steward", suffix="bad-role")
        )

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("update audit_events set result = 'denied'")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("delete from audit_events")

    third = store.append_audit_event(
        _audit(
            "audit.read",
            role="audit_reader",
            suffix="third",
            occurred_at=NOW + timedelta(seconds=2),
        )
    )
    assert third.sequence == 3


def test_legacy_only_schema_is_exact_and_does_not_claim_shared_audit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-only.sqlite3"
    _initialize_legacy(path)

    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        validate_legacy_session_schema(connection, require_exclusive=True)
        counts = dict(
            connection.execute(
                """
                select type, count(*) from sqlite_master
                where sql is not null and name not like 'sqlite_%'
                group by type
                """
            )
        )
        table_names = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type = 'table'"
            )
        }
        manifest = connection.execute(
            "select * from legacy_session_component_schema"
        ).fetchone()

    assert counts == {"index": 9, "table": 5, "trigger": 3}
    assert "audit_events" not in table_names
    assert manifest == (
        LEGACY_SESSION_COMPONENT_ID,
        1,
        LEGACY_SESSION_SCHEMA_CHECKSUM,
        1_777_777,
    )


def test_exclusive_validation_ignores_internal_catalog_without_querying_it(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-internal-catalog.sqlite3"
    _initialize_legacy(path)
    statements: list[str] = []

    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        assert connection.execute(
            "select 1 from sqlite_master where name = 'sqlite_sequence'"
        ).fetchone() == (1,)
        connection.set_trace_callback(statements.append)
        validate_legacy_session_schema(connection, require_exclusive=True)

    trace = "\n".join(statements).casefold()
    assert "sqlite_sequence" not in trace
    assert "name not like 'sqlite_%'" in trace


@pytest.mark.parametrize(
    "order",
    tuple(
        itertools.permutations(
            (SQLiteLegacySessionStore, SQLiteControlStore, RetentionLedger)
        )
    ),
    ids=("LCR", "LRC", "CLR", "CRL", "RLC", "RCL"),
)
def test_all_three_constructor_orders_and_reopens_preserve_every_component(
    tmp_path: Path,
    order: tuple[Callable[[Path], object], ...],
) -> None:
    path = tmp_path / "-".join(constructor.__name__ for constructor in order)
    for constructor in order:
        constructor(path)

    control = SQLiteControlStore(path)
    retention = RetentionLedger(path)
    control.register_job("job-preserved", "a" * 64)
    retention.register_target(
        target_id="target-preserved",
        copies=(
            {
                "copy_id": "copy-preserved",
                "provider": "s3",
                "file_id": "object-preserved",
                "revision": "version-preserved",
                "sha256": "b" * 64,
            },
        ),
        idempotency_key="retention-preserved",
        actor_id="actor-preserved",
        now=NOW,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            insert into legacy_workload_principals (
                principal_subject, tenant_id, workspace_id, audience, role,
                transport, active_generation, revoked_at_us, state_version,
                created_at_us, updated_at_us
            ) values ('principal-preserved', 'tenant-preserved',
                      'workspace-preserved', 'workflow-helper:capture-upload',
                      'capture_uploader', 'capture_workload', 1, null, 1, 1, 1)
            """
        )
    before = _complete_snapshot(path)

    for constructor in reversed(order):
        constructor(path)

    assert _complete_snapshot(path) == before
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        validate_legacy_session_schema(connection)


@pytest.mark.parametrize("constructor", (SQLiteControlStore, RetentionLedger))
def test_exact_legacy_only_is_the_only_nonempty_audit_absent_admission(
    tmp_path: Path,
    constructor: Callable[[Path], object],
) -> None:
    path = tmp_path / f"legacy-first-{constructor.__name__}.sqlite3"
    _initialize_legacy(path)
    with sqlite3.connect(path) as connection:
        before_legacy = connection.execute(
            """
            select type, name, tbl_name, sql from sqlite_master
            where name like 'legacy_%' or tbl_name like 'legacy_%'
            order by type, name
            """
        ).fetchall()

    constructor(path)

    with sqlite3.connect(path) as connection:
        after_legacy = connection.execute(
            """
            select type, name, tbl_name, sql from sqlite_master
            where name like 'legacy_%' or tbl_name like 'legacy_%'
            order by type, name
            """
        ).fetchall()
        audit_objects = connection.execute(
            """
            select type, name from sqlite_master
            where name = 'audit_events' or tbl_name = 'audit_events'
            order by type, name
            """
        ).fetchall()
    assert after_legacy == before_legacy
    assert audit_objects == [
        ("index", "audit_events_sequence_idx"),
        ("index", "sqlite_autoindex_audit_events_1"),
        ("table", "audit_events"),
        ("trigger", "audit_events_no_delete"),
        ("trigger", "audit_events_no_update"),
    ]


@pytest.mark.parametrize(
    "drift",
    ("extra", "partial", "table_sql", "manifest", "foreign_key", "name_collision"),
)
@pytest.mark.parametrize("constructor", (SQLiteControlStore, RetentionLedger))
def test_legacy_admission_drift_fails_without_schema_data_sequence_or_version_changes(
    tmp_path: Path,
    drift: str,
    constructor: Callable[[Path], object],
) -> None:
    path = tmp_path / f"legacy-{drift}-{constructor.__name__}.sqlite3"
    if drift in {"partial", "name_collision"}:
        with sqlite3.connect(path) as connection:
            if drift == "partial":
                connection.execute(
                    "create table legacy_session_component_schema (component_id text)"
                )
            else:
                connection.execute("create table unrelated (value text)")
                connection.execute(
                    "create index legacy_sessions_owner_idx on unrelated(value)"
                )
                connection.execute("insert into unrelated values ('preserved')")
    else:
        _initialize_legacy(path)
        with sqlite3.connect(path) as connection:
            if drift == "extra":
                connection.execute("create table legacy_extra (value text)")
            elif drift == "table_sql":
                connection.execute(
                    "create index legacy_sessions_extra_idx on legacy_sessions(project_id)"
                )
            elif drift == "manifest":
                connection.execute(
                    "update legacy_session_component_schema set schema_checksum = ?",
                    ("0" * 64,),
                )
            elif drift == "foreign_key":
                connection.execute("pragma foreign_keys = off")
                connection.execute(
                    """
                    insert into legacy_session_events (
                        event_id, session_id, tenant_id, workspace_id,
                        capture_owner_subject, event_type, from_state, to_state,
                        state_version, actor_subject, actor_role, idempotency_key,
                        request_digest, detail_json, occurred_at_us
                    ) values ('event-orphan', 'missing', 'tenant', 'workspace',
                              'owner', 'registered', null, 'registered', 1,
                              'actor', 'role', null, ?, '{}', 1)
                    """,
                    ("c" * 64,),
                )
            else:  # pragma: no cover - parametrization guard
                raise AssertionError(drift)
    with sqlite3.connect(path) as connection:
        connection.execute("pragma user_version = 47")
    before_bytes = path.read_bytes()
    before = _complete_snapshot(path)

    with pytest.raises(AuditSchemaError):
        constructor(path)

    assert path.read_bytes() == before_bytes
    assert _complete_snapshot(path) == before


def test_legacy_initializer_rejects_name_collision_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "legacy-name-collision.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("create table unrelated (value text)")
        connection.execute("create index legacy_sessions_owner_idx on unrelated(value)")
        connection.execute("insert into unrelated values ('preserved')")
        connection.execute("pragma user_version = 23")
    before_bytes = path.read_bytes()
    before = _complete_snapshot(path)

    with sqlite3.connect(path, isolation_level=None) as connection:
        connection.execute("pragma foreign_keys = on")
        with pytest.raises((LegacySessionSchemaError, sqlite3.OperationalError)):
            initialize_legacy_session_schema(connection, installed_at_us=2)

    assert path.read_bytes() == before_bytes
    assert _complete_snapshot(path) == before


def test_control_constructor_rolls_back_audit_and_partial_control_ddl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "control-fault.sqlite3"
    monkeypatch.setattr(
        "workflow_api.control_store._schema_statements",
        lambda _script: (
            "create table control_fault_probe (value text)",
            "create table control_fault_probe (value text)",
        ),
    )

    with pytest.raises(sqlite3.OperationalError):
        SQLiteControlStore(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "select name from sqlite_master where sql is not null"
        ).fetchall() == []


def test_constructor_fault_during_canonical_audit_ddl_restores_exact_legacy_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "audit-ddl-fault.sqlite3"
    _initialize_legacy(path)
    before_bytes = path.read_bytes()
    before = _complete_snapshot(path)
    monkeypatch.setattr(
        "workflow_api.audit_schema.AUDIT_SCHEMA_SQL",
        (
            AUDIT_TABLE_SQL,
            AUDIT_SEQUENCE_INDEX_SQL,
            AUDIT_TABLE_SQL,
        ),
    )

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        SQLiteControlStore(path)

    assert path.read_bytes() == before_bytes
    assert _complete_snapshot(path) == before


def test_retention_constructor_rolls_back_audit_and_partial_retention_ddl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "retention-fault.sqlite3"
    monkeypatch.setattr(
        "workflow_api.retention_store._RETENTION_SCHEMA",
        (
            "create table retention_fault_probe (value text)",
            "create table retention_fault_probe (value text)",
        ),
    )

    with pytest.raises(sqlite3.OperationalError):
        RetentionLedger(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "select name from sqlite_master where sql is not null"
        ).fetchall() == []


def test_concurrent_control_and_retention_after_legacy_only_converge(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent.sqlite3"
    _initialize_legacy(path)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(constructor, path)
            for constructor in (SQLiteControlStore, RetentionLedger)
        ]
        for future in futures:
            future.result()

    SQLiteControlStore(path)
    RetentionLedger(path)
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        validate_legacy_session_schema(connection)
        names = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type = 'table'"
            )
        }
    assert {"audit_events", "control_jobs", "retention_targets"} <= names
