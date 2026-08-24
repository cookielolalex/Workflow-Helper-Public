from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import sqlite3
from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from workflow_api.artifact_gateway import ArtifactAuthority
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.control_store import SQLiteControlStore
from workflow_api.legacy_session_store import (
    ResolvedSessionCaptureAuthority,
    SQLiteLegacySessionStore,
)
from workflow_api.models import ProcessingCompletion, SessionCreate
from workflow_api.repository import SessionNotFoundError

NOW = datetime(2026, 8, 19, 3, 0, tzinfo=UTC)
SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
OTHER_SCOPE = TenantWorkspaceScope("tenant-other", "workspace-other")
OWNER = "capture-owner-synthetic"


def _run(coroutine):
    return asyncio.run(coroutine)


def _registration(session_id: UUID | None = None) -> SessionCreate:
    return SessionCreate(
        schema_version="1.0",
        session_id=session_id or uuid4(),
        machine_id="machine-fallback-synthetic",
        project_id="project-fallback-synthetic",
        started_at=NOW - timedelta(minutes=2),
        ended_at=NOW - timedelta(minutes=1),
        active_duration_seconds=60,
        approved_process="acad",
        package_sha256="a" * 64,
        package_size_bytes=2_048,
    )


def _completion(session_id: UUID) -> ProcessingCompletion:
    payload = {
        "schema_version": "1.0",
        "session_id": str(session_id),
        "event_count": 1,
        "meaningful_event_count": 1,
        "timeline": [],
        "keyframes": [],
        "warnings": [],
        "output_object_key": f"sessions/{session_id}/timeline.json",
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return ProcessingCompletion(
        **payload,
        idempotency_key=hashlib.sha256(canonical).hexdigest(),
    )


def _store(path: Path) -> SQLiteLegacySessionStore:
    return SQLiteLegacySessionStore(path, clock=lambda: NOW)


def _register(store: SQLiteLegacySessionStore, registration: SessionCreate) -> None:
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))


def _generic_absence(error: SessionNotFoundError, *attempted_values: object) -> None:
    assert error.args == ("session unavailable",)
    rendered = f"{error!s} {error!r}"
    sensitive_values = (
        OWNER,
        SCOPE.tenant_id,
        SCOPE.workspace_id,
        *attempted_values,
    )
    for value in sensitive_values:
        representations = {str(value), repr(value)}
        if isinstance(value, memoryview):
            stored_bytes = bytes(value)
            representations.update((str(stored_bytes), repr(stored_bytes)))
            try:
                representations.add(stored_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                pass
        assert all(representation not in rendered for representation in representations)


@dataclass(frozen=True, slots=True)
class _SQLiteFiles:
    main: bytes
    wal: bytes | None
    shm: bytes | None

    @property
    def inventory(self) -> tuple[str, ...]:
        return tuple(
            name
            for name, value in (("main", self.main), ("-wal", self.wal), ("-shm", self.shm))
            if value is not None
        )


@dataclass(frozen=True, slots=True)
class _ReadObservation:
    result: ResolvedSessionCaptureAuthority | None
    error: SessionNotFoundError | None
    before_files: _SQLiteFiles
    immediate_after_files: _SQLiteFiles
    final_files: _SQLiteFiles
    statements: tuple[str, ...]
    total_changes: tuple[int, ...]


def _file_state(path: Path) -> _SQLiteFiles:
    def optional_bytes(candidate: Path) -> bytes | None:
        return candidate.read_bytes() if candidate.exists() else None

    return _SQLiteFiles(
        path.read_bytes(),
        optional_bytes(Path(f"{path}-wal")),
        optional_bytes(Path(f"{path}-shm")),
    )


def _semantic_state(
    path: Path,
    *,
    connection: sqlite3.Connection | None = None,
) -> tuple[str, ...]:
    if connection is not None:
        return tuple(connection.iterdump())
    with sqlite3.connect(path) as opened:
        return tuple(opened.iterdump())


def _assert_durable_state_unchanged(before: _SQLiteFiles, after: _SQLiteFiles) -> None:
    assert after.inventory == before.inventory
    assert after.main == before.main
    assert after.wal == before.wal
    _assert_only_wal_index_reader_marks_changed(before.shm, after.shm)


def _assert_only_wal_index_reader_marks_changed(
    before: bytes | None,
    after: bytes | None,
) -> None:
    if before is None or after is None:
        assert after is before
        return
    assert len(after) == len(before)
    differing_offsets = {
        offset for offset, (old, new) in enumerate(zip(before, after, strict=True)) if old != new
    }
    assert differing_offsets <= set(range(100, 120))


def _observe_resolver_read(
    store: SQLiteLegacySessionStore,
    path: Path,
    session_id: object,
    scope: object,
    *,
    semantic_connection: sqlite3.Connection | None = None,
) -> _ReadObservation:
    owned_semantic_connection = None
    if semantic_connection is None:
        owned_semantic_connection = sqlite3.connect(path)
        semantic_connection = owned_semantic_connection
    semantic_before = _semantic_state(path, connection=semantic_connection)
    before_files = _file_state(path)
    changes: list[int] = []
    statements: list[str] = []
    original = store._connect

    def tracked_connect():
        connection = original()
        connection.set_trace_callback(statements.append)
        return _TrackedConnection(connection, changes)

    store._connect = tracked_connect  # type: ignore[method-assign]
    result: ResolvedSessionCaptureAuthority | None = None
    error: SessionNotFoundError | None = None
    try:
        result = _run(
            store.resolve_session_capture_authority(session_id, scope=scope)  # type: ignore[arg-type]
        )
    except SessionNotFoundError as caught:
        error = caught
    finally:
        store._connect = original  # type: ignore[method-assign]

    immediate_after_files = _file_state(path)
    semantic_after = _semantic_state(path, connection=semantic_connection)
    final_files = _file_state(path)
    if owned_semantic_connection is not None:
        owned_semantic_connection.close()
    assert semantic_after == semantic_before
    _assert_durable_state_unchanged(before_files, immediate_after_files)
    _assert_durable_state_unchanged(before_files, final_files)

    expected_selects = int(type(session_id) is UUID and type(scope) is TenantWorkspaceScope)
    selects = [
        statement for statement in statements if statement.lstrip().casefold().startswith("select")
    ]
    assert len(selects) == expected_selects
    assert changes == [0] * expected_selects
    assert not any(
        statement.lstrip().casefold().startswith(
            ("insert", "update", "delete", "replace", "begin", "commit", "rollback")
        )
        for statement in statements
    )
    return _ReadObservation(
        result,
        error,
        before_files,
        immediate_after_files,
        final_files,
        tuple(statements),
        tuple(changes),
    )


class _TrackedConnection:
    def __init__(self, connection: sqlite3.Connection, changes: list[int]) -> None:
        self._connection = connection
        self._changes = changes

    def execute(self, *args, **kwargs):
        return self._connection.execute(*args, **kwargs)

    def close(self) -> None:
        self._changes.append(self._connection.total_changes)
        self._connection.close()


def _corrupt_consistent_capture_owner(path: Path, session_id: UUID, value: object) -> None:
    with sqlite3.connect(path) as connection:
        trigger_row = connection.execute(
            "select sql from sqlite_master where type = 'trigger' "
            "and name = 'legacy_session_events_no_update'"
        ).fetchone()
        assert trigger_row is not None and type(trigger_row[0]) is str
        connection.execute("pragma foreign_keys = off")
        connection.execute("drop trigger legacy_session_events_no_update")
        connection.execute(
            "update legacy_session_events set capture_owner_subject = ? where session_id = ?",
            (value, str(session_id)),
        )
        connection.execute(
            "update legacy_sessions set capture_owner_subject = ? where session_id = ?",
            (value, str(session_id)),
        )
        connection.execute(trigger_row[0])


def test_exact_authority_is_frozen_and_survives_store_restart(tmp_path: Path) -> None:
    path = tmp_path / "capture-authority.sqlite3"
    registration = _registration()
    first = _store(path)
    _register(first, registration)

    expected = ResolvedSessionCaptureAuthority(
        registration.session_id,
        ArtifactAuthority(SCOPE, OWNER),
    )
    first_observation = _observe_resolver_read(
        first, path, registration.session_id, SCOPE
    )
    assert first_observation.error is None
    assert first_observation.result == expected
    restarted = _store(path)
    restarted_observation = _observe_resolver_read(
        restarted, path, registration.session_id, SCOPE
    )
    assert restarted_observation.error is None
    resolved = restarted_observation.result
    assert resolved == expected
    assert resolved is not None
    with pytest.raises(FrozenInstanceError):
        resolved.session_id = uuid4()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        resolved.authority.capture_owner_subject = "capture-owner-replacement"  # type: ignore[misc]


def test_unknown_cross_scope_and_malformed_identifiers_are_one_generic_absence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "generic-absence.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)

    attempts = (
        (uuid4(), SCOPE),
        (registration.session_id, OTHER_SCOPE),
        ("not-a-session-uuid", SCOPE),
        (str(registration.session_id), SCOPE),
        (registration.session_id, None),
        (registration.session_id, (SCOPE.tenant_id, SCOPE.workspace_id)),
        (
            registration.session_id,
            {"tenant_id": OTHER_SCOPE.tenant_id, "workspace_id": OTHER_SCOPE.workspace_id},
        ),
        (registration.session_id, "tenant-other/workspace-other"),
    )
    for session_id, scope in attempts:
        observation = _observe_resolver_read(store, path, session_id, scope)
        assert observation.result is None
        assert observation.error is not None
        attempted_details = (session_id, scope)
        if type(scope) is TenantWorkspaceScope:
            attempted_details += (scope.tenant_id, scope.workspace_id)
        _generic_absence(observation.error, *attempted_details)


@pytest.mark.parametrize(
    ("table", "column", "value"),
    (
        ("legacy_sessions", "capture_owner_subject", "capture-owner-replacement"),
        ("legacy_sessions", "capture_owner_subject", "not a pseudonymous subject"),
        ("legacy_sessions", "record_contract_version", "0.0"),
    ),
)
def test_malformed_or_inconsistent_stored_provenance_is_generic_and_read_only(
    tmp_path: Path,
    table: str,
    column: str,
    value: str,
) -> None:
    path = tmp_path / f"bad-provenance-{table}-{column}-{len(value)}.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)
    with sqlite3.connect(path) as connection:
        connection.execute(
            f"update {table} set {column} = ? where session_id = ?",
            (value, str(registration.session_id)),
        )

    observation = _observe_resolver_read(store, path, registration.session_id, SCOPE)
    assert observation.result is None
    assert observation.error is not None
    _generic_absence(observation.error, registration.session_id, value)


@pytest.mark.parametrize(
    ("column", "value"),
    (
        ("session_id", "not-a-persisted-session-uuid"),
        ("session_id", "00000000-0000-4000-8000-ABCDEFABCDEF"),
        ("tenant_id", "NOT-A-NORMALIZED-TENANT"),
        ("workspace_id", sqlite3.Binary(b"workspace-binary")),
    ),
)
def test_persisted_malformed_session_or_scope_is_generic_and_read_only(
    tmp_path: Path,
    column: str,
    value: object,
) -> None:
    path = tmp_path / f"malformed-persisted-{column}.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)
    with sqlite3.connect(path) as connection:
        connection.execute(
            f"update legacy_sessions set {column} = ? where session_id = ?",
            (value, str(registration.session_id)),
        )

    observation = _observe_resolver_read(store, path, registration.session_id, SCOPE)
    assert observation.result is None
    assert observation.error is not None
    _generic_absence(observation.error, registration.session_id, value)


@pytest.mark.parametrize(
    "value",
    (
        pytest.param(sqlite3.Binary(b"capture-owner-binary"), id="blob-type"),
        pytest.param("xy", id="too-short"),
        pytest.param("Capture-owner-synthetic", id="not-normalized"),
        pytest.param("c" * 129, id="too-long"),
    ),
)
def test_consistent_malformed_stored_owner_is_generic_and_read_only(
    tmp_path: Path,
    value: object,
) -> None:
    path = tmp_path / "consistent-malformed-owner.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)
    _corrupt_consistent_capture_owner(path, registration.session_id, value)

    observation = _observe_resolver_read(store, path, registration.session_id, SCOPE)
    assert observation.result is None
    assert observation.error is not None
    _generic_absence(observation.error, registration.session_id, value)


def test_scope_is_in_the_sole_select_and_resolution_never_changes_database_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sole-scoped-select.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)
    observation = _observe_resolver_read(store, path, registration.session_id, SCOPE)
    assert observation.error is None
    assert observation.result is not None
    assert observation.result.authority == ArtifactAuthority(SCOPE, OWNER)

    selects = [
        " ".join(statement.split()).casefold()
        for statement in observation.statements
        if statement.lstrip().casefold().startswith("select")
    ]
    assert len(selects) == 1
    assert "from legacy_sessions as session" in selects[0]
    assert "where session.session_id =" in selects[0]
    assert "and session.tenant_id =" in selects[0]
    assert "and session.workspace_id =" in selects[0]
    assert observation.total_changes == (0,)


def test_failures_are_read_only_by_total_changes_semantics_and_database_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "read-only-failures.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)
    for session_id, scope in ((uuid4(), SCOPE), (registration.session_id, OTHER_SCOPE)):
        observation = _observe_resolver_read(store, path, session_id, scope)
        assert observation.result is None
        assert observation.error is not None
        _generic_absence(
            observation.error,
            session_id,
            scope,
            scope.tenant_id,
            scope.workspace_id,
        )
        assert observation.total_changes == (0,)


def test_active_wal_preserves_durable_bytes_semantics_and_sidecar_inventory(
    tmp_path: Path,
) -> None:
    path = tmp_path / "active-wal.sqlite3"
    store = _store(path)
    registration = _registration()
    _register(store, registration)

    keeper = sqlite3.connect(path)
    try:
        keeper.execute(
            "update legacy_sessions set machine_id = ? where session_id = ?",
            ("machine-active-wal", str(registration.session_id)),
        )
        keeper.commit()
        initial_files = _file_state(path)
        assert initial_files.inventory == ("main", "-wal", "-shm")
        assert initial_files.wal
        assert initial_files.shm

        success = _observe_resolver_read(
            store,
            path,
            registration.session_id,
            SCOPE,
            semantic_connection=keeper,
        )
        assert success.error is None
        assert success.result is not None
        failure = _observe_resolver_read(
            store,
            path,
            registration.session_id,
            OTHER_SCOPE,
            semantic_connection=keeper,
        )
        assert failure.result is None
        assert failure.error is not None
        _generic_absence(
            failure.error,
            registration.session_id,
            OTHER_SCOPE,
            OTHER_SCOPE.tenant_id,
            OTHER_SCOPE.workspace_id,
        )

        snapshots = (
            initial_files,
            success.before_files,
            success.immediate_after_files,
            success.final_files,
            failure.before_files,
            failure.immediate_after_files,
            failure.final_files,
        )
        assert all(snapshot.inventory == ("main", "-wal", "-shm") for snapshot in snapshots)
        assert all(snapshot.main == initial_files.main for snapshot in snapshots)
        assert all(snapshot.wal == initial_files.wal for snapshot in snapshots)
        # The wal-index SHM file contains volatile reader marks and lock coordination.
        # Ordinary safe SQLite reads may change bytes 100..119 only; every other
        # SHM byte, its length, presence, durable bytes, and semantics stay exact.
        assert all(snapshot.shm is not None for snapshot in snapshots)
        for snapshot in snapshots:
            _assert_only_wal_index_reader_marks_changed(initial_files.shm, snapshot.shm)
    finally:
        keeper.close()


def test_worker_and_lease_owners_cannot_replace_durable_capture_owner(tmp_path: Path) -> None:
    legacy_path = tmp_path / "legacy.sqlite3"
    store = _store(legacy_path)
    registration = _registration()
    _register(store, registration)
    object_key = f"sessions/{registration.session_id}/object-key-fallback.zip"
    _run(store.mark_uploaded(registration.session_id, object_key, scope=SCOPE, owner_subject=OWNER))
    _run(
        store.complete_processing(
            registration.session_id,
            _completion(registration.session_id),
            scope=SCOPE,
            actor_subject="worker-fallback-owner",
        )
    )

    control = SQLiteControlStore(tmp_path / "control.sqlite3")
    control.register_job(str(registration.session_id), "b" * 64, now=NOW)
    lease = control.acquire(
        str(registration.session_id),
        "lease-fallback-owner",
        now=NOW,
        ttl_seconds=60,
    )
    control.heartbeat(lease, now=NOW + timedelta(seconds=1), ttl_seconds=60)

    observation = _observe_resolver_read(store, legacy_path, registration.session_id, SCOPE)
    assert observation.error is None
    resolved = observation.result
    assert resolved is not None
    assert resolved.authority == ArtifactAuthority(SCOPE, OWNER)
    assert resolved.authority.capture_owner_subject not in {
        registration.machine_id,
        registration.project_id,
        object_key,
        "worker-fallback-owner",
        "lease-fallback-owner",
    }


def test_resolver_has_no_caller_selected_identity_or_fallback_inputs() -> None:
    signature = inspect.signature(SQLiteLegacySessionStore.resolve_session_capture_authority)
    assert tuple(signature.parameters) == ("self", "session_id", "scope")
    assert signature.parameters["scope"].kind is inspect.Parameter.KEYWORD_ONLY
    prohibited = {
        "owner_subject",
        "actor_subject",
        "machine_id",
        "project_id",
        "lease_owner",
        "object_key",
        "headers",
        "capture_owner_subject",
    }
    assert prohibited.isdisjoint(signature.parameters)
