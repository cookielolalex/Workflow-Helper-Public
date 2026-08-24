from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Response

from workflow_api.artifact_gateway import ArtifactAuthority
from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    ControlAction,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.identity import (
    GroupRoleBinding,
    GroupRoleMapping,
    SubjectScopeBinding,
    SubjectScopePolicy,
)
from workflow_api.legacy_session_composition import ProviderNeutralSecurityComposition
from workflow_api.legacy_session_schema import (
    LEGACY_SESSION_COMPONENT_ID,
    LEGACY_SESSION_SCHEMA_CHECKSUM,
    LegacySessionSchemaError,
    validate_legacy_session_schema,
)
from workflow_api.legacy_session_security import (
    LegacySessionAudience,
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
)
from workflow_api.legacy_session_store import (
    LegacyWorkloadPrincipalConflictError,
    SQLiteLegacySessionStore,
)
from workflow_api.models import (
    ProcessingCompletion,
    ProcessingCompletionV2,
    SessionCreate,
    UploadComplete,
)
from workflow_api.repository import SessionConflictError, SessionNotFoundError
from workflow_api.routes.sessions import complete_upload

NOW = datetime(2026, 8, 18, 6, 30, tzinfo=UTC)
SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
OTHER_SCOPE = TenantWorkspaceScope("tenant-other", "workspace-other")
OWNER = "capture-owner-synthetic"


def _run(coroutine):
    return asyncio.run(coroutine)


def _registration(session_id: UUID | None = None) -> SessionCreate:
    return SessionCreate(
        schema_version="1.0",
        session_id=session_id or uuid4(),
        machine_id="machine-synthetic-001",
        project_id="project-synthetic",
        started_at=NOW - timedelta(minutes=2),
        ended_at=NOW - timedelta(minutes=1),
        active_duration_seconds=60,
        approved_process="acad",
        package_sha256="a" * 64,
        package_size_bytes=2_048,
    )


def _completion(session_id: UUID, *, event_count: int = 2) -> ProcessingCompletion:
    payload = {
        "schema_version": "1.0",
        "session_id": str(session_id),
        "event_count": event_count,
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


def _completion_v2(session_id: UUID) -> ProcessingCompletionV2:
    source_event_id = uuid4()
    payload = {
        "schema_version": "2.0",
        "session_id": str(session_id),
        "event_count": 1,
        "meaningful_event_count": 1,
        "timeline": [
            {
                "offset_seconds": 1.0,
                "event_type": "cad_command",
                "summary": "Synthetic LINE command",
                "source_event_id": str(source_event_id),
            }
        ],
        "operation_segments": [
            {
                "sequence": 1,
                "start_offset_seconds": 1.0,
                "end_offset_seconds": 1.0,
                "command_names": ["LINE"],
                "drawing_ref": "synthetic-drawing-001",
                "summary": "Observed a synthetic line operation",
                "source_event_ids": [str(source_event_id)],
            }
        ],
        "keyframes": [],
        "warnings": [],
        "output_object_key": f"sessions/{session_id}/timeline-v2.json",
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return ProcessingCompletionV2(
        **payload,
        idempotency_key=hashlib.sha256(canonical).hexdigest(),
    )


def _store(path: Path, *, now: datetime = NOW) -> SQLiteLegacySessionStore:
    return SQLiteLegacySessionStore(path, clock=lambda: now)


def _durable_session_snapshot(
    store: SQLiteLegacySessionStore, session_id: UUID
) -> tuple[tuple[object, ...], tuple[tuple[object, ...], ...], bytes | None]:
    with sqlite3.connect(store.database_path) as connection:
        session = connection.execute(
            "select * from legacy_sessions where session_id = ?",
            (str(session_id),),
        ).fetchone()
        events = connection.execute(
            "select * from legacy_session_events where session_id = ? order by sequence",
            (str(session_id),),
        ).fetchall()
        output_bytes_row = connection.execute(
            "select cast(processing_output_json as blob) from legacy_sessions "
            "where session_id = ?",
            (str(session_id),),
        ).fetchone()
    assert session is not None
    assert output_bytes_row is not None
    return tuple(session), tuple(tuple(event) for event in events), output_bytes_row[0]


def _composition(store: SQLiteLegacySessionStore) -> ProviderNeutralSecurityComposition:
    reviewer = _principal(ControlRole.REVIEWER)
    composition = ProviderNeutralSecurityComposition(
        group_role_mapping=GroupRoleMapping(
            (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
        ),
        subject_scope_policy=SubjectScopePolicy(
            (SubjectScopeBinding(reviewer.subject, SCOPE),)
        ),
        authenticator_factory=lambda request: object(),
        browser_session_provider_factory=lambda request: object(),
        workload_credential_verifier_factory=lambda request: object(),
        store=store,
    )
    assert composition.store is store
    return composition


def _principal(
    role: ControlRole,
    *,
    scope: TenantWorkspaceScope = SCOPE,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        f"{role.value}-synthetic",
        frozenset({role}),
        scope,
    )


def _workload_context(
    *,
    role: ControlRole = ControlRole.CAPTURE_UPLOADER,
    scope: TenantWorkspaceScope = SCOPE,
    proof_digest: str = "d" * 64,
    generation: int = 1,
    body: bytes = b"{}",
    now: datetime = NOW,
) -> LegacyWorkloadContext:
    capture = role is ControlRole.CAPTURE_UPLOADER
    return LegacyWorkloadContext(
        principal=_principal(role, scope=scope),
        audience=(
            LegacySessionAudience.CAPTURE_UPLOAD
            if capture
            else LegacySessionAudience.PROCESSING_COMPLETION
        ),
        transport=(
            LegacySessionTransport.CAPTURE_WORKLOAD
            if capture
            else LegacySessionTransport.WORKER_WORKLOAD
        ),
        method="POST",
        path="/v1/sessions" if capture else "/v1/internal/sessions/abc/processing-completion",
        body_sha256=hashlib.sha256(body).hexdigest(),
        proof_identifier_digest=proof_digest,
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=1),
        generation=generation,
        # These provider decisions are deliberately non-authoritative in this store.
        active_generation=generation + 1,
        revoked=True,
        replay_decision=ReplayDecision.REJECT,
    )


def _register_context_principal(
    store: SQLiteLegacySessionStore,
    context: LegacyWorkloadContext,
) -> None:
    role = next(iter(context.principal.roles))
    assert context.principal.scope is not None
    store.register_workload_principal(
        principal_subject=context.principal.subject,
        scope=context.principal.scope,
        audience=context.audience,
        role=role,
        transport=context.transport,
        active_generation=context.generation,
        now=NOW - timedelta(minutes=1),
    )


def _claim(
    store: SQLiteLegacySessionStore,
    context: LegacyWorkloadContext,
    body: bytes = b"{}",
    *,
    method: str | None = None,
    path: str | None = None,
):
    role = next(iter(context.principal.roles))
    action = (
        ControlAction.SESSION_REGISTER
        if role is ControlRole.CAPTURE_UPLOADER
        else ControlAction.SESSION_PROCESSING_COMPLETE
    )
    return store.claim_workload_proof(
        context=context,
        method=context.method if method is None else method,
        path=context.path if path is None else path,
        body=body,
        action=action,
        audience=context.audience,
        transport=context.transport,
        now=NOW,
    )


def test_constructor_creates_exact_schema_wal_full_foreign_keys_and_reopens(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    first = _store(path)
    second = _store(path)

    assert first.database_path == second.database_path == str(path)
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        validate_legacy_session_schema(connection, require_exclusive=True)
        assert connection.execute("pragma journal_mode").fetchone() == ("wal",)
        manifest = connection.execute(
            "select component_id, schema_checksum from legacy_session_component_schema"
        ).fetchone()
    assert manifest == (LEGACY_SESSION_COMPONENT_ID, LEGACY_SESSION_SCHEMA_CHECKSUM)
    with first._connect() as connection:
        assert connection.execute("pragma synchronous").fetchone()[0] == 2
        assert connection.execute("pragma foreign_keys").fetchone()[0] == 1


@pytest.mark.parametrize("drift", ("partial", "manifest", "shape", "missing_manifest"))
def test_constructor_fails_closed_on_partial_or_drifted_component(
    tmp_path: Path,
    drift: str,
) -> None:
    path = tmp_path / f"{drift}.sqlite3"
    if drift == "partial":
        with sqlite3.connect(path) as connection:
            connection.execute("create table legacy_sessions (session_id text)")
    else:
        _store(path)
        with sqlite3.connect(path) as connection:
            if drift == "manifest":
                connection.execute(
                    "update legacy_session_component_schema set schema_checksum = ?",
                    ("0" * 64,),
                )
            elif drift == "shape":
                connection.execute(
                    "create index legacy_sessions_extra_idx on legacy_sessions(project_id)"
                )
            else:
                connection.execute("delete from legacy_session_component_schema")

    with sqlite3.connect(path) as connection:
        before = connection.execute("pragma journal_mode").fetchone()[0]
    with pytest.raises((LegacySessionSchemaError, sqlite3.OperationalError)):
        _store(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("pragma journal_mode").fetchone()[0] == before


def test_session_lifecycle_is_scoped_atomic_versioned_and_exactly_idempotent(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "sessions.sqlite3")
    registration = _registration()
    created = _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    assert created.processing_status == "registered"
    assert created.raw_expires_at == NOW + timedelta(days=14)

    object_key = f"sessions/{registration.session_id}/packages/{'a' * 64}.zip"
    uploaded, queue_pending = _run(
        store.mark_uploaded(
            registration.session_id,
            object_key,
            scope=SCOPE,
            owner_subject=OWNER,
            expected_state_version=1,
        )
    )
    assert queue_pending and uploaded.processing_status == "uploaded"
    replay, queue_pending = _run(
        store.mark_uploaded(
            registration.session_id,
            object_key,
            scope=SCOPE,
            owner_subject=OWNER,
            expected_state_version=1,
        )
    )
    assert queue_pending and replay.updated_at == uploaded.updated_at

    completion = _completion(registration.session_id)
    processed = _run(
        store.complete_processing(
            registration.session_id,
            completion,
            scope=SCOPE,
            expected_state_version=2,
        )
    )
    exact_replay = _run(
        store.complete_processing(
            registration.session_id,
            completion,
            scope=SCOPE,
            expected_state_version=2,
        )
    )
    assert processed == exact_replay
    assert processed.processing_status == "processed"
    assert processed.review_status == "pending"
    assert _run(store.get_timeline(registration.session_id, scope=SCOPE)) == completion.as_result()
    expected_output_json = json.dumps(
        completion.as_result().model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    )

    events = _run(store.list_events(registration.session_id, scope=SCOPE))
    assert [event.event_type for event in events] == [
        "registered",
        "uploaded",
        "processing_completed",
    ]
    assert [event.state_version for event in events] == [1, 2, 3]
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "select state_version from legacy_sessions where session_id = ?",
            (str(registration.session_id),),
        ).fetchone() == (3,)
        assert connection.execute(
            "select record_contract_version, processing_output_json "
            "from legacy_sessions where session_id = ?",
            (str(registration.session_id),),
        ).fetchone() == ("1.0", expected_output_json)
    reopened = _store(Path(store.database_path))
    assert _run(reopened.get_timeline(registration.session_id, scope=SCOPE)) == completion.as_result()


def test_v2_completion_is_durable_restart_safe_and_exactly_idempotent(tmp_path: Path) -> None:
    database_path = tmp_path / "sessions-v2.sqlite3"
    store = _store(database_path)
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{'a' * 64}.zip"
    _run(store.mark_uploaded(registration.session_id, object_key, scope=SCOPE, owner_subject=OWNER))

    completion = _completion_v2(registration.session_id)
    processed = _run(store.complete_processing(registration.session_id, completion, scope=SCOPE))
    replay = _run(store.complete_processing(registration.session_id, completion, scope=SCOPE))
    assert replay == processed
    assert processed.schema_version == "1.0"
    assert processed.processing_output == completion.as_result()
    expected_output_json = json.dumps(
        completion.as_result().model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "select record_contract_version, processing_output_json "
            "from legacy_sessions where session_id = ?",
            (str(registration.session_id),),
        ).fetchone() == ("1.0", expected_output_json)

    reopened = _store(database_path)
    assert _run(reopened.get_timeline(registration.session_id, scope=SCOPE)) == completion.as_result()
    assert len(_run(reopened.list_events(registration.session_id, scope=SCOPE))) == 3


def test_cross_version_completion_conflicts_without_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path / "cross-version.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{'a' * 64}.zip"
    _run(store.mark_uploaded(registration.session_id, object_key, scope=SCOPE, owner_subject=OWNER))
    completion = _completion(registration.session_id)
    persisted = _run(store.complete_processing(registration.session_id, completion, scope=SCOPE))
    before = _durable_session_snapshot(store, registration.session_id)

    with pytest.raises(SessionConflictError, match="persisted result"):
        _run(
            store.complete_processing(
                registration.session_id,
                _completion_v2(registration.session_id),
                scope=SCOPE,
            )
        )
    assert _durable_session_snapshot(store, registration.session_id) == before
    assert _run(store.get(registration.session_id, scope=SCOPE)) == persisted


@pytest.mark.parametrize(
    "stored_output",
    [
        '{"schema_version":"3.0"}',
        '{"event_count":0}',
        "not-json",
    ],
)
def test_historical_processing_output_requires_exact_known_schema_version(
    tmp_path: Path, stored_output: str
) -> None:
    store = _store(tmp_path / "malformed-history.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "update legacy_sessions set processing_output_json = ? where session_id = ?",
            (stored_output, str(registration.session_id)),
        )
    with pytest.raises(RuntimeError, match="stored processing output is incompatible"):
        _run(store.get(registration.session_id, scope=SCOPE))


def test_completed_replay_fails_closed_before_branching_on_unknown_persisted_output(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "completed-corrupt.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{'a' * 64}.zip"
    _run(store.mark_uploaded(registration.session_id, object_key, scope=SCOPE, owner_subject=OWNER))
    completion = _completion(registration.session_id)
    _run(store.complete_processing(registration.session_id, completion, scope=SCOPE))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "update legacy_sessions set processing_output_json = ? where session_id = ?",
            ('{"schema_version":"3.0"}', str(registration.session_id)),
        )
    before = _durable_session_snapshot(store, registration.session_id)

    with pytest.raises(RuntimeError, match="stored processing output is incompatible"):
        _run(store.complete_processing(registration.session_id, completion, scope=SCOPE))

    assert _durable_session_snapshot(store, registration.session_id) == before


def test_ready_transition_fails_closed_before_overwriting_malformed_persisted_output(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "uploaded-corrupt.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{'a' * 64}.zip"
    _run(store.mark_uploaded(registration.session_id, object_key, scope=SCOPE, owner_subject=OWNER))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "update legacy_sessions set processing_output_json = ? where session_id = ?",
            ("not-json", str(registration.session_id)),
        )
    before = _durable_session_snapshot(store, registration.session_id)

    with pytest.raises(RuntimeError, match="stored processing output is incompatible"):
        _run(
            store.complete_processing(
                registration.session_id,
                _completion_v2(registration.session_id),
                scope=SCOPE,
            )
        )

    assert _durable_session_snapshot(store, registration.session_id) == before


def test_scoped_owner_absence_and_global_uuid_collision_are_generic(tmp_path: Path) -> None:
    store = _store(tmp_path / "scoped.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))

    for scope, owner in (
        (OTHER_SCOPE, None),
        (SCOPE, "capture-owner-other"),
    ):
        with pytest.raises(SessionNotFoundError):
            _run(store.get(registration.session_id, scope=scope, owner_subject=owner))
    with pytest.raises(SessionNotFoundError, match="session unavailable"):
        _run(
            store.create(
                registration,
                14,
                scope=OTHER_SCOPE,
                owner_subject="capture-owner-other",
            )
        )
    assert _run(store.list(scope=OTHER_SCOPE)) == []


def test_scoped_sql_is_executed_before_materialization(tmp_path: Path) -> None:
    store = _store(tmp_path / "trace.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    statements: list[str] = []
    original = store._connect

    def traced_connect():
        connection = original()
        connection.set_trace_callback(statements.append)
        return connection

    store._connect = traced_connect  # type: ignore[method-assign]
    _run(store.get(registration.session_id, scope=SCOPE, owner_subject=OWNER))
    _run(store.list(scope=SCOPE, limit=10))
    trace = " ".join(" ".join(statement.split()).casefold() for statement in statements)
    assert "where session_id =" in trace
    assert "and tenant_id =" in trace
    assert "and workspace_id =" in trace
    assert "and capture_owner_subject =" in trace
    assert "order by started_at_us desc, session_id limit 10" in trace


def test_event_insert_failure_rolls_back_session_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path / "atomic.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            create trigger synthetic_event_failure before insert on legacy_session_events
            when new.event_type = 'uploaded'
            begin select raise(abort, 'synthetic event failure'); end
            """
        )
    with pytest.raises(sqlite3.IntegrityError, match="synthetic event failure"):
        _run(
            store.mark_uploaded(
                registration.session_id,
                "sessions/synthetic/package.zip",
                scope=SCOPE,
                owner_subject=OWNER,
            )
        )
    record = _run(store.get(registration.session_id, scope=SCOPE))
    assert record.processing_status == "registered"
    assert len(_run(store.list_events(registration.session_id, scope=SCOPE))) == 1


def test_registration_event_failure_rolls_back_inserted_session_and_event(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "registration-atomic.sqlite3")
    registration = _registration()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            create trigger synthetic_registration_event_failure
            before insert on legacy_session_events
            when new.event_type = 'registered'
            begin select raise(abort, 'synthetic registration event failure'); end
            """
        )

    with pytest.raises(SessionNotFoundError, match="session unavailable"):
        _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("select count(*) from legacy_sessions").fetchone() == (0,)
        assert connection.execute("select count(*) from legacy_session_events").fetchone() == (0,)


def test_complete_upload_orders_verify_commit_then_queue_with_no_open_external_transaction(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "route-order.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{registration.package_sha256}.zip"
    body = json.dumps({"object_key": object_key}, separators=(",", ":")).encode()
    context = replace(
        _workload_context(body=body),
        principal=AuthenticatedPrincipal(
            OWNER,
            frozenset({ControlRole.CAPTURE_UPLOADER}),
            SCOPE,
        ),
        path=f"/v1/sessions/{registration.session_id}/uploaded",
    )
    _register_context_principal(store, context)
    authorization = store.claim_workload_proof(
        context=context,
        method=context.method,
        path=context.path,
        body=body,
        action=ControlAction.SESSION_UPLOAD_COMPLETE,
        audience=context.audience,
        transport=context.transport,
        now=NOW,
    )

    transaction_open = False
    order: list[str] = []

    @contextmanager
    def tracked_transaction():
        nonlocal transaction_open
        connection = store._connect()
        try:
            connection.execute("begin immediate")
            transaction_open = True
            yield connection
            connection.commit()
            order.append("commit")
        except BaseException:
            connection.rollback()
            raise
        finally:
            transaction_open = False
            connection.close()

    store._transaction = tracked_transaction  # type: ignore[method-assign]

    class Gateway:
        def verify_package_upload(
            self,
            authority: ArtifactAuthority,
            supplied_key: str,
            existing,
        ) -> None:
            assert not transaction_open
            assert authority == ArtifactAuthority(SCOPE, OWNER)
            assert supplied_key == object_key
            assert existing.processing_status == "registered"
            order.append("verify")

        def enqueue_processing(
            self,
            authority: ArtifactAuthority,
            session_id: UUID,
            supplied_key: str,
        ) -> None:
            assert not transaction_open
            assert authority == ArtifactAuthority(SCOPE, OWNER)
            assert session_id == registration.session_id
            assert supplied_key == object_key
            with sqlite3.connect(store.database_path) as connection:
                assert connection.execute(
                    """
                    select processing_status, state_version from legacy_sessions
                    where session_id = ? and tenant_id = ? and workspace_id = ?
                    """,
                    (str(session_id), SCOPE.tenant_id, SCOPE.workspace_id),
                ).fetchone() == ("uploaded", 2)
                assert connection.execute(
                    "select count(*) from legacy_session_events where session_id = ?",
                    (str(session_id),),
                ).fetchone() == (2,)
            order.append("queue")

    response = Response()
    result = _run(
        complete_upload(
            registration.session_id,
            authorization,
            UploadComplete(object_key=object_key),
            response,
            _composition(store),
            Gateway(),
        )
    )

    assert result.processing_status == "uploaded"
    assert response.status_code == 202
    assert order == ["verify", "commit", "queue"]


@pytest.mark.parametrize(
    ("scope", "subject"),
    (
        (OTHER_SCOPE, OWNER),
        (SCOPE, "capture-owner-other"),
    ),
    ids=("wrong-scope", "wrong-owner"),
)
def test_complete_upload_rejects_wrong_scope_or_owner_before_external_calls(
    tmp_path: Path,
    scope: TenantWorkspaceScope,
    subject: str,
) -> None:
    store = _store(tmp_path / f"route-absence-{scope.workspace_id}-{subject}.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{registration.package_sha256}.zip"
    body = json.dumps({"object_key": object_key}, separators=(",", ":")).encode()
    context = replace(
        _workload_context(scope=scope, body=body, proof_digest=hashlib.sha256(subject.encode()).hexdigest()),
        principal=AuthenticatedPrincipal(
            subject,
            frozenset({ControlRole.CAPTURE_UPLOADER}),
            scope,
        ),
        path=f"/v1/sessions/{registration.session_id}/uploaded",
    )
    _register_context_principal(store, context)
    authorization = store.claim_workload_proof(
        context=context,
        method=context.method,
        path=context.path,
        body=body,
        action=ControlAction.SESSION_UPLOAD_COMPLETE,
        audience=context.audience,
        transport=context.transport,
        now=NOW,
    )

    class Gateway:
        calls = 0

        def verify_package_upload(
            self, authority: ArtifactAuthority, object_key: str, existing
        ) -> None:
            self.calls += 1

        def enqueue_processing(
            self,
            authority: ArtifactAuthority,
            session_id: UUID,
            object_key: str,
        ) -> None:
            self.calls += 1

    gateway = Gateway()
    with pytest.raises(HTTPException) as error:
        _run(
            complete_upload(
                registration.session_id,
                authorization,
                UploadComplete(object_key=object_key),
                Response(),
                _composition(store),
                gateway,
            )
        )
    assert error.value.status_code == 404
    assert gateway.calls == 0


def test_completion_conflict_and_stale_optimistic_version_do_not_append(tmp_path: Path) -> None:
    store = _store(tmp_path / "conflict.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    object_key = f"sessions/{registration.session_id}/packages/{'a' * 64}.zip"
    _run(store.mark_uploaded(registration.session_id, object_key, scope=SCOPE, owner_subject=OWNER))
    with pytest.raises(SessionConflictError, match="state version"):
        _run(
            store.complete_processing(
                registration.session_id,
                _completion(registration.session_id),
                scope=SCOPE,
                expected_state_version=1,
            )
        )
    completion = _completion(registration.session_id)
    _run(store.complete_processing(registration.session_id, completion, scope=SCOPE))
    with pytest.raises(SessionConflictError, match="persisted result"):
        _run(
            store.complete_processing(
                registration.session_id,
                _completion(registration.session_id, event_count=3),
                scope=SCOPE,
            )
        )
    assert len(_run(store.list_events(registration.session_id, scope=SCOPE))) == 3


def test_events_and_proof_claims_are_immutable(tmp_path: Path) -> None:
    store = _store(tmp_path / "immutable.sqlite3")
    registration = _registration()
    _run(store.create(registration, 14, scope=SCOPE, owner_subject=OWNER))
    context = _workload_context()
    _register_context_principal(store, context)
    _claim(store, context)
    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("update legacy_session_events set to_state = 'failed'")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("delete from legacy_session_events")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("update legacy_workload_proof_claims set generation = 2")


def test_concurrent_proof_claim_has_one_global_winner_and_retention_floor(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "claims.sqlite3")
    context = _workload_context()
    _register_context_principal(store, context)

    def attempt() -> str:
        try:
            _claim(store, context)
        except LegacySessionSecurityRejectedError as exc:
            return str(exc)
        return "accepted"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: attempt(), range(8)))
    assert results.count("accepted") == 1
    assert results.count("request authorization rejected") == 7
    with sqlite3.connect(store.database_path) as connection:
        claim = connection.execute(
            """
            select expires_at_us, retain_until_us
            from legacy_workload_proof_claims
            """
        ).fetchone()
    assert claim is not None
    assert claim[1] >= claim[0] + 60_000_000


def test_durable_generation_revocation_and_binding_are_authoritative(tmp_path: Path) -> None:
    store = _store(tmp_path / "authority.sqlite3")
    context = _workload_context(proof_digest="1" * 64)
    _register_context_principal(store, context)
    # Provider-supplied active/revoked/replay fields disagree, but durable state wins.
    assert _claim(store, context).principal == context.principal

    principal = store.get_workload_principal(
        principal_subject=context.principal.subject,
        scope=SCOPE,
        audience=context.audience,
    )
    rotated = store.rotate_workload_generation(
        principal_subject=context.principal.subject,
        scope=SCOPE,
        audience=context.audience,
        expected_state_version=principal.state_version,
        new_generation=2,
        now=NOW,
    )
    with pytest.raises(LegacySessionSecurityRejectedError):
        _claim(store, replace(context, proof_identifier_digest="2" * 64))

    fresh = replace(
        context,
        proof_identifier_digest="3" * 64,
        generation=2,
        active_generation=1,
    )
    assert _claim(store, fresh).principal == context.principal
    store.revoke_workload_principal(
        principal_subject=context.principal.subject,
        scope=SCOPE,
        audience=context.audience,
        expected_state_version=rotated.state_version,
        now=NOW,
    )
    with pytest.raises(LegacySessionSecurityRejectedError):
        _claim(store, replace(fresh, proof_identifier_digest="4" * 64))


@pytest.mark.parametrize(
    "case",
    ("wrong-role", "wrong-audience", "wrong-transport", "cross-scope"),
)
def test_role_audience_transport_and_cross_scope_proofs_reject_generically(
    tmp_path: Path,
    case: str,
) -> None:
    store = _store(tmp_path / f"proof-boundary-{case}.sqlite3")
    context = _workload_context()
    _register_context_principal(store, context)
    audience = LegacySessionAudience.CAPTURE_UPLOAD
    transport = LegacySessionTransport.CAPTURE_WORKLOAD

    if case == "wrong-role":
        context = replace(
            context,
            principal=AuthenticatedPrincipal(
                context.principal.subject,
                frozenset({ControlRole.DETERMINISTIC_WORKER}),
                SCOPE,
            ),
        )
    elif case == "wrong-audience":
        audience = LegacySessionAudience.PROCESSING_COMPLETION
    elif case == "wrong-transport":
        transport = LegacySessionTransport.WORKER_WORKLOAD
    else:
        context = replace(
            context,
            principal=AuthenticatedPrincipal(
                context.principal.subject,
                frozenset({ControlRole.CAPTURE_UPLOADER}),
                OTHER_SCOPE,
            ),
        )

    with pytest.raises(
        LegacySessionSecurityRejectedError,
        match="request authorization rejected",
    ):
        store.claim_workload_proof(
            context=context,
            method=context.method,
            path=context.path,
            body=b"{}",
            action=ControlAction.SESSION_REGISTER,
            audience=audience,
            transport=transport,
            now=NOW,
        )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "select count(*) from legacy_workload_proof_claims"
        ).fetchone() == (0,)


@pytest.mark.parametrize("case", ("method", "path", "body", "future", "expired"))
def test_invalid_freshness_and_request_binding_reject_generically_without_claim(
    tmp_path: Path,
    case: str,
) -> None:
    store = _store(tmp_path / "binding.sqlite3")
    context = _workload_context()
    _register_context_principal(store, context)
    changed = context
    method = context.method
    path = context.path
    if case == "method":
        method = "GET"
    elif case == "path":
        path = f"/v1/sessions/{uuid4()}"
    elif case == "body":
        changed = replace(context, body_sha256="f" * 64)
    elif case == "future":
        changed = replace(
            context,
            issued_at=NOW + timedelta(seconds=61),
            expires_at=NOW + timedelta(seconds=121),
        )
    elif case == "expired":
        changed = replace(context, expires_at=NOW)
    with pytest.raises(
        LegacySessionSecurityRejectedError,
        match="request authorization rejected",
    ):
        _claim(store, changed, method=method, path=path)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "select count(*) from legacy_workload_proof_claims"
        ).fetchone() == (0,)


def test_rotation_and_revocation_require_current_optimistic_version(tmp_path: Path) -> None:
    store = _store(tmp_path / "principal-conflict.sqlite3")
    context = _workload_context()
    _register_context_principal(store, context)
    with pytest.raises(LegacyWorkloadPrincipalConflictError):
        store.rotate_workload_generation(
            principal_subject=context.principal.subject,
            scope=SCOPE,
            audience=context.audience,
            expected_state_version=2,
            new_generation=2,
            now=NOW,
        )
    current = store.get_workload_principal(
        principal_subject=context.principal.subject,
        scope=SCOPE,
        audience=context.audience,
    )
    assert (current.active_generation, current.state_version, current.revoked_at) == (1, 1, None)
