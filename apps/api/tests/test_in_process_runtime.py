from __future__ import annotations

import builtins
import os
import socket
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from workflow_api.artifact_gateway import NoNetworkArtifactGateway
from workflow_api.browser_session_store import (
    SQLiteBrowserSessionStore,
    StoreBackedBrowserSessionProviderFactory,
)
from workflow_api.candidate_discovery_service import CandidateDiscoveryService
from workflow_api.candidate_publication_store import SQLiteCandidatePublicationStore
from workflow_api.config import Settings
from workflow_api.control_auth import ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.control_service import ControlService
from workflow_api.control_store import SQLiteControlStore
from workflow_api.identity import (
    GroupRoleBinding,
    GroupRoleMapping,
    SubjectScopeBinding,
    SubjectScopePolicy,
)
from workflow_api.legacy_session_composition import ProviderNeutralSecurityComposition
from workflow_api.legacy_session_schema import LegacySessionSchemaError
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.retention_store import RetentionLedger
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetyDomain, SafetySwitchLedger

_PRIMARY_DATABASES = {
    "legacy.sqlite3",
    "browser.sqlite3",
    "control.sqlite3",
    "candidate-publications.sqlite3",
    "retention.sqlite3",
    "safety.sqlite3",
}
_SCOPE = TenantWorkspaceScope("tenant.synthetic", "workspace.synthetic")


class _NeverCalledFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, request: object) -> object:
        del request
        self.calls += 1
        raise AssertionError("construction invoked a request-scoped collaborator")


def _settings(**changes: object) -> Settings:
    values: dict[str, object] = {
        "environment": "synthetic",
        "log_level": "INFO",
        "cors_origins": "https://review.synthetic.example",
        "aws_region": "region.synthetic.example",
        "aws_endpoint_url": None,
        "aws_s3_presigned_endpoint_url": None,
        "raw_bucket": "raw.synthetic.example",
        "processed_bucket": "processed.synthetic.example",
        "processing_queue_url": None,
        "raw_retention_days": 14,
        "presigned_url_ttl_seconds": 900,
        "max_package_size_bytes": 512 * 1024 * 1024,
        "max_metadata_size_bytes": 1024 * 1024,
        "upload_stream_chunk_bytes": 1024 * 1024,
        "upload_spool_memory_bytes": 8 * 1024 * 1024,
    }
    values.update(changes)
    return Settings(_env_file=None, **values)


def _policies() -> tuple[GroupRoleMapping, SubjectScopePolicy]:
    return (
        GroupRoleMapping(
            (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
        ),
        SubjectScopePolicy(
            (SubjectScopeBinding("reviewer.synthetic", _SCOPE),)
        ),
    )


def _construct(
    data_dir: Path,
    *,
    settings: Settings | None = None,
    authenticator_factory: object | None = None,
    workload_factory: object | None = None,
) -> SealedSyntheticRuntimeBundle:
    from workflow_api.in_process_runtime import create_in_process_no_network_bundle

    mapping, policy = _policies()
    return create_in_process_no_network_bundle(
        data_dir=data_dir,
        settings=_settings() if settings is None else settings,
        group_role_mapping=mapping,
        subject_scope_policy=policy,
        authenticator_factory=(
            _NeverCalledFactory()
            if authenticator_factory is None
            else authenticator_factory
        ),  # type: ignore[arg-type]
        workload_credential_verifier_factory=(
            _NeverCalledFactory() if workload_factory is None else workload_factory
        ),  # type: ignore[arg-type]
    )


def _count_rows(path: Path, table: str) -> int:
    with sqlite3.connect(path) as connection:
        row = connection.execute(f"select count(*) from {table}").fetchone()
    assert row is not None
    return int(row[0])


def _assert_only_primary_databases_and_sidecars(data_dir: Path) -> None:
    assert not any(entry.is_dir() for entry in data_dir.iterdir())
    names = {entry.name for entry in data_dir.iterdir()}
    assert _PRIMARY_DATABASES.issubset(names)
    allowed = _PRIMARY_DATABASES | {
        f"{name}{suffix}"
        for name in _PRIMARY_DATABASES
        for suffix in ("-wal", "-shm")
    }
    assert names <= allowed


def test_factory_constructs_exact_six_path_no_network_graph(tmp_path: Path) -> None:
    data_dir = (tmp_path / "explicit-runtime").resolve()
    settings = _settings()
    authenticator_factory = _NeverCalledFactory()
    workload_factory = _NeverCalledFactory()
    actual_import = builtins.__import__

    def reject_provider_import(
        name: str,
        globals: object = None,
        locals: object = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "boto3" or name == "aws_clients" or name.endswith(".aws_clients"):
            raise AssertionError("provider import attempted")
        return actual_import(name, globals, locals, fromlist, level)

    forbidden = AssertionError("ambient runtime access attempted")
    with (
        patch.object(builtins, "__import__", reject_provider_import),
        patch.object(socket, "socket", side_effect=forbidden),
        patch("workflow_api.config.get_settings", side_effect=forbidden),
        patch.object(os._Environ, "get", side_effect=forbidden),
        patch.object(os._Environ, "__getitem__", side_effect=forbidden),
        patch.object(os._Environ, "__iter__", side_effect=forbidden),
    ):
        bundle = _construct(
            data_dir,
            settings=settings,
            authenticator_factory=authenticator_factory,
            workload_factory=workload_factory,
        )

    assert type(bundle) is SealedSyntheticRuntimeBundle
    assert type(bundle.composition) is ProviderNeutralSecurityComposition
    assert type(bundle.legacy_store) is SQLiteLegacySessionStore
    assert type(bundle.browser_store) is SQLiteBrowserSessionStore
    assert type(bundle.browser_factory) is StoreBackedBrowserSessionProviderFactory
    assert type(bundle.candidate_publication_store) is SQLiteCandidatePublicationStore
    assert type(bundle.candidate_discovery_service) is CandidateDiscoveryService
    assert type(bundle.control_service) is ControlService
    assert type(bundle.safety_control_service) is SafetyControlService
    assert type(bundle.artifact_gateway) is NoNetworkArtifactGateway
    assert bundle.settings is settings
    assert bundle.composition.store is bundle.legacy_store
    assert bundle.composition.browser_factory is bundle.browser_factory
    assert bundle.browser_factory.store is bundle.browser_store
    assert bundle.artifact_gateway.presigned_url_ttl_seconds == 900
    assert bundle.artifact_gateway.max_package_size_bytes == 512 * 1024 * 1024
    assert bundle.artifact_gateway._registrations == {}
    assert bundle.artifact_gateway._receipts == {}
    assert bundle.artifact_gateway.queue_evidence == ()
    assert authenticator_factory.calls == 0
    assert workload_factory.calls == 0

    assert Path(bundle.legacy_store.database_path) == data_dir / "legacy.sqlite3"
    assert Path(bundle.browser_store.database_path) == data_dir / "browser.sqlite3"
    assert type(bundle.control_service._store) is SQLiteControlStore
    assert bundle.control_service._store._database_path == str(data_dir / "control.sqlite3")
    assert bundle.candidate_publication_store is not None
    assert bundle.candidate_discovery_service is not None
    assert bundle.candidate_discovery_service._control_service is bundle.control_service
    assert bundle.candidate_discovery_service._publication_store is (
        bundle.candidate_publication_store
    )
    assert bundle.candidate_publication_store.database_path == str(
        data_dir / "candidate-publications.sqlite3"
    )
    assert bundle.candidate_publication_store.control_database_path == str(
        data_dir / "control.sqlite3"
    )
    assert type(bundle.control_service._retention) is RetentionLedger
    assert bundle.control_service._retention.database_path == str(
        data_dir / "retention.sqlite3"
    )
    assert type(bundle.safety_control_service._ledger) is SafetySwitchLedger
    assert bundle.safety_control_service._ledger.database_path == str(
        data_dir / "safety.sqlite3"
    )
    _assert_only_primary_databases_and_sidecars(data_dir)

    assert _count_rows(data_dir / "legacy.sqlite3", "legacy_sessions") == 0
    assert _count_rows(data_dir / "legacy.sqlite3", "legacy_session_events") == 0
    assert _count_rows(data_dir / "legacy.sqlite3", "legacy_workload_principals") == 0
    assert _count_rows(data_dir / "legacy.sqlite3", "legacy_workload_proof_claims") == 0
    assert _count_rows(data_dir / "browser.sqlite3", "browser_sessions") == 0
    assert _count_rows(data_dir / "browser.sqlite3", "browser_session_digest_allocations") == 0
    assert _count_rows(data_dir / "control.sqlite3", "control_jobs") == 0
    assert _count_rows(data_dir / "control.sqlite3", "lease_events") == 0
    assert _count_rows(data_dir / "control.sqlite3", "review_events") == 0
    assert _count_rows(data_dir / "control.sqlite3", "review_projection") == 0
    assert _count_rows(data_dir / "control.sqlite3", "audit_events") == 0
    assert _count_rows(
        data_dir / "candidate-publications.sqlite3", "candidate_publications"
    ) == 0
    assert _count_rows(data_dir / "retention.sqlite3", "retention_targets") == 0
    assert _count_rows(data_dir / "retention.sqlite3", "retention_copies") == 0
    assert _count_rows(data_dir / "retention.sqlite3", "retention_events") == 0
    assert _count_rows(data_dir / "retention.sqlite3", "audit_events") == 0
    assert _count_rows(data_dir / "safety.sqlite3", "safety_switch_events") == 0
    assert _count_rows(data_dir / "safety.sqlite3", "safety_switches") == len(SafetyDomain)


def test_invalid_explicit_inputs_fail_before_path_or_provider_access(
    tmp_path: Path,
) -> None:
    from workflow_api.in_process_runtime import create_in_process_no_network_bundle

    mapping, policy = _policies()
    authenticator_factory = _NeverCalledFactory()
    workload_factory = _NeverCalledFactory()
    bad_settings = _settings(environment="development")
    bad_directories = [
        (tmp_path / "bad-settings").resolve(),
        (tmp_path / "bad-mapping").resolve(),
        (tmp_path / "bad-authenticator").resolve(),
        (tmp_path / "bad-workload").resolve(),
    ]

    with pytest.raises(ValueError, match="synthetic environment"):
        create_in_process_no_network_bundle(
            data_dir=bad_directories[0],
            settings=bad_settings,
            group_role_mapping=mapping,
            subject_scope_policy=policy,
            authenticator_factory=authenticator_factory,
            workload_credential_verifier_factory=workload_factory,
        )
    with pytest.raises(TypeError, match="group-role"):
        create_in_process_no_network_bundle(
            data_dir=bad_directories[1],
            settings=_settings(),
            group_role_mapping=object(),  # type: ignore[arg-type]
            subject_scope_policy=policy,
            authenticator_factory=authenticator_factory,
            workload_credential_verifier_factory=workload_factory,
        )
    with pytest.raises(TypeError, match="authenticator"):
        create_in_process_no_network_bundle(
            data_dir=bad_directories[2],
            settings=_settings(),
            group_role_mapping=mapping,
            subject_scope_policy=policy,
            authenticator_factory=object(),  # type: ignore[arg-type]
            workload_credential_verifier_factory=workload_factory,
        )
    with pytest.raises(TypeError, match="workload credential"):
        create_in_process_no_network_bundle(
            data_dir=bad_directories[3],
            settings=_settings(),
            group_role_mapping=mapping,
            subject_scope_policy=policy,
            authenticator_factory=authenticator_factory,
            workload_credential_verifier_factory=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="pathlib Path"):
        create_in_process_no_network_bundle(
            data_dir=str(tmp_path / "string-path"),  # type: ignore[arg-type]
            settings=_settings(),
            group_role_mapping=mapping,
            subject_scope_policy=policy,
            authenticator_factory=authenticator_factory,
            workload_credential_verifier_factory=workload_factory,
        )
    with pytest.raises(ValueError, match="absolute data directory"):
        create_in_process_no_network_bundle(
            data_dir=Path("relative-runtime"),
            settings=_settings(),
            group_role_mapping=mapping,
            subject_scope_policy=policy,
            authenticator_factory=authenticator_factory,
            workload_credential_verifier_factory=workload_factory,
        )

    assert all(not path.exists() for path in bad_directories)
    assert authenticator_factory.calls == 0
    assert workload_factory.calls == 0

    incompatible_dir = (tmp_path / "incompatible").resolve()
    incompatible_dir.mkdir()
    legacy_path = incompatible_dir / "legacy.sqlite3"
    with sqlite3.connect(legacy_path) as connection:
        connection.execute("create table legacy_sessions (value text not null)")
        connection.execute("insert into legacy_sessions values ('preserve-synthetic')")
    with sqlite3.connect(legacy_path) as connection:
        before_schema = connection.execute(
            "select type, name, sql from sqlite_master order by type, name"
        ).fetchall()
        before_rows = connection.execute("select value from legacy_sessions").fetchall()

    with pytest.raises(LegacySessionSchemaError):
        _construct(
            incompatible_dir,
            authenticator_factory=authenticator_factory,
            workload_factory=workload_factory,
        )

    with sqlite3.connect(legacy_path) as connection:
        after_schema = connection.execute(
            "select type, name, sql from sqlite_master order by type, name"
        ).fetchall()
        after_rows = connection.execute("select value from legacy_sessions").fetchall()
    assert after_schema == before_schema
    assert after_rows == before_rows
    assert {entry.name for entry in incompatible_dir.iterdir()} <= {
        "legacy.sqlite3",
        "legacy.sqlite3-wal",
        "legacy.sqlite3-shm",
    }
    assert authenticator_factory.calls == 0
    assert workload_factory.calls == 0


def _restart_program(data_dir: Path, body: str) -> str:
    common = f"""
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from workflow_api.artifact_gateway import ArtifactAuthority
from workflow_api.config import Settings
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.identity import GroupRoleBinding, GroupRoleMapping, SubjectScopeBinding, SubjectScopePolicy
from workflow_api.in_process_runtime import create_in_process_no_network_bundle
from workflow_api.legacy_session_security import LegacySessionAudience, LegacySessionTransport
from workflow_api.safety_switches import SafetyDomain

data_dir = Path({str(data_dir)!r})
scope = TenantWorkspaceScope("tenant.synthetic", "workspace.synthetic")
settings = Settings(
    _env_file=None,
    environment="synthetic",
    log_level="INFO",
    cors_origins="https://review.synthetic.example",
    aws_region="region.synthetic.example",
    aws_endpoint_url=None,
    aws_s3_presigned_endpoint_url=None,
    raw_bucket="raw.synthetic.example",
    processed_bucket="processed.synthetic.example",
    processing_queue_url=None,
    raw_retention_days=14,
    presigned_url_ttl_seconds=900,
    max_package_size_bytes=512 * 1024 * 1024,
    max_metadata_size_bytes=1024 * 1024,
    upload_stream_chunk_bytes=1024 * 1024,
    upload_spool_memory_bytes=8 * 1024 * 1024,
)
mapping = GroupRoleMapping((GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),))
policy = SubjectScopePolicy((SubjectScopeBinding("reviewer.synthetic", scope),))

def forbidden_authenticator_factory(request):
    raise AssertionError("restart construction invoked authenticator factory")

def forbidden_workload_factory(request):
    raise AssertionError("restart construction invoked workload factory")

bundle = create_in_process_no_network_bundle(
    data_dir=data_dir,
    settings=settings,
    group_role_mapping=mapping,
    subject_scope_policy=policy,
    authenticator_factory=forbidden_authenticator_factory,
    workload_credential_verifier_factory=forbidden_workload_factory,
)
"""
    return textwrap.dedent(common + body)


def test_fresh_process_reopen_preserves_supported_five_store_state(
    tmp_path: Path,
) -> None:
    data_dir = (tmp_path / "restart-runtime").resolve()
    process_a = _restart_program(
        data_dir,
        """
now = datetime.now(UTC)
capture = AuthenticatedPrincipal("capture.synthetic", frozenset({ControlRole.CAPTURE_UPLOADER}), scope)
reviewer = AuthenticatedPrincipal("reviewer.synthetic", frozenset({ControlRole.REVIEWER}), scope)
worker = AuthenticatedPrincipal("worker.synthetic", frozenset({ControlRole.DETERMINISTIC_WORKER}), scope)
retention = AuthenticatedPrincipal("retention.synthetic", frozenset({ControlRole.RETENTION_STEWARD}), scope)
safety = AuthenticatedPrincipal("safety.synthetic", frozenset({ControlRole.SAFETY_STEWARD}), scope)

bundle.legacy_store.register_workload_principal(
    principal_subject=capture.subject,
    scope=scope,
    audience=LegacySessionAudience.CAPTURE_UPLOAD,
    role=ControlRole.CAPTURE_UPLOADER,
    transport=LegacySessionTransport.CAPTURE_WORKLOAD,
)
bundle.browser_store.register_session(
    session_identifier_digest="1" * 64,
    csrf_token_digest="2" * 64,
    principal=reviewer,
    allowed_browser_origin="https://review.synthetic.example",
    issued_at=now - timedelta(minutes=5),
    authenticated_at=now - timedelta(minutes=4),
    last_seen_at=now - timedelta(seconds=1),
    idle_expires_at=now + timedelta(minutes=29),
    absolute_expires_at=now + timedelta(hours=7),
    now=now,
)
bundle.control_service.register_job(
    worker,
    job_id="job.restart",
    payload_digest="a" * 64,
    correlation_id="correlation-job-a",
    idempotency_key="idempotency-job-a",
)
bundle.control_service.register_retention(
    retention,
    target_id="target.restart",
    copies=[{
        "copy_id": "copy.restart",
        "provider": "s3",
        "file_id": "object.synthetic",
        "revision": "revision.synthetic",
        "sha256": "b" * 64,
    }],
    correlation_id="correlation-retention-a",
    idempotency_key="idempotency-retention-a",
    now=now,
)
bundle.safety_control_service.engage(
    safety,
    domain=SafetyDomain.ANALYSIS,
    idempotency_key="idempotency-safety-a",
    correlation_id="correlation-safety-a",
    reason="synthetic restart evidence",
)
authority = ArtifactAuthority(scope, capture.subject)
session_id = UUID("00000000-0000-4000-8000-000000000001")
object_key, _, _ = bundle.artifact_gateway.create_package_upload(
    authority, session_id, "c" * 64, 1024
)
bundle.artifact_gateway.record_receipt(
    authority=authority,
    object_key=object_key,
    package_sha256="c" * 64,
    package_size_bytes=1024,
)
bundle.artifact_gateway.enqueue_processing(authority, session_id, object_key)
assert len(bundle.artifact_gateway.queue_evidence) == 1
""",
    )
    process_b = _restart_program(
        data_dir,
        """
now = datetime.now(UTC)
worker = AuthenticatedPrincipal("worker.synthetic", frozenset({ControlRole.DETERMINISTIC_WORKER}), scope)
retention = AuthenticatedPrincipal("retention.synthetic", frozenset({ControlRole.RETENTION_STEWARD}), scope)
safety = AuthenticatedPrincipal("safety.synthetic", frozenset({ControlRole.SAFETY_STEWARD}), scope)

principal_state = bundle.legacy_store.get_workload_principal(
    principal_subject="capture.synthetic",
    scope=scope,
    audience=LegacySessionAudience.CAPTURE_UPLOAD,
)
assert principal_state.active_generation == 1
browser_context = bundle.browser_store.resolve_session(
    session_identifier_digest="1" * 64,
    now=now,
)
assert browser_context.principal.subject == "reviewer.synthetic"
job = bundle.control_service.register_job(
    worker,
    job_id="job.restart",
    payload_digest="a" * 64,
    correlation_id="correlation-job-b",
    idempotency_key="idempotency-job-b",
)
assert job.job_id == "job.restart"
retention_state = bundle.control_service.read_retention(
    retention,
    target_id="target.restart",
    correlation_id="correlation-retention-b",
)
assert retention_state is not None
assert retention_state.target_id == "target.restart"
events = bundle.safety_control_service.list_events(safety)
assert len(events) == 1
assert events[0].reason == "synthetic restart evidence"
assert bundle.safety_control_service.read_switch(safety, domain=SafetyDomain.ANALYSIS).engaged
assert bundle.artifact_gateway.queue_evidence == ()
""",
    )

    subprocess.run([sys.executable, "-c", process_a], check=True)
    subprocess.run([sys.executable, "-c", process_b], check=True)
    _assert_only_primary_databases_and_sidecars(data_dir)


def test_import_and_default_app_remain_inert_without_runtime_construction(
    tmp_path: Path,
) -> None:
    sentinel_dir = (tmp_path / "default-must-not-exist").resolve()
    program = textwrap.dedent(
        f"""
import builtins
import importlib
import sqlite3
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from workflow_api.artifact_gateway import NoNetworkArtifactGateway
from workflow_api.browser_session_store import SQLiteBrowserSessionStore, StoreBackedBrowserSessionProviderFactory
from workflow_api.candidate_discovery_service import CandidateDiscoveryService
from workflow_api.candidate_publication_store import SQLiteCandidatePublicationStore
from workflow_api.config import Settings
from workflow_api.control_service import ControlService
from workflow_api.control_store import SQLiteControlStore
from workflow_api.legacy_session_composition import ProviderNeutralSecurityComposition
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.retention_store import RetentionLedger
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetySwitchLedger

sentinel_dir = Path({str(sentinel_dir)!r})
actual_import = builtins.__import__

def reject_provider_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "boto3" or name == "aws_clients" or name.endswith(".aws_clients"):
        raise AssertionError("default import attempted provider access")
    return actual_import(name, globals, locals, fromlist, level)

constructors = (
    Settings,
    SQLiteLegacySessionStore,
    SQLiteBrowserSessionStore,
    SQLiteControlStore,
    SQLiteCandidatePublicationStore,
    CandidateDiscoveryService,
    RetentionLedger,
    SafetySwitchLedger,
    StoreBackedBrowserSessionProviderFactory,
    ProviderNeutralSecurityComposition,
    ControlService,
    SafetyControlService,
    NoNetworkArtifactGateway,
    SealedSyntheticRuntimeBundle,
)
with ExitStack() as stack:
    stack.enter_context(patch.object(builtins, "__import__", reject_provider_import))
    stack.enter_context(patch.object(sqlite3, "connect", side_effect=AssertionError("default opened SQLite")))
    stack.enter_context(patch("workflow_api.config.get_settings", side_effect=AssertionError("default read settings")))
    for constructor in constructors:
        stack.enter_context(patch.object(constructor, "__init__", side_effect=AssertionError("default constructed runtime")))
    imported = importlib.import_module("workflow_api.in_process_runtime")
    main = importlib.import_module("workflow_api.main")
    application = main.create_app()

assert callable(imported.create_in_process_no_network_bundle)
assert application.state.runtime_bundle is None
assert main.app.state.runtime_bundle is None
assert not sentinel_dir.exists()
"""
    )
    subprocess.run([sys.executable, "-c", program], check=True)
