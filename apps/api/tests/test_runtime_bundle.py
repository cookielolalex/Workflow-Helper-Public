from __future__ import annotations

import base64
import builtins
import hashlib
import importlib
import re
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import workflow_api.main as main_module
from workflow_api.artifact_gateway import (
    ArtifactAuthority,
    ArtifactGateway,
    ArtifactGatewayUnavailableError,
    ArtifactQueueEvidence,
    NoNetworkArtifactGateway,
)
from workflow_api.browser_session_store import (
    SQLiteBrowserSessionStore,
    StoreBackedBrowserSessionProviderFactory,
    StoreBackedSessionSecurityContextProvider,
)
from workflow_api.candidate_discovery_service import CandidateDiscoveryService
from workflow_api.candidate_publication_store import SQLiteCandidatePublicationStore
from workflow_api.config import Settings
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.control_service import ControlService
from workflow_api.control_store import SQLiteControlStore
from workflow_api.dependencies import (
    get_artifact_gateway,
    get_authenticated_principal,
    get_control_service,
    get_provider_neutral_security_composition,
    get_runtime_bundle,
    get_runtime_settings,
    get_safety_control_service,
)
from workflow_api.identity import (
    AuthenticationAssurance,
    AuthenticationContext,
    AuthenticationMethod,
    GroupRoleBinding,
    GroupRoleMapping,
    IdentityRejectedError,
    SubjectScopeBinding,
    SubjectScopePolicy,
    VerifiedIdentityEvidence,
)
from workflow_api.legacy_session_composition import ProviderNeutralSecurityComposition
from workflow_api.legacy_session_security import (
    LegacySessionAudience,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
)
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.main import create_app
from workflow_api.models import SessionCreate, SessionRecord
from workflow_api.retention_store import RetentionLedger
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetySwitchLedger
from workflow_api.session_security import csrf_token_digest

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
OTHER_SCOPE = TenantWorkspaceScope("tenant-other", "workspace-other")
AUTHORITY = ArtifactAuthority(SCOPE, "capture-synthetic")
NOW = datetime.now(UTC)
SESSION_MATERIAL = base64.urlsafe_b64encode(b"s" * 32).decode().rstrip("=")
CSRF_MATERIAL = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")


class SyntheticAuthenticator:
    def __init__(
        self,
        principal: AuthenticatedPrincipal,
        calls: list[str],
        *,
        reject: bool = False,
    ) -> None:
        self.principal = principal
        self.calls = calls
        self.reject = reject

    def authenticate(self) -> VerifiedIdentityEvidence:
        self.calls.append("identity")
        if self.reject:
            raise IdentityRejectedError("synthetic rejected evidence")
        return VerifiedIdentityEvidence(
            self.principal.subject,
            ("reviewers",),
            AuthenticationContext(
                AuthenticationAssurance.MULTI_FACTOR,
                (AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
            ),
            self.principal.scope,
        )


class SyntheticWorkloadVerifier:
    def __init__(
        self,
        capture: AuthenticatedPrincipal,
        worker: AuthenticatedPrincipal,
        calls: list[str],
        *,
        fixed_proof: str | None = None,
    ) -> None:
        self.capture = capture
        self.worker = worker
        self.calls = calls
        self.fixed_proof = fixed_proof
        self.counter = 0

    def get_workload_context(self, *, method, path, body_sha256, headers):
        del headers
        self.calls.append("workload")
        self.counter += 1
        is_worker = path.startswith("/v1/internal/")
        principal = self.worker if is_worker else self.capture
        proof = self.fixed_proof or hashlib.sha256(str(self.counter).encode()).hexdigest()
        now = datetime.now(UTC)
        return LegacyWorkloadContext(
            principal=principal,
            audience=(
                LegacySessionAudience.PROCESSING_COMPLETION
                if is_worker
                else LegacySessionAudience.CAPTURE_UPLOAD
            ),
            transport=(
                LegacySessionTransport.WORKER_WORKLOAD
                if is_worker
                else LegacySessionTransport.CAPTURE_WORKLOAD
            ),
            method=method,
            path=path,
            body_sha256=body_sha256,
            proof_identifier_digest=proof,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=1),
            generation=1,
            active_generation=1,
            revoked=False,
            replay_decision=ReplayDecision.ACCEPT,
        )


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


def _bundle(
    tmp_path: Path,
    *,
    fixed_proof: str | None = None,
    reject_identity: bool = False,
    scope: TenantWorkspaceScope = SCOPE,
    capture_subject: str = "capture-synthetic",
    artifact_gateway: ArtifactGateway | None = None,
    settings: Settings | None = None,
) -> tuple[
    SealedSyntheticRuntimeBundle,
    list[str],
    AuthenticatedPrincipal,
    SyntheticWorkloadVerifier,
]:
    calls: list[str] = []
    reviewer = AuthenticatedPrincipal(
        "reviewer-synthetic",
        frozenset({ControlRole.REVIEWER}),
        scope,
    )
    capture = AuthenticatedPrincipal(
        capture_subject, frozenset({ControlRole.CAPTURE_UPLOADER}), scope
    )
    worker = AuthenticatedPrincipal(
        "worker-synthetic", frozenset({ControlRole.DETERMINISTIC_WORKER}), scope
    )
    legacy_store = SQLiteLegacySessionStore(tmp_path / "legacy.sqlite3")
    legacy_store.register_workload_principal(
        principal_subject=capture.subject,
        scope=scope,
        audience=LegacySessionAudience.CAPTURE_UPLOAD,
        role=ControlRole.CAPTURE_UPLOADER,
        transport=LegacySessionTransport.CAPTURE_WORKLOAD,
    )
    legacy_store.register_workload_principal(
        principal_subject=worker.subject,
        scope=scope,
        audience=LegacySessionAudience.PROCESSING_COMPLETION,
        role=ControlRole.DETERMINISTIC_WORKER,
        transport=LegacySessionTransport.WORKER_WORKLOAD,
    )
    browser_store = SQLiteBrowserSessionStore(tmp_path / "browser.sqlite3")
    browser_store.register_session(
        session_identifier_digest=hashlib.sha256(b"s" * 32).hexdigest(),
        csrf_token_digest=csrf_token_digest(CSRF_MATERIAL),
        principal=reviewer,
        allowed_browser_origin="https://review.synthetic.example",
        issued_at=NOW - timedelta(minutes=5),
        authenticated_at=NOW - timedelta(minutes=4),
        last_seen_at=NOW - timedelta(seconds=1),
        idle_expires_at=NOW + timedelta(minutes=29),
        absolute_expires_at=NOW + timedelta(hours=7),
        now=NOW,
    )
    browser_factory = StoreBackedBrowserSessionProviderFactory(store=browser_store)
    authenticator = SyntheticAuthenticator(reviewer, calls, reject=reject_identity)
    verifier = SyntheticWorkloadVerifier(
        capture, worker, calls, fixed_proof=fixed_proof
    )
    composition = ProviderNeutralSecurityComposition(
        group_role_mapping=GroupRoleMapping(
            (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
        ),
        subject_scope_policy=SubjectScopePolicy(
            (SubjectScopeBinding(reviewer.subject, scope),)
        ),
        authenticator_factory=lambda request: authenticator,
        browser_session_provider_factory=browser_factory,
        workload_credential_verifier_factory=lambda request: verifier,
        store=legacy_store,
    )
    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    control_service = ControlService(
        control_store,
        RetentionLedger(tmp_path / "retention.sqlite3"),
    )
    safety_service = SafetyControlService(SafetySwitchLedger(tmp_path / "safety.sqlite3"))
    settings = settings if settings is not None else _settings()
    gateway = artifact_gateway if artifact_gateway is not None else NoNetworkArtifactGateway(
        ticket_origin="https://uploads.synthetic.example",
        presigned_url_ttl_seconds=settings.presigned_url_ttl_seconds,
        max_package_size_bytes=settings.max_package_size_bytes,
    )
    bundle = SealedSyntheticRuntimeBundle(
        composition=composition,
        legacy_store=legacy_store,
        browser_store=browser_store,
        browser_factory=browser_factory,
        control_service=control_service,
        safety_control_service=safety_service,
        settings=settings,
        artifact_gateway=gateway,
    )
    return bundle, calls, reviewer, verifier


def _rebuild_bundle(
    bundle: SealedSyntheticRuntimeBundle,
    *,
    artifact_gateway: object,
    settings: Settings | None = None,
    candidate_publication_store: SQLiteCandidatePublicationStore | None = None,
    candidate_discovery_service: CandidateDiscoveryService | None = None,
) -> SealedSyntheticRuntimeBundle:
    return SealedSyntheticRuntimeBundle(
        composition=bundle.composition,
        legacy_store=bundle.legacy_store,
        browser_store=bundle.browser_store,
        browser_factory=bundle.browser_factory,
        control_service=bundle.control_service,
        safety_control_service=bundle.safety_control_service,
        settings=settings if settings is not None else bundle.settings,
        artifact_gateway=artifact_gateway,  # type: ignore[arg-type]
        candidate_publication_store=candidate_publication_store,
        candidate_discovery_service=candidate_discovery_service,
    )


def _registration(session_id: UUID, digest: str = "a" * 64, size: int = 1024):
    return {
        "schema_version": "1.0",
        "session_id": str(session_id),
        "machine_id": "machine-synthetic",
        "project_id": "synthetic",
        "started_at": "2026-08-16T04:00:00Z",
        "ended_at": "2026-08-16T04:01:00Z",
        "active_duration_seconds": 60,
        "approved_process": "acad",
        "package_sha256": digest,
        "package_size_bytes": size,
    }


def _api_routes(application) -> list[APIRoute]:
    routes: list[APIRoute] = []
    for route in application.routes:
        if isinstance(route, APIRoute):
            routes.append(route)
        elif hasattr(route, "original_router"):
            routes.extend(
                item
                for item in route.original_router.routes
                if isinstance(item, APIRoute)
            )
    return routes


def test_default_factory_is_inert_health_only_and_route_inventory_is_exact() -> None:
    explode = AssertionError("default app factory performed a forbidden operation")
    actual_import = builtins.__import__
    aws_import_attempts: list[str] = []

    def reject_aws_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "aws_clients" or name.endswith(".aws_clients"):
            aws_import_attempts.append(name)
            raise explode
        return actual_import(name, globals, locals, fromlist, level)

    constructors = (
        (NoNetworkArtifactGateway, "__init__"),
        (SQLiteBrowserSessionStore, "__init__"),
        (StoreBackedBrowserSessionProviderFactory, "__init__"),
        (ProviderNeutralSecurityComposition, "__init__"),
        (SQLiteLegacySessionStore, "__init__"),
        (SQLiteControlStore, "__init__"),
        (ControlService, "__init__"),
        (RetentionLedger, "__init__"),
        (SafetySwitchLedger, "__init__"),
        (SafetyControlService, "__init__"),
    )
    collaborator_types = (
        ProviderNeutralSecurityComposition,
        StoreBackedSessionSecurityContextProvider,
        NoNetworkArtifactGateway,
        SQLiteLegacySessionStore,
        SQLiteBrowserSessionStore,
        SQLiteControlStore,
        ControlService,
        RetentionLedger,
        SafetySwitchLedger,
        SafetyControlService,
    )
    collaborator_access = tuple(
        (owner, name)
        for owner in collaborator_types
        for name, value in vars(owner).items()
        if not name.startswith("_") and callable(value)
    ) + (
        (StoreBackedBrowserSessionProviderFactory, "__call__"),
    )
    with ExitStack() as sentinels:
        boto_client = sentinels.enter_context(
            patch("boto3.client", side_effect=explode)
        )
        for target in (
            patch("workflow_api.config.Settings.__init__", side_effect=explode),
            patch("workflow_api.config.Settings.model_construct", side_effect=explode),
            patch("workflow_api.config.Settings.model_validate", side_effect=explode),
            patch("sqlite3.connect", side_effect=explode),
            patch("pathlib.Path.mkdir", side_effect=explode),
            patch("pathlib.Path.open", side_effect=explode),
            patch("os.open", side_effect=explode),
            patch(
                "pydantic_settings.sources.providers.env.EnvSettingsSource.__call__",
                side_effect=explode,
            ),
            patch(
                "pydantic_settings.sources.providers.dotenv.DotEnvSettingsSource.__call__",
                side_effect=explode,
            ),
            patch("socket.socket.connect", side_effect=explode),
            patch("socket.socket.connect_ex", side_effect=explode),
            patch("socket.create_connection", side_effect=explode),
            patch("builtins.open", side_effect=explode),
            patch("builtins.__import__", side_effect=reject_aws_import),
        ):
            sentinels.enter_context(target)
        for owner, name in constructors + collaborator_access:
            sentinels.enter_context(patch.object(owner, name, side_effect=explode))
        application = importlib.reload(main_module).create_app()
        client = TestClient(application)
        assert client.get("/health").status_code == 200
        routes = _api_routes(application)
        assert len(routes) == 29
        assert sum(route.path != "/health" for route in routes) == 28
        assert sum(
            route.path.startswith("/v1/control/")
            and bool(route.methods & {"POST", "PUT", "PATCH", "DELETE"})
            for route in routes
        ) == 11
        assert application.state.runtime_bundle is None
        for route in routes:
            if route.path == "/health":
                continue
            path = re.sub(
                r"\{([^}]+)\}",
                lambda match: (
                    "00000000-0000-4000-8000-000000000000"
                    if match.group(1) == "session_id"
                    else "capture"
                    if match.group(1) == "domain"
                    else "synthetic"
                ),
                route.path,
            )
            method = next(iter(route.methods))
            response = client.request(
                method, path, json={} if method == "POST" else None
            )
            assert response.status_code == 503, (method, path, response.text)
            assert len(response.content) <= 64
        for framework_path in (
            "/docs",
            "/docs/oauth2-redirect",
            "/redoc",
            "/openapi.json",
        ):
            assert client.get(framework_path).status_code == 404
        preflight = client.options(
            "/v1/control/jobs",
            headers={
                "Origin": "https://review.synthetic.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert preflight.status_code == 400
        assert "access-control-allow-origin" not in preflight.headers
        assert not boto_client.called
        assert aws_import_attempts == []


def test_exact_bundle_roots_repeat_identical_singletons(tmp_path: Path) -> None:
    bundle, _, _, _ = _bundle(tmp_path)
    assert type(bundle.artifact_gateway) is NoNetworkArtifactGateway
    assert get_provider_neutral_security_composition(bundle) is bundle.composition
    assert get_control_service(bundle) is bundle.control_service
    assert get_safety_control_service(bundle) is bundle.safety_control_service
    assert get_runtime_settings(bundle) is bundle.settings
    assert get_artifact_gateway(bundle) is bundle.artifact_gateway
    assert get_artifact_gateway.__annotations__["return"] is ArtifactGateway
    assert bundle.composition.store is bundle.legacy_store
    assert bundle.composition.browser_factory is bundle.browser_factory
    assert bundle.browser_factory.store is bundle.browser_store
    application = create_app(bundle)
    assert application.state.runtime_bundle is bundle
    assert application.dependency_overrides[get_runtime_bundle]() is bundle
    client = TestClient(application)
    for framework_path in (
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/openapi.json",
    ):
        assert client.get(framework_path).status_code == 404
    allowed = client.options(
        "/v1/control/jobs",
        headers={
            "Origin": "https://review.synthetic.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == (
        "https://review.synthetic.example"
    )
    denied = client.options(
        "/v1/control/jobs",
        headers={
            "Origin": "https://other.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_candidate_router_is_conditional_on_explicit_no_network_pair(
    tmp_path: Path,
) -> None:
    bundle, _, reviewer, _ = _bundle(tmp_path)
    path = "/v1/control/candidate-publications?correlation_id=candidate-route"

    # The existing bundle has no candidate pair, so its route remains dormant.
    assert TestClient(create_app(bundle)).get(path).status_code == 404

    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate-publications.sqlite3",
        control_database_path=bundle.control_service._store,
    )
    discovery_service = CandidateDiscoveryService(
        publication_store,
        bundle.control_service,
    )
    candidate_bundle = _rebuild_bundle(
        bundle,
        artifact_gateway=bundle.artifact_gateway,
        candidate_publication_store=publication_store,
        candidate_discovery_service=discovery_service,
    )
    application = create_app(candidate_bundle)
    application.dependency_overrides[get_authenticated_principal] = lambda: reviewer
    application.dependency_overrides[main_module.require_control_session_security] = (
        lambda: None
    )
    response = TestClient(application).get(path)
    assert response.status_code == 200, response.text
    assert response.json() == {"items": [], "count": 0, "next_cursor": None}
    assert candidate_bundle.candidate_publication_store is publication_store
    assert candidate_bundle.candidate_discovery_service is discovery_service
    assert discovery_service._control_service is candidate_bundle.control_service
    assert discovery_service._publication_store is publication_store
    assert publication_store.control_database_path == str(
        tmp_path / "control.sqlite3"
    )
    assert publication_store.database_path != publication_store.control_database_path

    # A complete pair does not activate the route for a provider-backed graph.
    from workflow_api.aws_clients import AwsGateway

    with patch("boto3.client", side_effect=[object(), object(), object()]):
        provider_bundle = _rebuild_bundle(
            candidate_bundle,
            artifact_gateway=AwsGateway(candidate_bundle.settings),
            candidate_publication_store=publication_store,
            candidate_discovery_service=discovery_service,
        )
    assert TestClient(create_app(provider_bundle)).get(path).status_code == 404


def test_candidate_pair_rejects_partial_identity_and_path_mismatch(
    tmp_path: Path,
) -> None:
    bundle, _, _, _ = _bundle(tmp_path)
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate-publications.sqlite3",
        control_database_path=bundle.control_service._store,
    )
    with pytest.raises(ValueError, match="pair must be complete"):
        _rebuild_bundle(
            bundle,
            artifact_gateway=bundle.artifact_gateway,
            candidate_publication_store=publication_store,
        )
    with pytest.raises(ValueError, match="store identity"):
        _rebuild_bundle(
            bundle,
            artifact_gateway=bundle.artifact_gateway,
            candidate_publication_store=publication_store,
            candidate_discovery_service=CandidateDiscoveryService(
                SQLiteCandidatePublicationStore(
                    tmp_path / "other-publications.sqlite3",
                    control_database_path=bundle.control_service._store,
                ),
                bundle.control_service,
            ),
        )

    same_path_store = object.__new__(SQLiteCandidatePublicationStore)
    object.__setattr__(same_path_store, "_database_path", str(tmp_path / "control.sqlite3"))
    object.__setattr__(same_path_store, "_control_database_path", str(tmp_path / "control.sqlite3"))
    same_path_service = CandidateDiscoveryService(same_path_store, bundle.control_service)
    with pytest.raises(ValueError, match="distinct"):
        _rebuild_bundle(
            bundle,
            artifact_gateway=bundle.artifact_gateway,
            candidate_publication_store=same_path_store,
            candidate_discovery_service=same_path_service,
        )


def test_candidate_registration_keeps_auth_and_session_before_service(
    tmp_path: Path,
) -> None:
    bundle, _, reviewer, _ = _bundle(tmp_path)
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate-publications.sqlite3",
        control_database_path=bundle.control_service._store,
    )
    discovery_service = CandidateDiscoveryService(
        publication_store,
        bundle.control_service,
    )
    candidate_bundle = _rebuild_bundle(
        bundle,
        artifact_gateway=bundle.artifact_gateway,
        candidate_publication_store=publication_store,
        candidate_discovery_service=discovery_service,
    )
    from workflow_api.routes.candidate_discovery import get_candidate_discovery_service

    auth_application = create_app(candidate_bundle)
    def rejected_authentication() -> AuthenticatedPrincipal:
        raise HTTPException(status_code=401, detail="identity rejected")

    auth_application.dependency_overrides[get_authenticated_principal] = (
        rejected_authentication
    )
    service_called = False

    def forbidden_service() -> CandidateDiscoveryService:
        nonlocal service_called
        service_called = True
        raise AssertionError("candidate service resolved before authentication")

    auth_application.dependency_overrides[get_candidate_discovery_service] = (
        forbidden_service
    )
    auth_application.dependency_overrides[main_module.require_control_session_security] = (
        lambda: None
    )
    response = TestClient(auth_application).get(
        "/v1/control/candidate-publications?correlation_id=auth-order"
    )
    assert response.status_code == 401
    assert service_called is False

    session_application = create_app(candidate_bundle)
    session_application.dependency_overrides[get_authenticated_principal] = lambda: reviewer
    session_application.dependency_overrides[get_candidate_discovery_service] = (
        forbidden_service
    )

    def rejected_session() -> None:
        raise HTTPException(status_code=503, detail="session security unavailable")

    session_application.dependency_overrides[main_module.require_control_session_security] = (
        rejected_session
    )
    response = TestClient(session_application).get(
        "/v1/control/candidate-publications?correlation_id=session-order"
    )
    assert response.status_code == 503
    assert service_called is False


def test_exact_prebuilt_aws_gateway_is_admitted_by_identity_and_same_settings(
    tmp_path: Path,
) -> None:
    from workflow_api.aws_clients import AwsGateway

    settings = _settings()
    clients = [object(), object(), object()]
    with patch("boto3.client", side_effect=clients) as boto_client:
        gateway = AwsGateway(settings)
    assert boto_client.call_count == 3

    no_network_bundle, _, _, _ = _bundle(tmp_path)
    bundle = _rebuild_bundle(
        no_network_bundle,
        artifact_gateway=gateway,
        settings=settings,
    )
    assert bundle.artifact_gateway is gateway
    assert get_artifact_gateway(bundle) is gateway
    assert gateway.settings is settings
    assert gateway.presigned_url_ttl_seconds == settings.presigned_url_ttl_seconds
    assert gateway.max_package_size_bytes == settings.max_package_size_bytes


def test_gateway_subclasses_impostor_and_unsupported_reject_before_access(
    tmp_path: Path,
) -> None:
    from workflow_api.aws_clients import AwsGateway

    explode = AssertionError("rejected gateway was accessed")

    class NoNetworkSubclass(NoNetworkArtifactGateway):
        @property
        def presigned_url_ttl_seconds(self) -> int:
            raise explode

        @property
        def max_package_size_bytes(self) -> int:
            raise explode

    class AwsSubclass(AwsGateway):
        @property
        def settings(self) -> Settings:
            raise explode

        @property
        def presigned_url_ttl_seconds(self) -> int:
            raise explode

        @property
        def max_package_size_bytes(self) -> int:
            raise explode

    class StructuralImpostor:
        def __getattribute__(self, name: str) -> object:
            raise explode

    settings = _settings()
    no_network_subclass = NoNetworkSubclass(
        ticket_origin="https://uploads.synthetic.example",
        presigned_url_ttl_seconds=settings.presigned_url_ttl_seconds,
        max_package_size_bytes=settings.max_package_size_bytes,
    )
    with patch("boto3.client", side_effect=[object(), object(), object()]) as boto_client:
        aws_subclass = AwsSubclass(settings)
    assert boto_client.call_count == 3
    bundle, _, _, _ = _bundle(tmp_path)

    for rejected in (
        no_network_subclass,
        aws_subclass,
        StructuralImpostor(),
        object(),
    ):
        with pytest.raises(TypeError, match="exact artifact gateway"):
            _rebuild_bundle(bundle, artifact_gateway=rejected)


def test_exact_aws_gateway_rejects_distinct_value_equal_settings(
    tmp_path: Path,
) -> None:
    from workflow_api.aws_clients import AwsGateway

    gateway_settings = _settings()
    bundle_settings = _settings()
    assert gateway_settings is not bundle_settings
    assert gateway_settings.model_dump() == bundle_settings.model_dump()
    with patch("boto3.client", side_effect=[object(), object(), object()]) as boto_client:
        gateway = AwsGateway(gateway_settings)
    assert boto_client.call_count == 3
    bundle, _, _, _ = _bundle(tmp_path)

    with pytest.raises(ValueError, match="settings identity mismatch"):
        _rebuild_bundle(
            bundle,
            artifact_gateway=gateway,
            settings=bundle_settings,
        )


@pytest.mark.parametrize(
    ("gateway_changes", "message"),
    [
        ({"presigned_url_ttl_seconds": 899}, "ticket TTL mismatch"),
        ({"max_package_size_bytes": 512 * 1024 * 1024 - 1}, "package limit mismatch"),
    ],
)
def test_exact_no_network_gateway_rejects_limit_mismatch(
    tmp_path: Path,
    gateway_changes: dict[str, int],
    message: str,
) -> None:
    bundle, _, _, _ = _bundle(tmp_path)
    gateway_values = {
        "ticket_origin": "https://uploads.synthetic.example",
        "presigned_url_ttl_seconds": bundle.settings.presigned_url_ttl_seconds,
        "max_package_size_bytes": bundle.settings.max_package_size_bytes,
    }
    gateway_values.update(gateway_changes)
    gateway = NoNetworkArtifactGateway(**gateway_values)

    with pytest.raises(ValueError, match=message):
        _rebuild_bundle(bundle, artifact_gateway=gateway)


def test_bundle_rejects_mismatch_subclass_and_implicit_settings(tmp_path: Path) -> None:
    bundle, _, _, _ = _bundle(tmp_path)
    other_store = SQLiteLegacySessionStore(tmp_path / "other.sqlite3")
    with pytest.raises(ValueError, match="legacy store identity mismatch"):
        SealedSyntheticRuntimeBundle(
            composition=bundle.composition,
            legacy_store=other_store,
            browser_store=bundle.browser_store,
            browser_factory=bundle.browser_factory,
            control_service=bundle.control_service,
            safety_control_service=bundle.safety_control_service,
            settings=bundle.settings,
            artifact_gateway=bundle.artifact_gateway,
        )
    with pytest.raises(TypeError, match="cannot be subclassed"):
        type("ForbiddenBundle", (SealedSyntheticRuntimeBundle,), {})
    implicit = Settings(_env_file=None, environment="synthetic")
    with pytest.raises(ValueError, match="every synthetic setting"):
        SealedSyntheticRuntimeBundle(
            composition=bundle.composition,
            legacy_store=bundle.legacy_store,
            browser_store=bundle.browser_store,
            browser_factory=bundle.browser_factory,
            control_service=bundle.control_service,
            safety_control_service=bundle.safety_control_service,
            settings=implicit,
            artifact_gateway=bundle.artifact_gateway,
        )


def test_no_network_artifact_receipt_end_to_end(tmp_path: Path) -> None:
    bundle, _, _, _ = _bundle(tmp_path)
    client = TestClient(create_app(bundle))
    session_id = uuid4()
    digest = "d" * 64
    created = client.post("/v1/sessions", json=_registration(session_id, digest, 2048))
    assert created.status_code == 201
    ticket = client.post(f"/v1/sessions/{session_id}/upload-url")
    assert ticket.status_code == 200
    body = ticket.json()
    object_key = f"sessions/{session_id}/packages/{digest}.zip"
    assert body == {
        "method": "PUT",
        "upload_url": f"https://uploads.synthetic.example/{object_key}",
        "object_key": object_key,
        "expires_in_seconds": 900,
        "required_headers": {
            "Content-Length": "2048",
            "X-Workflow-Content-SHA256": digest,
        },
    }
    with pytest.raises(ValueError, match="artifact receipt rejected"):
        bundle.artifact_gateway.record_receipt(
            authority=AUTHORITY,
            object_key=object_key,
            package_sha256="e" * 64,
            package_size_bytes=2048,
        )
    missing = client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
    )
    assert missing.status_code == 409
    assert bundle.artifact_gateway.queue_evidence == ()
    reviewer_headers = {"Cookie": f"workflow_session={SESSION_MATERIAL}"}
    unchanged = client.get(
        f"/v1/sessions/{session_id}", headers=reviewer_headers
    )
    assert unchanged.status_code == 200
    assert unchanged.json()["processing_status"] == "registered"

    bundle.artifact_gateway.record_receipt(
        authority=AUTHORITY,
        object_key=object_key,
        package_sha256=digest,
        package_size_bytes=2048,
    )
    uploaded = client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
    )
    assert uploaded.status_code == 202
    assert bundle.artifact_gateway.queue_evidence == (
        ArtifactQueueEvidence(AUTHORITY, session_id, object_key, digest, 2_048),
    )
    fetched = client.get(f"/v1/sessions/{session_id}", headers=reviewer_headers)
    assert fetched.status_code == 200
    assert fetched.json()["processing_status"] == "uploaded"


@pytest.mark.parametrize(
    ("second_scope", "second_owner"),
    (
        (OTHER_SCOPE, "capture-other-synthetic"),
        (SCOPE, "capture-other-synthetic"),
    ),
    ids=("different-scope", "same-scope-different-owner"),
)
def test_shared_oracle_isolates_identical_artifacts_by_exact_authority(
    tmp_path: Path,
    second_scope: TenantWorkspaceScope,
    second_owner: str,
) -> None:
    settings = _settings()
    gateway = NoNetworkArtifactGateway(
        ticket_origin="https://uploads.synthetic.example",
        presigned_url_ttl_seconds=settings.presigned_url_ttl_seconds,
        max_package_size_bytes=settings.max_package_size_bytes,
    )
    first_bundle, _, _, _ = _bundle(
        tmp_path / "first",
        artifact_gateway=gateway,
    )
    second_bundle, _, _, _ = _bundle(
        tmp_path / "second",
        scope=second_scope,
        capture_subject=second_owner,
        artifact_gateway=gateway,
    )
    first_client = TestClient(create_app(first_bundle))
    second_client = TestClient(create_app(second_bundle))
    session_id = uuid4()
    digest = "7" * 64
    object_key = f"sessions/{session_id}/packages/{digest}.zip"
    second_authority = ArtifactAuthority(second_scope, second_owner)

    for client in (first_client, second_client):
        assert client.post(
            "/v1/sessions", json=_registration(session_id, digest, 4_096)
        ).status_code == 201
        ticket = client.post(f"/v1/sessions/{session_id}/upload-url")
        assert ticket.status_code == 200
        assert ticket.json()["object_key"] == object_key

    gateway.record_receipt(
        authority=AUTHORITY,
        object_key=object_key,
        package_sha256=digest,
        package_size_bytes=4_096,
    )
    assert first_client.post(
        f"/v1/sessions/{session_id}/uploaded",
        json={"object_key": object_key},
    ).status_code == 202
    rejected = second_client.post(
        f"/v1/sessions/{session_id}/uploaded",
        json={
            "object_key": object_key,
            "authority": {
                "tenant_id": SCOPE.tenant_id,
                "workspace_id": SCOPE.workspace_id,
                "capture_owner_subject": AUTHORITY.capture_owner_subject,
            },
        },
        headers={"X-Artifact-Authority": "request-input-is-not-authoritative"},
    )
    assert rejected.status_code == 409
    assert rejected.json() == {"detail": "session conflict"}
    second_state = second_client.get(
        f"/v1/sessions/{session_id}",
        headers={"Cookie": f"workflow_session={SESSION_MATERIAL}"},
    )
    assert second_state.status_code == 200
    assert second_state.json()["processing_status"] == "registered"
    assert gateway.queue_evidence == (
        ArtifactQueueEvidence(AUTHORITY, session_id, object_key, digest, 4_096),
    )

    gateway.record_receipt(
        authority=second_authority,
        object_key=object_key,
        package_sha256=digest,
        package_size_bytes=4_096,
    )
    assert second_client.post(
        f"/v1/sessions/{session_id}/uploaded",
        json={"object_key": object_key},
    ).status_code == 202
    assert gateway.queue_evidence == (
        ArtifactQueueEvidence(AUTHORITY, session_id, object_key, digest, 4_096),
        ArtifactQueueEvidence(second_authority, session_id, object_key, digest, 4_096),
    )


def test_direct_oracle_operations_reject_wrong_authority_before_mutation() -> None:
    gateway = NoNetworkArtifactGateway(
        ticket_origin="https://uploads.synthetic.example",
        presigned_url_ttl_seconds=900,
        max_package_size_bytes=512 * 1024 * 1024,
    )
    session_id = uuid4()
    digest = "8" * 64
    size = 2_048
    object_key = f"sessions/{session_id}/packages/{digest}.zip"
    record = SessionRecord.from_create(
        SessionCreate.model_validate(_registration(session_id, digest, size)),
        14,
    )
    wrong_authorities = (
        ArtifactAuthority(OTHER_SCOPE, AUTHORITY.capture_owner_subject),
        ArtifactAuthority(SCOPE, "capture-other-synthetic"),
    )

    gateway.create_package_upload(AUTHORITY, session_id, digest, size)
    for wrong_authority in wrong_authorities:
        with pytest.raises(ValueError, match="artifact receipt rejected"):
            gateway.record_receipt(
                authority=wrong_authority,
                object_key=object_key,
                package_sha256=digest,
                package_size_bytes=size,
            )
    assert gateway._receipts == {}
    assert gateway.queue_evidence == ()

    gateway.record_receipt(
        authority=AUTHORITY,
        object_key=object_key,
        package_sha256=digest,
        package_size_bytes=size,
    )
    mismatched_records = (
        SessionRecord.from_create(
            SessionCreate.model_validate(_registration(uuid4(), digest, size)),
            14,
        ),
        SessionRecord.from_create(
            SessionCreate.model_validate(_registration(session_id, "a" * 64, size)),
            14,
        ),
        SessionRecord.from_create(
            SessionCreate.model_validate(_registration(session_id, digest, size + 1)),
            14,
        ),
    )
    for mismatched_record in mismatched_records:
        with pytest.raises(ValueError, match="artifact receipt rejected"):
            gateway.verify_package_upload(AUTHORITY, object_key, mismatched_record)
    assert gateway.queue_evidence == ()
    for wrong_authority in wrong_authorities:
        with pytest.raises(ValueError, match="artifact receipt rejected"):
            gateway.verify_package_upload(wrong_authority, object_key, record)
        with pytest.raises(ArtifactGatewayUnavailableError, match="queue unavailable"):
            gateway.enqueue_processing(wrong_authority, session_id, object_key)
        assert gateway.queue_evidence == ()

    gateway.verify_package_upload(AUTHORITY, object_key, record)
    gateway.enqueue_processing(AUTHORITY, session_id, object_key)
    gateway.enqueue_processing(AUTHORITY, session_id, object_key)
    assert gateway.queue_evidence == (
        ArtifactQueueEvidence(AUTHORITY, session_id, object_key, digest, size),
    )


def test_oracle_requires_exact_valid_authority_on_every_operation() -> None:
    gateway = NoNetworkArtifactGateway(
        ticket_origin="https://uploads.synthetic.example",
        presigned_url_ttl_seconds=900,
        max_package_size_bytes=512 * 1024 * 1024,
    )
    session_id = uuid4()
    digest = "9" * 64
    size = 1_024
    object_key = f"sessions/{session_id}/packages/{digest}.zip"
    record = SessionRecord.from_create(
        SessionCreate.model_validate(_registration(session_id, digest, size)),
        14,
    )

    with pytest.raises(TypeError):
        gateway.create_package_upload(session_id, digest, size)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        gateway.record_receipt(  # type: ignore[call-arg]
            object_key=object_key,
            package_sha256=digest,
            package_size_bytes=size,
        )
    with pytest.raises(TypeError):
        gateway.verify_package_upload(object_key, record)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        gateway.enqueue_processing(session_id, object_key)  # type: ignore[call-arg]
    assert gateway._registrations == {}
    assert gateway._receipts == {}
    assert gateway.queue_evidence == ()

    invalid = object.__new__(ArtifactAuthority)
    object.__setattr__(invalid, "scope", SCOPE)
    object.__setattr__(invalid, "capture_owner_subject", "INVALID")

    class ArtifactAuthoritySubclass(ArtifactAuthority):
        pass

    subclassed = object.__new__(ArtifactAuthoritySubclass)
    object.__setattr__(subclassed, "scope", SCOPE)
    object.__setattr__(subclassed, "capture_owner_subject", "capture-synthetic")
    for rejected in (invalid, subclassed):
        with pytest.raises((TypeError, ValueError)):
            gateway.create_package_upload(rejected, session_id, digest, size)
        with pytest.raises((TypeError, ValueError)):
            gateway.record_receipt(
                authority=rejected,
                object_key=object_key,
                package_sha256=digest,
                package_size_bytes=size,
            )
        with pytest.raises((TypeError, ValueError)):
            gateway.verify_package_upload(rejected, object_key, record)
        with pytest.raises((TypeError, ValueError)):
            gateway.enqueue_processing(rejected, session_id, object_key)
    assert gateway._registrations == {}
    assert gateway._receipts == {}
    assert gateway.queue_evidence == ()


def test_replayed_workload_proof_stops_before_second_handler_and_oracle(
    tmp_path: Path,
) -> None:
    bundle, calls, _, verifier = _bundle(tmp_path, fixed_proof="f" * 64)
    client = TestClient(create_app(bundle))
    first_id = uuid4()
    second_id = uuid4()
    assert client.post("/v1/sessions", json=_registration(first_id)).status_code == 201
    replay = client.post("/v1/sessions", json=_registration(second_id))
    assert replay.status_code == 401
    assert replay.json() == {"detail": "request authorization rejected"}
    assert verifier.counter == 2
    assert bundle.artifact_gateway.queue_evidence == ()
    assert calls == ["workload", "workload"]


def test_invalid_identity_and_browser_stop_before_store_and_oracle(tmp_path: Path) -> None:
    rejected_bundle, calls, _, _ = _bundle(tmp_path / "identity", reject_identity=True)
    with patch.object(
        rejected_bundle.legacy_store,
        "list",
        side_effect=AssertionError("store must not be reached"),
    ):
        rejected = TestClient(create_app(rejected_bundle)).get(
            "/v1/sessions",
            headers={"Cookie": f"workflow_session={SESSION_MATERIAL}"},
        )
    assert rejected.status_code == 401
    assert calls == ["identity"]
    assert rejected_bundle.artifact_gateway.queue_evidence == ()

    browser_bundle, calls, _, _ = _bundle(tmp_path / "browser")
    with patch.object(
        browser_bundle.legacy_store,
        "list",
        side_effect=AssertionError("store must not be reached"),
    ):
        rejected = TestClient(create_app(browser_bundle)).get("/v1/sessions")
    assert rejected.status_code == 401
    assert calls == ["identity"]
    assert browser_bundle.artifact_gateway.queue_evidence == ()


def test_validation_and_browser_rejection_are_bounded(tmp_path: Path) -> None:
    bundle, calls, _, _ = _bundle(tmp_path)
    client = TestClient(create_app(bundle))
    invalid = client.get(
        "/v1/control/safety/events?limit=not-an-integer",
        headers={"Cookie": f"workflow_session={SESSION_MATERIAL}"},
    )
    assert invalid.status_code == 422
    assert invalid.json() == {"detail": "request rejected"}
    assert len(invalid.content) <= 64

    calls.clear()
    rejected = client.post(
        "/v1/control/jobs",
        json={},
        headers={
            "Cookie": f"workflow_session={SESSION_MATERIAL}",
            "Origin": "https://wrong.example",
            "X-CSRF-Token": CSRF_MATERIAL,
        },
    )
    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "request security rejected"}
    assert len(rejected.content) <= 64
    assert calls == ["identity"]


def test_settings_reject_live_origins_endpoints_and_over_cap(tmp_path: Path) -> None:
    bundle, _, _, _ = _bundle(tmp_path)
    for settings in (
        _settings(cors_origins="https://review.example.org"),
        _settings(cors_origins="https://*.example"),
        _settings(aws_endpoint_url="https://aws.example"),
    ):
        with pytest.raises(ValueError):
            SealedSyntheticRuntimeBundle(
                composition=bundle.composition,
                legacy_store=bundle.legacy_store,
                browser_store=bundle.browser_store,
                browser_factory=bundle.browser_factory,
                control_service=bundle.control_service,
                safety_control_service=bundle.safety_control_service,
                settings=settings,
                artifact_gateway=bundle.artifact_gateway,
            )
