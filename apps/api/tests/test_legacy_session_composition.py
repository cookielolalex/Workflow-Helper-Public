from __future__ import annotations

import base64
import dataclasses
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from workflow_api.artifact_gateway import NoNetworkArtifactGateway
from workflow_api.browser_session_store import (
    SQLiteBrowserSessionStore,
    StoreBackedBrowserSessionProviderFactory,
    StoreBackedSessionSecurityContextProvider,
)
from workflow_api.config import Settings
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.control_service import ControlService
from workflow_api.control_store import SQLiteControlStore
from workflow_api.dependencies import get_provider_neutral_security_composition
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
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
)
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.main import app, create_app
from workflow_api.retention_store import RetentionLedger
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetySwitchLedger
from workflow_api.session_security import (
    SessionSecurityContext,
    SessionSecurityRejectedError,
    SessionTransport,
    csrf_token_digest,
)

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
OTHER_SCOPE = TenantWorkspaceScope("tenant-other", "workspace-other")
ORIGIN = "https://review.example.com"
BUNDLE_ORIGIN = "https://review.synthetic.example"
CSRF_TOKEN = "A" * 43
SESSION_MATERIAL = base64.urlsafe_b64encode(b"s" * 32).decode().rstrip("=")


def _principal(role: ControlRole, *, subject: str | None = None, scope=SCOPE):
    return AuthenticatedPrincipal(
        subject or f"{role.value}-synthetic",
        frozenset({role}),
        scope,
    )


class Authenticator:
    def __init__(self, principal: AuthenticatedPrincipal, counters: dict[str, int]) -> None:
        self.principal = principal
        self.counters = counters

    def authenticate(self) -> VerifiedIdentityEvidence:
        self.counters["identity"] += 1
        return VerifiedIdentityEvidence(
            self.principal.subject,
            (f"group-{next(iter(self.principal.roles)).value}",),
            AuthenticationContext(
                AuthenticationAssurance.MULTI_FACTOR,
                (AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
            ),
            self.principal.scope,
        )


class BrowserProvider:
    def __init__(self, principal: AuthenticatedPrincipal, counters: dict[str, int]) -> None:
        self.principal = principal
        self.counters = counters

    def get_session_security_context(self) -> SessionSecurityContext:
        self.counters["browser"] += 1
        now = datetime.now(UTC)
        return SessionSecurityContext(
            principal=self.principal,
            session_identifier_digest="a" * 64,
            session_generation=1,
            active_generation=1,
            issued_at=now - timedelta(minutes=2),
            authenticated_at=now - timedelta(minutes=2),
            last_seen_at=now - timedelta(seconds=1),
            idle_expires_at=now + timedelta(minutes=10),
            absolute_expires_at=now + timedelta(hours=1),
            revoked=False,
            transport=SessionTransport.BROWSER_COOKIE,
            allowed_browser_origin=ORIGIN,
            csrf_token_digest=csrf_token_digest(CSRF_TOKEN),
        )


class WorkloadProvider:
    def __init__(
        self,
        counters: dict[str, int],
        *,
        proof_digest: str | None = None,
        mutate=None,
    ) -> None:
        self.counters = counters
        self.proof_digest = proof_digest
        self.mutate = mutate

    def get_workload_context(self, *, method, path, body_sha256, headers):
        self.counters["workload"] += 1
        worker = path.startswith("/v1/internal/")
        now = datetime.now(UTC)
        context = LegacyWorkloadContext(
            principal=_principal(
                ControlRole.DETERMINISTIC_WORKER
                if worker
                else ControlRole.CAPTURE_UPLOADER
            ),
            audience=(
                LegacySessionAudience.PROCESSING_COMPLETION
                if worker
                else LegacySessionAudience.CAPTURE_UPLOAD
            ),
            transport=(
                LegacySessionTransport.WORKER_WORKLOAD
                if worker
                else LegacySessionTransport.CAPTURE_WORKLOAD
            ),
            method=method,
            path=path,
            body_sha256=body_sha256,
            proof_identifier_digest=(
                self.proof_digest
                or hashlib.sha256(f"proof-{uuid4()}".encode()).hexdigest()
            ),
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=1),
            generation=1,
            active_generation=1,
            revoked=False,
            replay_decision=ReplayDecision.ACCEPT,
        )
        return self.mutate(context) if self.mutate else context


def _register_principals(store: SQLiteLegacySessionStore) -> None:
    store.register_workload_principal(
        principal_subject="capture_uploader-synthetic",
        scope=SCOPE,
        audience=LegacySessionAudience.CAPTURE_UPLOAD,
        role=ControlRole.CAPTURE_UPLOADER,
        transport=LegacySessionTransport.CAPTURE_WORKLOAD,
    )
    store.register_workload_principal(
        principal_subject="deterministic_worker-synthetic",
        scope=SCOPE,
        audience=LegacySessionAudience.PROCESSING_COMPLETION,
        role=ControlRole.DETERMINISTIC_WORKER,
        transport=LegacySessionTransport.WORKER_WORKLOAD,
    )


def _composition(
    store: SQLiteLegacySessionStore,
    *,
    reviewer: AuthenticatedPrincipal | None = None,
    counters: dict[str, int] | None = None,
    workload_provider=None,
    authenticator=None,
    browser_provider=None,
    browser_factory=None,
) -> ProviderNeutralSecurityComposition:
    reviewer = reviewer or _principal(ControlRole.REVIEWER)
    counters = counters or {"identity": 0, "browser": 0, "workload": 0}
    role = next(iter(reviewer.roles))
    authenticator = authenticator or Authenticator(reviewer, counters)
    browser = browser_provider or BrowserProvider(reviewer, counters)
    verifier = workload_provider or WorkloadProvider(counters)
    return ProviderNeutralSecurityComposition(
        group_role_mapping=GroupRoleMapping(
            (GroupRoleBinding(f"group-{role.value}", (role,)),)
        ),
        subject_scope_policy=SubjectScopePolicy(
            (SubjectScopeBinding(reviewer.subject, reviewer.scope),)
        ),
        authenticator_factory=lambda request: authenticator,
        browser_session_provider_factory=(
            browser_factory if browser_factory is not None else lambda request: browser
        ),
        workload_credential_verifier_factory=lambda request: verifier,
        store=store,
    )


def _sealed_bundle(
    tmp_path: Path,
    store: SQLiteLegacySessionStore,
    *,
    name: str,
    counters: dict[str, int],
    workload_provider=None,
) -> SealedSyntheticRuntimeBundle:
    """Build the exact whole graph used by legacy successful-path tests."""

    browser_store = SQLiteBrowserSessionStore(tmp_path / f"{name}-browser.sqlite3")
    now = datetime.now(UTC)
    browser_store.register_session(
        session_identifier_digest=hashlib.sha256(b"s" * 32).hexdigest(),
        csrf_token_digest=csrf_token_digest(CSRF_TOKEN),
        principal=_principal(ControlRole.REVIEWER),
        allowed_browser_origin=BUNDLE_ORIGIN,
        issued_at=now - timedelta(minutes=2),
        authenticated_at=now - timedelta(minutes=2),
        last_seen_at=now - timedelta(seconds=1),
        idle_expires_at=now + timedelta(minutes=29),
        absolute_expires_at=now + timedelta(hours=7),
        now=now,
    )
    browser_factory = StoreBackedBrowserSessionProviderFactory(store=browser_store)
    composition = _composition(
        store,
        counters=counters,
        workload_provider=workload_provider,
        browser_factory=browser_factory,
    )
    settings = Settings(
        _env_file=None,
        environment="synthetic",
        log_level="INFO",
        cors_origins=BUNDLE_ORIGIN,
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
    return SealedSyntheticRuntimeBundle(
        composition=composition,
        legacy_store=store,
        browser_store=browser_store,
        browser_factory=browser_factory,
        control_service=ControlService(
            SQLiteControlStore(tmp_path / f"{name}-control.sqlite3"),
            RetentionLedger(tmp_path / f"{name}-retention.sqlite3"),
        ),
        safety_control_service=SafetyControlService(
            SafetySwitchLedger(tmp_path / f"{name}-safety.sqlite3")
        ),
        settings=settings,
        artifact_gateway=NoNetworkArtifactGateway(
            ticket_origin="https://uploads.synthetic.example",
            presigned_url_ttl_seconds=settings.presigned_url_ttl_seconds,
            max_package_size_bytes=settings.max_package_size_bytes,
        ),
    )


def _registration(session_id: str, digest: str = "b" * 64) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "machine_id": "machine-synthetic-1",
        "project_id": "synthetic",
        "started_at": "2026-08-16T04:00:00Z",
        "ended_at": "2026-08-16T04:01:00Z",
        "active_duration_seconds": 60,
        "approved_process": "acad",
        "package_sha256": digest,
        "package_size_bytes": 100,
    }


def _walk_routes(router):
    for route in router.routes:
        child = getattr(route, "original_router", None)
        if child is not None:
            yield from _walk_routes(child)
        else:
            yield route


def _inventory() -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for route in _walk_routes(app):
        path = getattr(route, "path", "")
        if not path.startswith(("/health", "/v1/")):
            continue
        for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
            result.append((method, path))
    return sorted(result)


def _concrete(path: str) -> str:
    value = path.replace("{session_id}", "00000000-0000-0000-0000-000000000001")
    value = value.replace("{job_id}", "job-synthetic")
    value = value.replace("{dataset_id}", "dataset-synthetic")
    value = value.replace("{target_id}", "target-synthetic")
    value = value.replace("{copy_id}", "copy-synthetic")
    value = value.replace("{event_id}", "event-synthetic")
    return value.replace("{domain}", "capture")


@pytest.fixture(autouse=True)
def clean_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_dynamic_inventory_is_exact_and_default_is_side_effect_free(tmp_path: Path) -> None:
    inventory = _inventory()
    assert len(inventory) == 29
    assert inventory.count(("GET", "/health")) == 1
    assert len([value for value in inventory if value[1].startswith("/v1/control/")]) == 21
    assert len([value for value in inventory if value[0] == "GET" and "/sessions" in value[1]]) == 3
    assert len([value for value in inventory if value[0] == "POST" and "/sessions" in value[1]]) == 4

    before = list(tmp_path.iterdir())
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    for method, path in inventory:
        if path == "/health":
            continue
        response = client.request(method, _concrete(path), json={} if method == "POST" else None)
        assert response.status_code == 503, (method, path, response.text)
        detail = response.json()["detail"]
        assert len(detail) <= 64
        assert not any(
            term in detail.casefold()
            for term in ("sqlite", "credential", "digest", "generation", "provider", "sql")
        )
    assert list(tmp_path.iterdir()) == before


def test_control_routes_use_composed_identity_and_browser_session_and_exact_csrf(
    tmp_path: Path,
) -> None:
    store = SQLiteLegacySessionStore(tmp_path / "control.sqlite3")
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}
    composition = _composition(store, counters=counters)
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: composition
    client = TestClient(app)

    controls = [(method, path) for method, path in _inventory() if path.startswith("/v1/control/")]
    unsafe = [(method, path) for method, path in controls if method != "GET"]
    assert len(controls) == 21
    assert len(unsafe) == 11
    for method, path in controls:
        headers = {}
        if method != "GET":
            response = client.request(method, _concrete(path), json={})
            assert response.status_code == 401
            headers = {"Origin": ORIGIN, "X-CSRF-Token": CSRF_TOKEN}
        response = client.request(
            method,
            _concrete(path),
            json={} if method != "GET" else None,
            headers=headers,
        )
        assert response.status_code != 401

    assert counters == {"identity": 32, "browser": 32, "workload": 0}


def test_control_routes_resolve_durable_browser_authority_and_keep_exact_csrf(
    tmp_path: Path,
) -> None:
    legacy_store = SQLiteLegacySessionStore(tmp_path / "legacy-control.sqlite3")
    _register_principals(legacy_store)
    reviewer = _principal(ControlRole.REVIEWER)
    now = datetime.now(UTC)
    browser_store = SQLiteBrowserSessionStore(
        tmp_path / "browser-control.sqlite3",
        clock=lambda: now,
    )
    browser_store.register_session(
        session_identifier_digest="e" * 64,
        csrf_token_digest=csrf_token_digest(CSRF_TOKEN),
        principal=reviewer,
        allowed_browser_origin=ORIGIN,
        issued_at=now - timedelta(minutes=2),
        authenticated_at=now - timedelta(minutes=2),
        last_seen_at=now - timedelta(seconds=1),
        idle_expires_at=now + timedelta(minutes=29),
        absolute_expires_at=now + timedelta(hours=7),
        now=now,
    )
    provider = StoreBackedSessionSecurityContextProvider(
        store=browser_store,
        session_identifier_digest="e" * 64,
    )
    composition = _composition(
        legacy_store,
        reviewer=reviewer,
        browser_provider=provider,
    )
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: composition
    client = TestClient(app)

    controls = [(method, path) for method, path in _inventory() if path.startswith("/v1/control/")]
    assert len(controls) == 21
    assert len([(method, path) for method, path in controls if method != "GET"]) == 11
    for method, path in controls:
        if method != "GET":
            assert client.request(method, _concrete(path), json={}).status_code == 401
        response = client.request(
            method,
            _concrete(path),
            json={} if method != "GET" else None,
            headers=(
                {"Origin": ORIGIN, "X-CSRF-Token": CSRF_TOKEN}
                if method != "GET"
                else {}
            ),
        )
        assert response.status_code != 401


@pytest.mark.parametrize("failure", ("locked", "corrupt", "unavailable"))
def test_durable_browser_invalid_is_401_and_store_failure_is_bounded_503(
    tmp_path: Path,
    failure: str,
) -> None:
    legacy_store = SQLiteLegacySessionStore(tmp_path / "legacy-fault.sqlite3")
    _register_principals(legacy_store)
    reviewer = _principal(ControlRole.REVIEWER)
    browser_store = SQLiteBrowserSessionStore(tmp_path / "browser-fault.sqlite3")

    invalid = StoreBackedSessionSecurityContextProvider(
        store=browser_store,
        session_identifier_digest="f" * 64,
    )
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: _composition(
        legacy_store,
        reviewer=reviewer,
        browser_provider=invalid,
    )
    response = TestClient(app).get(
        "/v1/control/reviews/target-synthetic?correlation_id=corr-browser-invalid"
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "request security rejected"}

    def broken_connect():
        detail = {
            "locked": "database is locked /private/path digest",
            "corrupt": "database disk image malformed /private/path digest",
            "unavailable": "private runtime unavailable /private/path digest",
        }[failure]
        if failure == "unavailable":
            raise RuntimeError(detail)
        raise sqlite3.OperationalError(detail)

    browser_store._connect = broken_connect  # type: ignore[method-assign]
    unavailable = StoreBackedSessionSecurityContextProvider(
        store=browser_store,
        session_identifier_digest="f" * 64,
    )
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: _composition(
        legacy_store,
        reviewer=reviewer,
        browser_provider=unavailable,
    )
    response = TestClient(app).get(
        "/v1/control/reviews/target-synthetic?correlation_id=corr-browser-fault"
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "session security unavailable"}
    assert not any(
        value in response.text.casefold()
        for value in ("sqlite", "database", "locked", "private", "path", "digest")
    )


def test_browser_and_workload_transports_never_invoke_each_others_providers(
    tmp_path: Path,
) -> None:
    store = SQLiteLegacySessionStore(tmp_path / "separation.sqlite3")
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}
    bundle = _sealed_bundle(
        tmp_path,
        store,
        name="separation",
        counters=counters,
    )
    client = TestClient(create_app(bundle))
    original_resolve = SQLiteBrowserSessionStore.resolve_session

    def counted_resolve(browser_store, **kwargs):
        counters["browser"] += 1
        return original_resolve(browser_store, **kwargs)

    with patch.object(SQLiteBrowserSessionStore, "resolve_session", counted_resolve):
        assert client.get(
            "/v1/sessions", cookies={"workflow_session": SESSION_MATERIAL}
        ).status_code == 200
    assert counters == {"identity": 1, "browser": 1, "workload": 0}
    assert client.post("/v1/sessions", json=_registration(str(uuid4()))).status_code == 201
    assert counters == {"identity": 1, "browser": 1, "workload": 1}


def test_provider_decision_fields_are_ignored_but_durable_authority_is_enforced(
    tmp_path: Path,
) -> None:
    store = SQLiteLegacySessionStore(tmp_path / "authority.sqlite3")
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}
    provider = WorkloadProvider(
        counters,
        mutate=lambda context: dataclasses.replace(
            context,
            active_generation=999,
            revoked=True,
            replay_decision=ReplayDecision.REJECT,
        ),
    )
    bundle = _sealed_bundle(
        tmp_path,
        store,
        name="authority",
        counters=counters,
        workload_provider=provider,
    )
    client = TestClient(create_app(bundle))

    response = client.post("/v1/sessions", json=_registration(str(uuid4())))
    assert response.status_code == 201

    state = store.get_workload_principal(
        principal_subject="capture_uploader-synthetic",
        scope=SCOPE,
        audience=LegacySessionAudience.CAPTURE_UPLOAD,
    )
    rotated = store.rotate_workload_generation(
        principal_subject=state.principal_subject,
        scope=SCOPE,
        audience=state.audience,
        expected_state_version=state.state_version,
        new_generation=2,
    )
    assert client.post("/v1/sessions", json=_registration(str(uuid4()))).status_code == 401
    store.revoke_workload_principal(
        principal_subject=rotated.principal_subject,
        scope=SCOPE,
        audience=rotated.audience,
        expected_state_version=rotated.state_version,
    )


def test_reopen_preserves_sessions_and_replay_claims_with_one_exact_store(tmp_path: Path) -> None:
    path = tmp_path / "restart.sqlite3"
    store = SQLiteLegacySessionStore(path)
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}
    proof = "c" * 64
    provider = WorkloadProvider(counters, proof_digest=proof)
    first = _sealed_bundle(
        tmp_path,
        store,
        name="restart-first",
        counters=counters,
        workload_provider=provider,
    )
    assert first.composition.store is store
    client = TestClient(create_app(first))
    session_id = str(uuid4())
    payload = _registration(session_id)
    assert client.post("/v1/sessions", json=payload).status_code == 201

    reopened = SQLiteLegacySessionStore(path)
    second = _sealed_bundle(
        tmp_path,
        reopened,
        name="restart-second",
        counters=counters,
        workload_provider=provider,
    )
    assert second.composition.store is reopened
    reopened_client = TestClient(create_app(second))
    assert reopened_client.post("/v1/sessions", json=payload).status_code == 401
    listing = reopened_client.get(
        "/v1/sessions", cookies={"workflow_session": SESSION_MATERIAL}
    )
    assert listing.status_code == 200
    assert listing.json()["count"] == 1


def test_concurrent_identical_proof_has_exactly_one_route_winner(tmp_path: Path) -> None:
    store = SQLiteLegacySessionStore(tmp_path / "concurrent.sqlite3")
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}
    provider = WorkloadProvider(counters, proof_digest="d" * 64)
    bundle = _sealed_bundle(
        tmp_path,
        store,
        name="concurrent",
        counters=counters,
        workload_provider=provider,
    )
    application = create_app(bundle)
    payload = _registration(str(uuid4()))

    def attempt(_: int) -> int:
        return TestClient(application).post("/v1/sessions", json=payload).status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        statuses = list(executor.map(attempt, range(8)))
    assert statuses.count(201) == 1
    assert statuses.count(401) == 7
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("select count(*) from legacy_sessions").fetchone() == (1,)
        assert connection.execute(
            "select count(*) from legacy_workload_proof_claims"
        ).fetchone() == (1,)


@pytest.mark.parametrize("layer", ("identity", "browser", "workload"))
@pytest.mark.parametrize("failure", ("invalid", "operational"))
def test_invalid_evidence_is_401_and_operational_failure_is_503(
    tmp_path: Path,
    layer: str,
    failure: str,
) -> None:
    store = SQLiteLegacySessionStore(tmp_path / f"{layer}-{failure}.sqlite3")
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}
    invalid_errors = {
        "identity": IdentityRejectedError("invalid-private-evidence"),
        "browser": SessionSecurityRejectedError("invalid-private-evidence"),
        "workload": LegacySessionSecurityRejectedError("invalid-private-evidence"),
    }
    exception = (
        invalid_errors[layer]
        if failure == "invalid"
        else RuntimeError("operational-private-detail")
    )

    class FailingAuthenticator:
        def authenticate(self):
            raise exception

    class FailingBrowserProvider:
        def get_session_security_context(self):
            raise exception

    class FailingWorkloadProvider:
        def get_workload_context(self, **kwargs):
            raise exception

    composition = _composition(
        store,
        counters=counters,
        authenticator=FailingAuthenticator() if layer == "identity" else None,
        browser_provider=FailingBrowserProvider() if layer == "browser" else None,
        workload_provider=FailingWorkloadProvider() if layer == "workload" else None,
    )
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: composition
    client = TestClient(app)
    response = (
        client.post("/v1/sessions", json=_registration(str(uuid4())))
        if layer == "workload"
        else client.get(
            "/v1/control/reviews/target-synthetic?correlation_id=corr-security"
        )
    )
    assert response.status_code == (401 if failure == "invalid" else 503)
    assert response.json()["detail"] in {
        "request authorization rejected",
        "legacy session service unavailable",
        "identity rejected",
        "control authentication unavailable",
        "request security rejected",
        "session security unavailable",
    }
    assert "private" not in response.text


@pytest.mark.parametrize(
    "failure",
    ("provider", "invalid", "locked", "corrupt", "runtime-claim", "runtime-handler"),
)
def test_failures_are_bounded_and_store_operational_errors_are_503(
    tmp_path: Path,
    failure: str,
) -> None:
    store = SQLiteLegacySessionStore(tmp_path / f"{failure}.sqlite3")
    _register_principals(store)
    counters = {"identity": 0, "browser": 0, "workload": 0}

    if failure == "provider":
        class Provider:
            def get_workload_context(self, **kwargs):
                raise RuntimeError("provider-private-detail")

        provider = Provider()
        expected = 503
    elif failure == "invalid":
        provider = WorkloadProvider(
            counters,
            mutate=lambda context: dataclasses.replace(context, body_sha256="0" * 64),
        )
        expected = 401
    elif failure in {"locked", "corrupt", "runtime-claim"}:
        provider = WorkloadProvider(counters)
        message = "database is locked" if failure == "locked" else "database disk image malformed"

        def broken_connect():
            if failure == "runtime-claim":
                raise RuntimeError("store-private-runtime")
            raise sqlite3.OperationalError(message)

        store._connect = broken_connect  # type: ignore[method-assign]
        expected = 503
    else:
        provider = WorkloadProvider(counters)

        async def broken_list(*args, **kwargs):
            raise RuntimeError("store-private-runtime")

        store.list = broken_list  # type: ignore[method-assign]
        expected = 503

    composition = _composition(store, counters=counters, workload_provider=provider)
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: composition
    response = (
        TestClient(app).get("/v1/sessions")
        if failure == "runtime-handler"
        else TestClient(app).post("/v1/sessions", json=_registration(str(uuid4())))
    )
    assert response.status_code == expected
    detail = response.json()["detail"]
    assert len(detail) <= 64
    assert not any(
        term in detail.casefold()
        for term in ("provider", "sqlite", "database", "locked", "malformed", "digest")
    )
