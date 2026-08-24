from __future__ import annotations

import base64
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from workflow_api.artifact_gateway import NoNetworkArtifactGateway
from workflow_api.browser_session_store import (
    SQLiteBrowserSessionStore,
    StoreBackedBrowserSessionProviderFactory,
)
from workflow_api.config import Settings
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.control_service import ControlService
from workflow_api.control_store import SQLiteControlStore
from workflow_api.dependencies import (
    get_authenticated_principal,
    get_control_service,
    get_session_security_context_provider,
)
from workflow_api.identity import (
    GroupRoleBinding,
    GroupRoleMapping,
    SubjectScopeBinding,
    SubjectScopePolicy,
)
from workflow_api.legacy_session_composition import ProviderNeutralSecurityComposition
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.main import (
    app,
    control_session_dependencies,
    create_app,
    require_control_session_security,
)
from workflow_api.retention_store import RetentionLedger
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetySwitchLedger
from workflow_api.session_security import (
    SessionSecurityContext,
    SessionSecurityRejectedError,
    SessionTransport,
    csrf_token_digest,
    validate_session_security,
)

ORIGIN = "https://control.synthetic.test"
BUNDLE_ORIGIN = "https://control.synthetic.example"
TOKEN = base64.urlsafe_b64encode(b"c" * 32).decode("ascii").rstrip("=")
ROTATED_TOKEN = base64.urlsafe_b64encode(b"d" * 32).decode("ascii").rstrip("=")
SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")


class SyntheticProvider:
    def __init__(self, context: SessionSecurityContext):
        self.context = context

    def get_session_security_context(self) -> SessionSecurityContext:
        return self.context


def _principal(
    *,
    subject: str = "reviewer-synthetic",
    roles: frozenset[ControlRole] | None = None,
    scope: TenantWorkspaceScope = SCOPE,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject,
        frozenset({ControlRole.REVIEWER}) if roles is None else roles,
        scope,
    )


def _context(
    principal: AuthenticatedPrincipal | None = None,
    *,
    token: str = TOKEN,
    generation: int = 1,
    now: datetime | None = None,
) -> SessionSecurityContext:
    current = datetime.now(UTC) if now is None else now
    return SessionSecurityContext(
        principal=_principal() if principal is None else principal,
        session_identifier_digest="a" * 64,
        session_generation=generation,
        active_generation=generation,
        issued_at=current - timedelta(minutes=10),
        authenticated_at=current - timedelta(minutes=9),
        last_seen_at=current - timedelta(minutes=1),
        idle_expires_at=current + timedelta(minutes=29),
        absolute_expires_at=current + timedelta(hours=7),
        revoked=False,
        transport=SessionTransport.BROWSER_COOKIE,
        allowed_browser_origin=ORIGIN,
        csrf_token_digest=csrf_token_digest(token),
    )


def _headers(
    *,
    origin: str | None = ORIGIN,
    token: str | None = TOKEN,
) -> Headers:
    values: list[tuple[str, str]] = []
    if origin is not None:
        values.append(("Origin", origin))
    if token is not None:
        values.append(("X-CSRF-Token", token))
    return Headers(
        raw=[(key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in values]
    )


def _cors_bundle(tmp_path: Path) -> SealedSyntheticRuntimeBundle:
    legacy_store = SQLiteLegacySessionStore(tmp_path / "cors-legacy.sqlite3")
    browser_store = SQLiteBrowserSessionStore(tmp_path / "cors-browser.sqlite3")
    browser_factory = StoreBackedBrowserSessionProviderFactory(store=browser_store)
    principal = _principal()
    composition = ProviderNeutralSecurityComposition(
        group_role_mapping=GroupRoleMapping(
            (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
        ),
        subject_scope_policy=SubjectScopePolicy(
            (SubjectScopeBinding(principal.subject, principal.scope),)
        ),
        authenticator_factory=lambda request: object(),
        browser_session_provider_factory=browser_factory,
        workload_credential_verifier_factory=lambda request: object(),
        store=legacy_store,
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
        legacy_store=legacy_store,
        browser_store=browser_store,
        browser_factory=browser_factory,
        control_service=ControlService(
            SQLiteControlStore(tmp_path / "cors-control.sqlite3"),
            RetentionLedger(tmp_path / "cors-retention.sqlite3"),
        ),
        safety_control_service=SafetyControlService(
            SafetySwitchLedger(tmp_path / "cors-safety.sqlite3")
        ),
        settings=settings,
        artifact_gateway=NoNetworkArtifactGateway(
            ticket_origin="https://uploads.synthetic.example",
            presigned_url_ttl_seconds=settings.presigned_url_ttl_seconds,
            max_package_size_bytes=settings.max_package_size_bytes,
        ),
    )


@pytest.fixture(autouse=True)
def _clear_dependency_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _control_operations() -> list[tuple[str, str]]:
    operations: list[tuple[str, str]] = []
    for path, path_item in app.openapi()["paths"].items():
        if not path.startswith("/v1/control"):
            continue
        for method in ("get", "post", "put", "patch", "delete"):
            if method in path_item:
                operations.append((method.upper(), path))
    return operations


def test_shared_guard_inventory_covers_every_current_control_route() -> None:
    operations = _control_operations()

    assert sum(method == "GET" for method, _ in operations) == 10
    assert sum(method == "POST" for method, _ in operations) == 11
    assert not any(method in {"PUT", "PATCH", "DELETE"} for method, _ in operations)
    assert len(control_session_dependencies) == 1
    assert control_session_dependencies[0].dependency is require_control_session_security


def test_every_control_route_still_fails_closed_at_authentication_by_default() -> None:
    client = TestClient(app)
    for method, route_path in _control_operations():
        path = re.sub(r"\{[^}]+\}", "synthetic", route_path)
        response = client.request(method, path, json={} if method == "POST" else None)
        assert response.status_code == 503, (method, path, response.text)
        assert response.json() == {"detail": "control authentication unavailable"}

def test_missing_session_provider_is_a_bounded_503_after_authentication() -> None:
    app.dependency_overrides[get_authenticated_principal] = _principal
    response = TestClient(app).get(
        "/v1/control/reviews/synthetic?correlation_id=corr-session"
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "session security unavailable"}


def test_safe_and_unsafe_policy_are_distinct_and_future_unsafe_methods_are_covered() -> None:
    principal = _principal()
    context = _context(principal)

    validate_session_security(
        context=context,
        route_principal=principal,
        method="GET",
        headers=Headers(),
    )
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        validate_session_security(
            context=context,
            route_principal=principal,
            method=method,
            headers=_headers(),
        )
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(SessionSecurityRejectedError, match="request security rejected"):
            validate_session_security(
                context=context,
                route_principal=principal,
                method=method,
                headers=Headers(),
            )


def test_token_matrix_rejects_missing_blank_malformed_oversized_wrong_and_stale() -> None:
    principal = _principal()
    context = _context(principal)
    invalid_tokens = (
        None,
        "",
        " ",
        "not-canonical",
        "A" * 44,
        ROTATED_TOKEN,
        TOKEN.swapcase(),
    )
    for token in invalid_tokens:
        with pytest.raises(SessionSecurityRejectedError, match="request security rejected"):
            validate_session_security(
                context=context,
                route_principal=principal,
                method="POST",
                headers=_headers(token=token),
            )


def test_origin_matrix_is_exact_canonical_https_only() -> None:
    principal = _principal()
    context = _context(principal)
    invalid_origins = (
        None,
        "",
        "null",
        "http://control.synthetic.test",
        "HTTPS://control.synthetic.test",
        "https://CONTROL.synthetic.test",
        "https://control.synthetic.test:443",
        "https://control.synthetic.test:444",
        "https://control.synthetic.test.attacker.example",
        "https://sub.control.synthetic.test",
        "https://*.synthetic.test",
        "https://synthetic.test/control.synthetic.test",
        "https://user@control.synthetic.test",
        "https://control.synthetic.test/",
        " https://control.synthetic.test",
    )
    for origin in invalid_origins:
        with pytest.raises(SessionSecurityRejectedError, match="request security rejected"):
            validate_session_security(
                context=context,
                route_principal=principal,
                method="POST",
                headers=_headers(origin=origin),
            )


def _forged_context(field: str, value: object) -> SessionSecurityContext:
    context = _context()
    object.__setattr__(context, field, value)
    return context


def test_session_matrix_revalidates_provider_output_and_exact_principal() -> None:
    principal = _principal()
    now = datetime.now(UTC)
    expired = _context(principal, now=now - timedelta(hours=9))
    future = _context(principal, now=now + timedelta(minutes=2))
    other_scope = TenantWorkspaceScope("tenant-synthetic", "workspace-other")
    mismatches = (
        _principal(subject="other-reviewer"),
        _principal(roles=frozenset({ControlRole.AUDIT_READER})),
        _principal(scope=other_scope),
    )
    invalid_contexts: list[object] = [
        object(),
        _forged_context("revoked", True),
        _forged_context("active_generation", 2),
        _forged_context("csrf_token_digest", "not-a-digest"),
        _forged_context("last_seen_at", now + timedelta(minutes=2)),
        _forged_context("issued_at", now + timedelta(minutes=2)),
        expired,
        future,
    ]

    for context in invalid_contexts:
        with pytest.raises(SessionSecurityRejectedError, match="request security rejected"):
            validate_session_security(
                context=context,  # type: ignore[arg-type]
                route_principal=principal,
                method="GET",
                headers=Headers(),
                now=now,
            )
    for mismatch in mismatches:
        with pytest.raises(SessionSecurityRejectedError, match="request security rejected"):
            validate_session_security(
                context=_context(mismatch, now=now),
                route_principal=principal,
                method="GET",
                headers=Headers(),
                now=now,
            )


def test_rotation_and_revocation_invalidate_old_generation_and_csrf_material() -> None:
    principal = _principal()
    now = datetime.now(UTC)
    rotated = _context(principal, token=ROTATED_TOKEN, generation=2, now=now)

    validate_session_security(
        context=rotated,
        route_principal=principal,
        method="POST",
        headers=_headers(token=ROTATED_TOKEN),
        now=now,
    )
    with pytest.raises(SessionSecurityRejectedError):
        validate_session_security(
            context=rotated,
            route_principal=principal,
            method="POST",
            headers=_headers(token=TOKEN),
            now=now,
        )

    stale = replace(rotated)
    object.__setattr__(stale, "session_generation", 1)
    with pytest.raises(SessionSecurityRejectedError):
        validate_session_security(
            context=stale,
            route_principal=principal,
            method="GET",
            headers=Headers(),
            now=now,
        )

    revoked = replace(rotated)
    object.__setattr__(revoked, "revoked", True)
    with pytest.raises(SessionSecurityRejectedError):
        validate_session_security(
            context=revoked,
            route_principal=principal,
            method="GET",
            headers=Headers(),
            now=now,
        )


def test_all_unsafe_routes_reject_non_header_tokens_before_service_access() -> None:
    principal = _principal()
    provider = SyntheticProvider(_context(principal))
    service_calls = 0

    def forbidden_service():
        nonlocal service_calls
        service_calls += 1
        raise AssertionError("service dependency must not run")

    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider
    app.dependency_overrides[get_control_service] = forbidden_service
    client = TestClient(app)
    post_routes = [
        path for method, path in _control_operations() if method == "POST"
    ]

    for route_path in post_routes:
        path = re.sub(r"\{[^}]+\}", "synthetic", route_path)
        response = client.post(
            f"{path}?csrf_token={TOKEN}",
            json={"csrf_token": TOKEN},
            cookies={"csrf_token": TOKEN},
            headers={"Origin": ORIGIN},
        )
        assert response.status_code == 401, (path, response.text)
        assert response.json() == {"detail": "request security rejected"}
    assert service_calls == 0


def test_generic_rejection_body_never_exposes_session_or_csrf_evidence() -> None:
    principal = _principal()
    context = _context(principal)
    provider = SyntheticProvider(context)
    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider

    response = TestClient(app).post(
        "/v1/control/jobs",
        json={},
        headers={"Origin": ORIGIN, "X-CSRF-Token": ROTATED_TOKEN},
    )

    assert response.status_code == 401
    body = response.text
    assert response.json() == {"detail": "request security rejected"}
    for secret_value in (
        TOKEN,
        ROTATED_TOKEN,
        context.csrf_token_digest,
        context.session_identifier_digest,
        principal.subject,
        "revoked",
        "expired",
        "generation",
    ):
        assert secret_value not in body


def test_exact_valid_request_passes_guard_and_reaches_default_service_503() -> None:
    principal = _principal()
    provider = SyntheticProvider(_context(principal))
    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider

    response = TestClient(app).post(
        "/v1/control/jobs",
        json={
            "job_id": "synthetic",
            "payload_digest": "a" * 64,
            "correlation_id": "corr-synthetic",
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": TOKEN},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "control service unavailable"}


def test_cors_is_explicit_defense_in_depth_and_route_guard_is_independent(
    tmp_path: Path,
) -> None:
    default_preflight = TestClient(create_app()).options(
        "/v1/control/jobs",
        headers={
            "Origin": BUNDLE_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-CSRF-Token",
        },
    )
    assert default_preflight.status_code == 400
    assert "access-control-allow-origin" not in default_preflight.headers

    application = create_app(_cors_bundle(tmp_path))
    client = TestClient(application)
    preflight = client.options(
        "/v1/control/jobs",
        headers={
            "Origin": BUNDLE_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-CSRF-Token",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == BUNDLE_ORIGIN
    assert "x-csrf-token" in preflight.headers["access-control-allow-headers"].lower()
    assert preflight.headers["access-control-allow-credentials"] == "true"

    principal = _principal()
    provider = SyntheticProvider(_context(principal))
    application.dependency_overrides[get_authenticated_principal] = lambda: principal
    application.dependency_overrides[get_session_security_context_provider] = lambda: provider
    rejected = client.post(
        "/v1/control/jobs",
        json={},
        headers={"Origin": BUNDLE_ORIGIN, "X-CSRF-Token": TOKEN},
    )
    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "request security rejected"}
