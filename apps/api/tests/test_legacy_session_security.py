import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from starlette.datastructures import Headers

from workflow_api.control_auth import AuthenticatedPrincipal, ControlAction, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.legacy_session_security import (
    LegacySessionAudience,
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
    authorize_browser_request,
    authorize_workload_request,
    raw_body_sha256,
)
from workflow_api.session_security import (
    SessionSecurityContext,
    SessionTransport,
    csrf_token_digest,
)

NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
BODY = b'{"synthetic":true}'
PATH = "/v1/sessions"
CSRF_TOKEN = "A" * 43


def _principal(role: ControlRole, *, subject: str = "capture-synthetic-1") -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject,
        frozenset({role}),
        TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic"),
    )


def _workload_context(
    *,
    role: ControlRole = ControlRole.CAPTURE_UPLOADER,
    audience: LegacySessionAudience = LegacySessionAudience.CAPTURE_UPLOAD,
    transport: LegacySessionTransport = LegacySessionTransport.CAPTURE_WORKLOAD,
) -> LegacyWorkloadContext:
    return LegacyWorkloadContext(
        principal=_principal(role),
        audience=audience,
        transport=transport,
        method="POST",
        path=PATH,
        body_sha256=raw_body_sha256(BODY),
        proof_identifier_digest="c" * 64,
        issued_at=NOW - timedelta(seconds=5),
        expires_at=NOW + timedelta(seconds=55),
        generation=7,
        active_generation=7,
        revoked=False,
        replay_decision=ReplayDecision.ACCEPT,
    )


def _authorize(context: LegacyWorkloadContext, **changes) -> None:
    authorize_workload_request(
        context=context,
        method=changes.get("method", "POST"),
        path=changes.get("path", PATH),
        body=changes.get("body", BODY),
        action=changes.get("action", ControlAction.SESSION_REGISTER),
        audience=changes.get("audience", LegacySessionAudience.CAPTURE_UPLOAD),
        transport=changes.get("transport", LegacySessionTransport.CAPTURE_WORKLOAD),
        now=changes.get("now", NOW),
    )


def test_valid_capture_context_is_exact_scoped_and_contains_no_raw_credentials() -> None:
    context = _workload_context()
    authorization = authorize_workload_request(
        context=context,
        method="POST",
        path=PATH,
        body=BODY,
        action=ControlAction.SESSION_REGISTER,
        audience=LegacySessionAudience.CAPTURE_UPLOAD,
        transport=LegacySessionTransport.CAPTURE_WORKLOAD,
        now=NOW,
    )

    assert authorization.scope == TenantWorkspaceScope(
        "tenant-synthetic", "workspace-synthetic"
    )
    names = {field.name for field in dataclasses.fields(context)}
    assert names.isdisjoint({"token", "credential", "authorization", "secret"})


@pytest.mark.parametrize(
    ("context_change", "request_change"),
    [
        ({}, {"method": "PUT"}),
        ({}, {"path": "/v1/sessions/00000000-0000-0000-0000-000000000000/uploaded"}),
        ({}, {"body": b'{"synthetic":false}'}),
        ({}, {"audience": LegacySessionAudience.PROCESSING_COMPLETION}),
        ({}, {"transport": LegacySessionTransport.WORKER_WORKLOAD}),
        ({"generation": 6}, {}),
        ({"revoked": True}, {}),
        ({"replay_decision": ReplayDecision.REJECT}, {}),
        (
            {"expires_at": NOW - timedelta(seconds=1), "issued_at": NOW - timedelta(minutes=1)},
            {},
        ),
    ],
)
def test_wrong_integrity_freshness_generation_revocation_and_replay_are_generic(
    context_change: dict, request_change: dict
) -> None:
    context = dataclasses.replace(_workload_context(), **context_change)

    with pytest.raises(
        LegacySessionSecurityRejectedError, match="request authorization rejected"
    ):
        _authorize(context, **request_change)


def test_wrong_role_subject_shape_and_provider_forgery_are_rejected() -> None:
    wrong_role = dataclasses.replace(
        _workload_context(), principal=_principal(ControlRole.REVIEWER)
    )
    mixed_role = dataclasses.replace(
        _workload_context(),
        principal=AuthenticatedPrincipal(
            "capture-synthetic-1",
            frozenset({ControlRole.CAPTURE_UPLOADER, ControlRole.REVIEWER}),
            TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic"),
        ),
    )

    for context in (wrong_role, mixed_role, object()):
        with pytest.raises(
            LegacySessionSecurityRejectedError, match="request authorization rejected"
        ):
            _authorize(context)  # type: ignore[arg-type]


def test_worker_transport_requires_exact_worker_role_audience_and_action() -> None:
    context = _workload_context(
        role=ControlRole.DETERMINISTIC_WORKER,
        audience=LegacySessionAudience.PROCESSING_COMPLETION,
        transport=LegacySessionTransport.WORKER_WORKLOAD,
    )
    context = dataclasses.replace(
        context,
        path="/v1/internal/sessions/00000000-0000-0000-0000-000000000000/processing-completion",
    )

    authorize_workload_request(
        context=context,
        method="POST",
        path=context.path,
        body=BODY,
        action=ControlAction.SESSION_PROCESSING_COMPLETE,
        audience=LegacySessionAudience.PROCESSING_COMPLETION,
        transport=LegacySessionTransport.WORKER_WORKLOAD,
        now=NOW,
    )
    with pytest.raises(LegacySessionSecurityRejectedError):
        authorize_workload_request(
            context=context,
            method="POST",
            path=context.path,
            body=BODY,
            action=ControlAction.SESSION_REGISTER,
            audience=LegacySessionAudience.PROCESSING_COMPLETION,
            transport=LegacySessionTransport.WORKER_WORKLOAD,
            now=NOW,
        )


def test_unbounded_or_non_utc_context_cannot_be_constructed() -> None:
    with pytest.raises(ValueError, match="lifetime exceeds cap"):
        dataclasses.replace(
            _workload_context(),
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=6),
        )
    with pytest.raises(ValueError, match="exact UTC"):
        dataclasses.replace(_workload_context(), issued_at=NOW.replace(tzinfo=None))


def test_browser_reviewer_reuses_existing_session_validator(monkeypatch) -> None:
    import workflow_api.legacy_session_security as policy

    principal = _principal(ControlRole.REVIEWER, subject="reviewer-synthetic-1")
    context = SessionSecurityContext(
        principal=principal,
        session_identifier_digest="a" * 64,
        session_generation=1,
        active_generation=1,
        issued_at=NOW - timedelta(minutes=2),
        authenticated_at=NOW - timedelta(minutes=2),
        last_seen_at=NOW - timedelta(seconds=10),
        idle_expires_at=NOW + timedelta(minutes=10),
        absolute_expires_at=NOW + timedelta(hours=1),
        revoked=False,
        transport=SessionTransport.BROWSER_COOKIE,
        allowed_browser_origin="https://review.example.com",
        csrf_token_digest=csrf_token_digest(CSRF_TOKEN),
    )
    original = policy.validate_session_security
    calls = 0

    def spy(**kwargs) -> None:
        nonlocal calls
        calls += 1
        original(**kwargs)

    monkeypatch.setattr(policy, "validate_session_security", spy)
    authorization = authorize_browser_request(
        context=context,
        principal=principal,
        method="GET",
        path="/v1/sessions",
        headers=Headers(),
        action=ControlAction.SESSION_LIST,
        now=NOW,
    )

    assert authorization.principal == principal
    assert calls == 1


def test_browser_and_workload_transports_are_not_interchangeable() -> None:
    workload = _workload_context()
    with pytest.raises(LegacySessionSecurityRejectedError):
        authorize_browser_request(
            context=workload,  # type: ignore[arg-type]
            principal=workload.principal,
            method="GET",
            path="/v1/sessions",
            headers=Headers(),
            action=ControlAction.SESSION_LIST,
            now=NOW,
        )
