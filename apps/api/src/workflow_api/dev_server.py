"""Explicit synthetic development server for the sealed runtime bundle.

This module is the only shipped command that constructs the no-network
runtime.  It is deliberately an outer development adapter: the inner
``Settings`` snapshot remains the exact ``environment=synthetic`` bundle
contract, and all proof material is supplied at invocation time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from starlette.datastructures import Headers
from starlette.requests import Request

from .config import Settings
from .control_auth import AuthenticatedPrincipal, ControlRole
from .control_scope import TenantWorkspaceScope
from .identity import (
    AuthenticationAssurance,
    AuthenticationContext,
    AuthenticationMethod,
    GroupRoleBinding,
    GroupRoleMapping,
    SubjectScopeBinding,
    SubjectScopePolicy,
    VerifiedIdentityEvidence,
)
from .legacy_session_security import (
    LegacySessionAudience,
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
)
from .runtime_bundle import SealedSyntheticRuntimeBundle
from .session_security import csrf_token_digest

_DEV_ENVIRONMENTS: Final = frozenset({"development", "dev", "local", "test"})
_TOKEN_PATTERN: Final = re.compile(r"^[A-Za-z0-9._:-]{32,256}$")
_MATERIAL_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")
_FORBIDDEN_PROVIDER_SOURCES: Final = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_CA_BUNDLE",
    "AWS_SDK_LOAD_CONFIG",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "BOTO_CONFIG",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_CREDENTIALS",
    "GOOGLE_AUTHENTICATION",
    "GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE",
    "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE",
    "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL",
    "GOOGLE_WORKLOAD_IDENTITY_PROVIDER",
    "GOOGLE_CLOUD_PROJECT",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_CONFIG",
    "GCE_METADATA_HOST",
    "GCE_METADATA_IP",
    "AWS_ENDPOINT_URL",
    "AWS_S3_PRESIGNED_ENDPOINT_URL",
    "PROCESSING_QUEUE_URL",
)

_FORBIDDEN_PROOF_VALUES: Final = frozenset(
    {
        "changeme",
        "change-me",
        "default",
        "dev",
        "local",
        "password",
        "placeholder",
        "replace-me",
        "secret",
        "synthetic",
        "test",
        "token",
    }
)

_SCOPE = TenantWorkspaceScope("tenant.synthetic", "workspace.synthetic")
_CAPTURE_SUBJECT = "capture-uploader.synthetic"
_WORKER_SUBJECT = "worker.synthetic"
_REVIEWER_SUBJECT = "reviewer.synthetic"
_REVIEWER_ORIGIN = "https://review.synthetic.example"


@dataclass(frozen=True, slots=True)
class _DevCredentials:
    """Runtime-only material; no raw value is stored in the bundle."""

    capture_proof: str
    worker_proof: str
    reviewer_proof: str
    reviewer_session: str
    reviewer_csrf: str


class _DevAuthenticator:
    __slots__ = ("_principal",)

    def __init__(self, principal: AuthenticatedPrincipal) -> None:
        self._principal = principal

    def authenticate(self) -> VerifiedIdentityEvidence:
        return VerifiedIdentityEvidence(
            subject=self._principal.subject,
            groups=("reviewer-synthetic",),
            authentication_context=AuthenticationContext(
                AuthenticationAssurance.MULTI_FACTOR,
                (AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
            ),
            scope=_SCOPE,
        )


class _DevWorkloadProvider:
    __slots__ = ("_capture_principal", "_capture_proof", "_worker_principal", "_worker_proof")

    def __init__(
        self,
        *,
        capture_principal: AuthenticatedPrincipal,
        capture_proof: str,
        worker_principal: AuthenticatedPrincipal,
        worker_proof: str,
    ) -> None:
        self._capture_principal = capture_principal
        self._capture_proof = capture_proof
        self._worker_principal = worker_principal
        self._worker_proof = worker_proof

    def get_workload_context(
        self,
        *,
        method: str,
        path: str,
        body_sha256: str,
        headers: object,
    ) -> LegacyWorkloadContext:
        if type(headers) is not Headers:
            raise LegacySessionSecurityRejectedError("request authorization rejected")
        worker_request = path.startswith("/v1/internal/")
        expected = self._worker_proof if worker_request else self._capture_proof
        presented = headers.getlist("x-workflow-dev-proof")
        if len(presented) != 1 or presented[0] != expected:
            raise LegacySessionSecurityRejectedError("request authorization rejected")
        principal = self._worker_principal if worker_request else self._capture_principal
        audience = (
            LegacySessionAudience.PROCESSING_COMPLETION
            if worker_request
            else LegacySessionAudience.CAPTURE_UPLOAD
        )
        transport = (
            LegacySessionTransport.WORKER_WORKLOAD
            if worker_request
            else LegacySessionTransport.CAPTURE_WORKLOAD
        )
        now = datetime.now(UTC)
        proof_digest = hashlib.sha256(
            f"{principal.subject}\0{method}\0{path}\0{body_sha256}".encode()
        ).hexdigest()
        return LegacyWorkloadContext(
            principal=principal,
            audience=audience,
            transport=transport,
            method=method,
            path=path,
            body_sha256=body_sha256,
            proof_identifier_digest=proof_digest,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=1),
            generation=1,
            active_generation=1,
            revoked=False,
            replay_decision=ReplayDecision.ACCEPT,
        )


def _require_dev_environment() -> None:
    """Reject non-development execution before any runtime side effect."""

    value = os.environ.get("ENVIRONMENT")
    if type(value) is not str or value != value.strip() or value not in _DEV_ENVIRONMENTS:
        raise RuntimeError("workflow_api.dev_server requires an explicit dev-like ENVIRONMENT")


def _reject_provider_sources() -> None:
    for name in _FORBIDDEN_PROVIDER_SOURCES:
        value = os.environ.get(name)
        if isinstance(value, str) and value.strip():
            raise RuntimeError(f"ambient provider source is forbidden: {name}")


def _required_token(name: str) -> str:
    value = os.environ.get(name)
    if (
        type(value) is not str
        or value != value.strip()
        or not _TOKEN_PATTERN.fullmatch(value)
        or value.casefold() in _FORBIDDEN_PROOF_VALUES
        or len(set(value)) < 4
    ):
        raise RuntimeError(f"{name} must be a runtime-supplied synthetic proof")
    return value


def _required_material(name: str) -> str:
    value = os.environ.get(name)
    if type(value) is not str or value != value.strip() or not _MATERIAL_PATTERN.fullmatch(value):
        raise RuntimeError(f"{name} must be canonical runtime-supplied material")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(f"{name} must be canonical runtime-supplied material") from exc
    if (
        len(decoded) != 32
        or len(set(decoded)) < 4
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise RuntimeError(f"{name} must be canonical runtime-supplied material")
    return value


def _required_data_dir() -> Path:
    value = os.environ.get("WORKFLOW_DEV_DATA_DIR")
    if type(value) is not str or value != value.strip() or not value:
        raise RuntimeError("WORKFLOW_DEV_DATA_DIR must be an absolute dedicated path")
    path = Path(value)
    if (
        not path.is_absolute()
        or path == Path("/")
        or len(path.parts) < 3
        or ".." in path.parts
        or path.is_symlink()
        or not path.parent.is_dir()
    ):
        raise RuntimeError("WORKFLOW_DEV_DATA_DIR must be an absolute dedicated path")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise RuntimeError("WORKFLOW_DEV_DATA_DIR must be fresh and dedicated")
    return path


def _read_credentials() -> _DevCredentials:
    _reject_provider_sources()
    credentials = _DevCredentials(
        capture_proof=_required_token("WORKFLOW_DEV_CAPTURE_PROOF"),
        worker_proof=_required_token("WORKFLOW_DEV_WORKER_PROOF"),
        reviewer_proof=_required_token("WORKFLOW_DEV_REVIEWER_PROOF"),
        reviewer_session=_required_material("WORKFLOW_DEV_REVIEWER_SESSION"),
        reviewer_csrf=_required_material("WORKFLOW_DEV_REVIEWER_CSRF"),
    )
    if (
        len(
            {
                credentials.capture_proof,
                credentials.worker_proof,
                credentials.reviewer_proof,
                credentials.reviewer_session,
                credentials.reviewer_csrf,
            }
        )
        != 5
    ):
        raise RuntimeError("synthetic proof inputs must be distinct")
    return credentials


def _synthetic_settings() -> Settings:
    """Return the exact inert settings admitted by ADR 0012."""

    return Settings(
        _env_file=None,
        environment="synthetic",
        log_level="INFO",
        cors_origins=_REVIEWER_ORIGIN,
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


def _session_digest(material: str) -> str:
    raw = base64.urlsafe_b64decode(material + "=")
    return hashlib.sha256(raw).hexdigest()


def _build_bundle(
    *,
    data_dir: Path,
    credentials: _DevCredentials,
) -> SealedSyntheticRuntimeBundle:
    """Construct one fixed synthetic graph after all outer guards pass."""

    from .in_process_runtime import create_in_process_no_network_bundle

    capture = AuthenticatedPrincipal(
        _CAPTURE_SUBJECT, frozenset({ControlRole.CAPTURE_UPLOADER}), _SCOPE
    )
    worker = AuthenticatedPrincipal(
        _WORKER_SUBJECT, frozenset({ControlRole.DETERMINISTIC_WORKER}), _SCOPE
    )
    reviewer = AuthenticatedPrincipal(_REVIEWER_SUBJECT, frozenset({ControlRole.REVIEWER}), _SCOPE)
    mapping = GroupRoleMapping(
        (
            GroupRoleBinding("capture-uploader-synthetic", (ControlRole.CAPTURE_UPLOADER,)),
            GroupRoleBinding("worker-synthetic", (ControlRole.DETERMINISTIC_WORKER,)),
            GroupRoleBinding("reviewer-synthetic", (ControlRole.REVIEWER,)),
        )
    )
    policy = SubjectScopePolicy(
        (
            SubjectScopeBinding(_CAPTURE_SUBJECT, _SCOPE),
            SubjectScopeBinding(_WORKER_SUBJECT, _SCOPE),
            SubjectScopeBinding(_REVIEWER_SUBJECT, _SCOPE),
        )
    )

    def authenticator_factory(request: Request) -> _DevAuthenticator:
        presented = request.headers.getlist("x-workflow-dev-reviewer-proof")
        if len(presented) != 1 or presented[0] != credentials.reviewer_proof:
            raise RuntimeError("reviewer proof rejected")
        return _DevAuthenticator(reviewer)

    provider = _DevWorkloadProvider(
        capture_principal=capture,
        capture_proof=credentials.capture_proof,
        worker_principal=worker,
        worker_proof=credentials.worker_proof,
    )

    data_dir.mkdir(parents=True, exist_ok=False)
    bundle = create_in_process_no_network_bundle(
        data_dir=data_dir,
        settings=_synthetic_settings(),
        group_role_mapping=mapping,
        subject_scope_policy=policy,
        authenticator_factory=authenticator_factory,
        workload_credential_verifier_factory=lambda _request: provider,
    )
    now = datetime.now(UTC)
    bundle.legacy_store.register_workload_principal(
        principal_subject=_CAPTURE_SUBJECT,
        scope=_SCOPE,
        audience=LegacySessionAudience.CAPTURE_UPLOAD,
        role=ControlRole.CAPTURE_UPLOADER,
        transport=LegacySessionTransport.CAPTURE_WORKLOAD,
    )
    bundle.legacy_store.register_workload_principal(
        principal_subject=_WORKER_SUBJECT,
        scope=_SCOPE,
        audience=LegacySessionAudience.PROCESSING_COMPLETION,
        role=ControlRole.DETERMINISTIC_WORKER,
        transport=LegacySessionTransport.WORKER_WORKLOAD,
    )
    browser_store = bundle.browser_store
    browser_store.register_session(
        session_identifier_digest=_session_digest(credentials.reviewer_session),
        csrf_token_digest=csrf_token_digest(credentials.reviewer_csrf),
        principal=reviewer,
        allowed_browser_origin=_REVIEWER_ORIGIN,
        issued_at=now - timedelta(seconds=2),
        authenticated_at=now - timedelta(seconds=2),
        last_seen_at=now - timedelta(seconds=1),
        idle_expires_at=now + timedelta(minutes=10),
        absolute_expires_at=now + timedelta(minutes=30),
    )
    return bundle


def build_app():
    """Build one fresh synthetic app, guarded by the outer dev contract."""

    _require_dev_environment()
    credentials = _read_credentials()
    data_dir = _required_data_dir()
    from .main import create_app

    return create_app(_build_bundle(data_dir=data_dir, credentials=credentials))


def main() -> None:
    """Serve the explicitly constructed app; no import-time app is installed."""

    application = build_app()
    import uvicorn

    uvicorn.run(application, host="0.0.0.0", port=8000, log_level="info")


if __name__ == "__main__":
    main()
