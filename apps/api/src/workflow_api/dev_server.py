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
import json
import math
import os
import re
import sqlite3
import stat
from contextlib import ExitStack, closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final
from urllib.parse import quote

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
_DATABASE_NAMES: Final = (
    "browser.sqlite3",
    "candidate-publications.sqlite3",
    "control.sqlite3",
    "legacy.sqlite3",
    "retention.sqlite3",
    "safety.sqlite3",
)
_MAX_EXISTING_DATABASE_BYTES: Final = 64 * 1024 * 1024
_MAX_EXISTING_DATABASE_ROWS: Final = 100_000


@dataclass(frozen=True, slots=True)
class _DevCredentials:
    """Runtime-only material; no raw value is stored in the bundle."""

    capture_proof: str
    worker_proof: str
    reviewer_proof: str
    reviewer_session: str
    reviewer_csrf: str


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    owner: int
    mode: int
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _ExistingRuntimeSnapshot:
    directory: _PathIdentity
    databases: tuple[tuple[str, _PathIdentity, str], ...]
    sidecars: tuple[tuple[str, _PathIdentity], ...]


def _path_identity(path: Path, *, directory: bool) -> _PathIdentity:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError("existing synthetic runtime path is unavailable") from exc
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o7022
    ):
        raise RuntimeError("existing synthetic runtime path is unsafe")
    return _PathIdentity(
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _typed_sqlite_value(value: object) -> tuple[str, str]:
    if value is None:
        return ("null", "")
    if type(value) is int:
        return ("integer", str(value))
    if type(value) is float and math.isfinite(value):
        return ("real", value.hex())
    if type(value) is str:
        return ("text", value)
    if type(value) is bytes:
        return ("blob", value.hex())
    raise RuntimeError("existing synthetic runtime contains an unsupported SQLite value")


def _digest_record(hasher: object, label: str, values: tuple[object, ...]) -> None:
    encoded = json.dumps(
        [label, *(_typed_sqlite_value(value) for value in values)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)


def _quoted_identifier(value: str) -> str:
    if type(value) is not str or not value or "\0" in value:
        raise RuntimeError("existing synthetic runtime schema is invalid")
    return '"' + value.replace('"', '""') + '"'


def _database_digest(path: Path) -> str:
    if path.stat().st_size > _MAX_EXISTING_DATABASE_BYTES:
        raise RuntimeError("existing synthetic runtime database exceeds its bound")
    uri = f"file:{quote(str(path), safe='/')}?mode=ro"
    hasher = hashlib.sha256()
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            connection.execute("pragma query_only = on")
            connection.execute("begin")
            try:
                if connection.execute("pragma integrity_check").fetchall() != [("ok",)]:
                    raise RuntimeError(
                        "existing synthetic runtime database failed integrity check"
                    )
                schema = connection.execute(
                    "select type, name, tbl_name, rootpage, sql "
                    "from sqlite_schema order by type, name, tbl_name, rootpage, sql"
                ).fetchall()
                for row in schema:
                    _digest_record(hasher, "schema", tuple(row))

                tables = sorted(
                    row[0]
                    for row in connection.execute(
                        "select name from sqlite_schema where type = 'table'"
                    ).fetchall()
                )
                row_count = 0
                for table in tables:
                    rows: list[bytes] = []
                    query = f"select * from {_quoted_identifier(table)}"
                    for row in connection.execute(query):
                        row_count += 1
                        if row_count > _MAX_EXISTING_DATABASE_ROWS:
                            raise RuntimeError(
                                "existing synthetic runtime database exceeds its row bound"
                            )
                        rows.append(
                            json.dumps(
                                [_typed_sqlite_value(value) for value in row],
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        )
                    _digest_record(hasher, "table", (table,))
                    for row in sorted(rows):
                        hasher.update(len(row).to_bytes(8, "big"))
                        hasher.update(row)
            finally:
                connection.rollback()
    except sqlite3.Error as exc:
        raise RuntimeError("existing synthetic runtime database is unavailable") from exc
    return hasher.hexdigest()


def _existing_runtime_snapshot(data_dir: Path) -> _ExistingRuntimeSnapshot:
    directory = _path_identity(data_dir, directory=True)
    try:
        initial_entries = tuple(data_dir.iterdir())
    except OSError as exc:
        raise RuntimeError("existing synthetic runtime directory is unavailable") from exc
    allowed_sidecars = {
        f"{name}{suffix}"
        for name in _DATABASE_NAMES
        for suffix in ("-shm", "-wal")
    }
    initial_names = {path.name for path in initial_entries}
    if (
        not set(_DATABASE_NAMES).issubset(initial_names)
        or initial_names - set(_DATABASE_NAMES) - allowed_sidecars
    ):
        raise RuntimeError("existing synthetic runtime must contain exactly six databases")
    databases = []
    for name in _DATABASE_NAMES:
        path = data_dir / name
        identity = _path_identity(path, directory=False)
        if identity.device != directory.device:
            raise RuntimeError("existing synthetic runtime path is unsafe")
        databases.append((name, identity, _database_digest(path)))
        if _path_identity(path, directory=False) != identity:
            raise RuntimeError("existing synthetic runtime identity changed during validation")
    try:
        final_entries = tuple(data_dir.iterdir())
    except OSError as exc:
        raise RuntimeError("existing synthetic runtime directory is unavailable") from exc
    final_names = {path.name for path in final_entries}
    if (
        not set(_DATABASE_NAMES).issubset(final_names)
        or final_names - set(_DATABASE_NAMES) - allowed_sidecars
    ):
        raise RuntimeError("existing synthetic runtime must contain exactly six databases")
    sidecars = []
    for path in sorted(final_entries, key=lambda item: item.name):
        if path.name in allowed_sidecars:
            identity = _path_identity(path, directory=False)
            if identity.device != directory.device:
                raise RuntimeError("existing synthetic runtime path is unsafe")
            sidecars.append((path.name, identity))
    if _path_identity(data_dir, directory=True) != directory:
        raise RuntimeError("existing synthetic runtime identity changed during validation")
    return _ExistingRuntimeSnapshot(directory, tuple(databases), tuple(sidecars))


def _validate_existing_runtime_paths(data_dir: Path) -> None:
    """Reject unsafe database paths before opening any SQLite connection."""

    directory = _path_identity(data_dir, directory=True)
    try:
        entries = tuple(data_dir.iterdir())
    except OSError as exc:
        raise RuntimeError("existing synthetic runtime directory is unavailable") from exc
    allowed_names = set(_DATABASE_NAMES) | {
        f"{name}{suffix}"
        for name in _DATABASE_NAMES
        for suffix in ("-shm", "-wal")
    }
    names = {path.name for path in entries}
    if not set(_DATABASE_NAMES).issubset(names) or names - allowed_names:
        raise RuntimeError("existing synthetic runtime must contain exactly six databases")
    for path in entries:
        identity = _path_identity(path, directory=False)
        if identity.device != directory.device:
            raise RuntimeError("existing synthetic runtime path is unsafe")


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


def _required_existing_data_dir() -> Path:
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
        or not path.is_dir()
    ):
        raise RuntimeError("WORKFLOW_DEV_DATA_DIR must contain an existing runtime")
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


def _construct_bundle(
    *,
    data_dir: Path,
    credentials: _DevCredentials,
    create_directory: bool,
) -> tuple[
    SealedSyntheticRuntimeBundle,
    AuthenticatedPrincipal,
    AuthenticatedPrincipal,
    AuthenticatedPrincipal,
]:
    """Construct one fixed graph without registering durable identities."""

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

    if create_directory:
        data_dir.mkdir(parents=True, exist_ok=False)
    bundle = create_in_process_no_network_bundle(
        data_dir=data_dir,
        settings=_synthetic_settings(),
        group_role_mapping=mapping,
        subject_scope_policy=policy,
        authenticator_factory=authenticator_factory,
        workload_credential_verifier_factory=lambda _request: provider,
    )
    return bundle, capture, worker, reviewer


def _build_bundle(
    *,
    data_dir: Path,
    credentials: _DevCredentials,
) -> SealedSyntheticRuntimeBundle:
    """Construct and initialize one fresh fixed synthetic graph."""

    bundle, _capture, _worker, reviewer = _construct_bundle(
        data_dir=data_dir,
        credentials=credentials,
        create_directory=True,
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


def _open_existing_bundle(
    *,
    data_dir: Path,
    credentials: _DevCredentials,
) -> SealedSyntheticRuntimeBundle:
    """Open one exact existing graph without initialization or repair calls."""

    _validate_existing_runtime_paths(data_dir)
    with ExitStack() as connections:
        for name in _DATABASE_NAMES:
            uri = f"file:{quote(str(data_dir / name), safe='/')}?mode=ro"
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(uri, uri=True)
                connection.execute("pragma query_only = on")
                journal_mode = connection.execute("pragma journal_mode").fetchone()
                if journal_mode == ("wal",):
                    connection.execute("begin")
                    connection.execute("select count(*) from sqlite_schema").fetchone()
                    connections.enter_context(closing(connection))
                    connection = None
            except sqlite3.Error as exc:
                raise RuntimeError(
                    "existing synthetic runtime database is unavailable"
                ) from exc
            finally:
                if connection is not None:
                    connection.close()
        before = _existing_runtime_snapshot(data_dir)
        bundle, _capture, _worker, _reviewer = _construct_bundle(
            data_dir=data_dir,
            credentials=credentials,
            create_directory=False,
        )
        after = _existing_runtime_snapshot(data_dir)
        if after != before:
            raise RuntimeError("existing synthetic runtime changed while opening")
    return bundle


def build_app():
    """Build one fresh synthetic app, guarded by the outer dev contract."""

    _require_dev_environment()
    credentials = _read_credentials()
    data_dir = _required_data_dir()
    from .main import create_app

    return create_app(_build_bundle(data_dir=data_dir, credentials=credentials))


def open_existing_app():
    """Open an existing synthetic app for a bounded non-serving harness."""

    _require_dev_environment()
    credentials = _read_credentials()
    data_dir = _required_existing_data_dir()
    from .main import create_app

    return create_app(
        _open_existing_bundle(data_dir=data_dir, credentials=credentials)
    )


def main() -> None:
    """Serve the explicitly constructed app; no import-time app is installed."""

    application = build_app()
    import uvicorn

    uvicorn.run(application, host="0.0.0.0", port=8000, log_level="info")


if __name__ == "__main__":
    main()
