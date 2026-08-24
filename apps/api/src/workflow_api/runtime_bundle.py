"""Exact, sealed, synthetic-only runtime authority.

Construction performs validation and identity checks only.  It never discovers
configuration, opens a path, constructs a provider, or invokes a collaborator.
"""

from __future__ import annotations

import os
import re
from typing import final
from urllib.parse import urlsplit

from .artifact_gateway import ArtifactGateway, NoNetworkArtifactGateway
from .browser_session_store import (
    SQLiteBrowserSessionStore,
    StoreBackedBrowserSessionProviderFactory,
)
from .candidate_discovery_service import CandidateDiscoveryService
from .candidate_publication_store import SQLiteCandidatePublicationStore
from .config import Settings
from .control_service import ControlService
from .control_store import SQLiteControlStore
from .legacy_session_composition import ProviderNeutralSecurityComposition
from .legacy_session_store import SQLiteLegacySessionStore
from .safety_control import SafetyControlService

_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$")
_HOST_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_MAX_PACKAGE_SIZE_BYTES = 512 * 1024 * 1024
_MAX_BUFFER_SIZE_BYTES = 512 * 1024 * 1024


@final
class SealedSyntheticRuntimeBundle:
    """One exact graph of preconstructed synthetic singleton collaborators."""

    __slots__ = (
        "_artifact_gateway",
        "_browser_factory",
        "_browser_store",
        "_candidate_discovery_service",
        "_candidate_publication_store",
        "_composition",
        "_control_service",
        "_legacy_store",
        "_safety_control_service",
        "_settings",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("sealed runtime bundle cannot be subclassed")

    def __init__(
        self,
        *,
        composition: ProviderNeutralSecurityComposition,
        legacy_store: SQLiteLegacySessionStore,
        browser_store: SQLiteBrowserSessionStore,
        browser_factory: StoreBackedBrowserSessionProviderFactory,
        control_service: ControlService,
        safety_control_service: SafetyControlService,
        settings: Settings,
        artifact_gateway: ArtifactGateway,
        candidate_publication_store: SQLiteCandidatePublicationStore | None = None,
        candidate_discovery_service: CandidateDiscoveryService | None = None,
    ) -> None:
        exact = (
            (composition, ProviderNeutralSecurityComposition, "security composition"),
            (legacy_store, SQLiteLegacySessionStore, "legacy store"),
            (browser_store, SQLiteBrowserSessionStore, "browser store"),
            (
                browser_factory,
                StoreBackedBrowserSessionProviderFactory,
                "browser factory",
            ),
            (control_service, ControlService, "control service"),
            (safety_control_service, SafetyControlService, "safety control service"),
            (settings, Settings, "settings snapshot"),
        )
        for value, expected, label in exact:
            if type(value) is not expected:
                raise TypeError(f"an exact {label} is required")
        is_aws_gateway = False
        if type(artifact_gateway) is not NoNetworkArtifactGateway:
            from .aws_clients import AwsGateway

            if type(artifact_gateway) is not AwsGateway:
                raise TypeError("an exact artifact gateway is required")
            is_aws_gateway = True
        _validate_settings(settings)
        if composition.store is not legacy_store:
            raise ValueError("legacy store identity mismatch")
        if composition.browser_factory is not browser_factory:
            raise ValueError("browser factory identity mismatch")
        if browser_factory.store is not browser_store:
            raise ValueError("browser store identity mismatch")
        if is_aws_gateway and artifact_gateway.settings is not settings:
            raise ValueError("artifact gateway settings identity mismatch")
        if artifact_gateway.presigned_url_ttl_seconds != settings.presigned_url_ttl_seconds:
            raise ValueError("artifact ticket TTL mismatch")
        if artifact_gateway.max_package_size_bytes != settings.max_package_size_bytes:
            raise ValueError("artifact package limit mismatch")
        _validate_candidate_pair(
            candidate_publication_store=candidate_publication_store,
            candidate_discovery_service=candidate_discovery_service,
            control_service=control_service,
        )

        self._composition = composition
        self._legacy_store = legacy_store
        self._browser_store = browser_store
        self._browser_factory = browser_factory
        self._candidate_publication_store = candidate_publication_store
        self._candidate_discovery_service = candidate_discovery_service
        self._control_service = control_service
        self._safety_control_service = safety_control_service
        self._settings = settings
        self._artifact_gateway = artifact_gateway

    @property
    def composition(self) -> ProviderNeutralSecurityComposition:
        return self._composition

    @property
    def legacy_store(self) -> SQLiteLegacySessionStore:
        return self._legacy_store

    @property
    def browser_store(self) -> SQLiteBrowserSessionStore:
        return self._browser_store

    @property
    def browser_factory(self) -> StoreBackedBrowserSessionProviderFactory:
        return self._browser_factory

    @property
    def candidate_publication_store(self) -> SQLiteCandidatePublicationStore | None:
        return self._candidate_publication_store

    @property
    def candidate_discovery_service(self) -> CandidateDiscoveryService | None:
        return self._candidate_discovery_service

    @property
    def control_service(self) -> ControlService:
        return self._control_service

    @property
    def safety_control_service(self) -> SafetyControlService:
        return self._safety_control_service

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def artifact_gateway(self) -> ArtifactGateway:
        return self._artifact_gateway


def _validate_settings(settings: Settings) -> None:
    if settings.model_fields_set != set(Settings.model_fields):
        raise ValueError("every synthetic setting must be explicit")
    if settings.environment != "synthetic":
        raise ValueError("synthetic environment is required")
    origins = settings.allowed_origins
    if (
        not origins
        or len(origins) != len(set(origins))
        or settings.cors_origins != ",".join(origins)
    ):
        raise ValueError("exact synthetic origins are required")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or not parsed.hostname.endswith(".example")
            or not _HOST_PATTERN.fullmatch(parsed.hostname)
            or parsed.hostname != parsed.hostname.lower()
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or origin != f"https://{parsed.hostname}"
        ):
            raise ValueError("only canonical reserved HTTPS origins are allowed")
    if not 1 <= settings.raw_retention_days <= 14:
        raise ValueError("raw retention is outside its synthetic bound")
    if not 1 <= settings.presigned_url_ttl_seconds <= 900:
        raise ValueError("ticket TTL is outside its synthetic bound")
    if not 1 <= settings.max_package_size_bytes <= _MAX_PACKAGE_SIZE_BYTES:
        raise ValueError("package size is outside its synthetic bound")
    for value in (
        settings.max_metadata_size_bytes,
        settings.upload_stream_chunk_bytes,
        settings.upload_spool_memory_bytes,
    ):
        if type(value) is not int or not 1 <= value <= _MAX_BUFFER_SIZE_BYTES:
            raise ValueError("buffer size is outside its synthetic bound")
    if (
        settings.aws_endpoint_url is not None
        or settings.aws_s3_presigned_endpoint_url is not None
        or settings.processing_queue_url is not None
    ):
        raise ValueError("provider endpoints are prohibited")
    labels = (settings.aws_region, settings.raw_bucket, settings.processed_bucket)
    if any(
        type(label) is not str
        or not _LABEL_PATTERN.fullmatch(label)
        or not label.endswith(".example")
        for label in labels
    ):
        raise ValueError("only inert reserved labels are allowed")


def _validate_candidate_pair(
    *,
    candidate_publication_store: SQLiteCandidatePublicationStore | None,
    candidate_discovery_service: CandidateDiscoveryService | None,
    control_service: ControlService,
) -> None:
    """Validate the optional candidate graph without touching the filesystem."""

    if (candidate_publication_store is None) != (candidate_discovery_service is None):
        raise ValueError("candidate publication store/service pair must be complete")
    if candidate_publication_store is None:
        return
    if type(candidate_publication_store) is not SQLiteCandidatePublicationStore:
        raise TypeError("an exact candidate publication store is required")
    if type(candidate_discovery_service) is not CandidateDiscoveryService:
        raise TypeError("an exact candidate discovery service is required")
    if getattr(candidate_discovery_service, "_publication_store", None) is not candidate_publication_store:
        raise ValueError("candidate publication store identity mismatch")
    if getattr(candidate_discovery_service, "_control_service", None) is not control_service:
        raise ValueError("candidate control service identity mismatch")

    control_store = getattr(control_service, "_store", None)
    if type(control_store) is not SQLiteControlStore:
        raise TypeError("candidate discovery requires an exact control store")
    control_path = _candidate_path_key(
        getattr(control_store, "_database_path", None),
        "control database path",
    )
    bound_path = _candidate_path_key(
        candidate_publication_store.control_database_path,
        "candidate control binding",
    )
    publication_path = _candidate_path_key(
        candidate_publication_store.database_path,
        "candidate publication database path",
    )
    if bound_path != control_path:
        raise ValueError("candidate publication control binding mismatch")
    if publication_path == control_path:
        raise ValueError("candidate publication database must be distinct")


def _candidate_path_key(value: object, label: str) -> str:
    if type(value) is not str or not value or value == ":memory:":
        raise ValueError(f"{label} must be a filesystem path")
    # This is lexical normalization only.  Runtime construction must remain
    # inert; inode, symlink, and schema authority checks belong to discovery.
    return os.path.normcase(os.path.normpath(os.path.abspath(value)))
