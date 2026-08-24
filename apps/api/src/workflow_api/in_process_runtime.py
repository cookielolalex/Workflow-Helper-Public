"""Explicit in-process construction for the no-network synthetic runtime.

The caller supplies every policy and configuration input.  Construction uses
only fixed component-local SQLite filenames and never installs the returned
bundle into the default application.
"""

from __future__ import annotations

from pathlib import Path

from .artifact_gateway import NoNetworkArtifactGateway
from .browser_session_store import (
    SQLiteBrowserSessionStore,
    StoreBackedBrowserSessionProviderFactory,
)
from .candidate_discovery_service import CandidateDiscoveryService
from .candidate_publication_store import SQLiteCandidatePublicationStore
from .config import Settings
from .control_service import ControlService
from .control_store import SQLiteControlStore
from .identity import GroupRoleMapping, SubjectScopePolicy
from .legacy_session_composition import (
    AuthenticatorFactory,
    ProviderNeutralSecurityComposition,
    WorkloadCredentialVerifierFactory,
)
from .legacy_session_store import SQLiteLegacySessionStore
from .retention_store import RetentionLedger
from .runtime_bundle import SealedSyntheticRuntimeBundle, _validate_settings
from .safety_control import SafetyControlService
from .safety_switches import SafetySwitchLedger


def create_in_process_no_network_bundle(
    *,
    data_dir: Path,
    settings: Settings,
    group_role_mapping: GroupRoleMapping,
    subject_scope_policy: SubjectScopePolicy,
    authenticator_factory: AuthenticatorFactory,
    workload_credential_verifier_factory: WorkloadCredentialVerifierFactory,
) -> SealedSyntheticRuntimeBundle:
    """Construct one explicit six-store, no-network synthetic authority graph."""

    if type(data_dir) is not type(Path()):
        raise TypeError("an exact pathlib Path data directory is required")
    if not data_dir.is_absolute():
        raise ValueError("an absolute data directory is required")
    if type(settings) is not Settings:
        raise TypeError("an exact settings snapshot is required")
    if type(group_role_mapping) is not GroupRoleMapping:
        raise TypeError("an exact group-role mapping is required")
    if type(subject_scope_policy) is not SubjectScopePolicy:
        raise TypeError("an exact subject-scope policy is required")
    if not callable(authenticator_factory):
        raise TypeError("an authenticator factory is required")
    if not callable(workload_credential_verifier_factory):
        raise TypeError("a workload credential verifier factory is required")

    # This is the existing sealed-bundle settings boundary.  Keep it ahead of
    # every store constructor because those constructors may create directories.
    _validate_settings(settings)

    legacy_store = SQLiteLegacySessionStore(data_dir / "legacy.sqlite3")
    browser_store = SQLiteBrowserSessionStore(data_dir / "browser.sqlite3")
    control_store = SQLiteControlStore(data_dir / "control.sqlite3")
    candidate_publication_store = SQLiteCandidatePublicationStore(
        data_dir / "candidate-publications.sqlite3",
        control_database_path=control_store,
    )
    retention = RetentionLedger(data_dir / "retention.sqlite3")
    safety_ledger = SafetySwitchLedger(data_dir / "safety.sqlite3")

    browser_factory = StoreBackedBrowserSessionProviderFactory(store=browser_store)
    composition = ProviderNeutralSecurityComposition(
        group_role_mapping=group_role_mapping,
        subject_scope_policy=subject_scope_policy,
        authenticator_factory=authenticator_factory,
        browser_session_provider_factory=browser_factory,
        workload_credential_verifier_factory=workload_credential_verifier_factory,
        store=legacy_store,
    )
    control_service = ControlService(control_store, retention)
    candidate_discovery_service = CandidateDiscoveryService(
        candidate_publication_store,
        control_service,
    )
    safety_control_service = SafetyControlService(safety_ledger)
    artifact_gateway = NoNetworkArtifactGateway(
        ticket_origin="https://uploads.synthetic.example",
        presigned_url_ttl_seconds=settings.presigned_url_ttl_seconds,
        max_package_size_bytes=settings.max_package_size_bytes,
    )
    return SealedSyntheticRuntimeBundle(
        composition=composition,
        legacy_store=legacy_store,
        browser_store=browser_store,
        browser_factory=browser_factory,
        control_service=control_service,
        safety_control_service=safety_control_service,
        settings=settings,
        artifact_gateway=artifact_gateway,
        candidate_publication_store=candidate_publication_store,
        candidate_discovery_service=candidate_discovery_service,
    )
