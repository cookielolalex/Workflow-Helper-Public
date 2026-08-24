"""Dormant, pure semantic admission for raw package input references."""

from __future__ import annotations

from uuid import UUID

from workflow_worker.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJobV2,
)

_ADMISSION_REJECTED = "package input admission rejected"
_MAX_PACKAGE_BYTES = 536_870_912
_JOB_FIELDS = frozenset({"schema_version", "job_id", "session_id", "input_artifact"})
_ARTIFACT_FIELDS = frozenset(
    {"provider", "file_id", "revision", "sha256", "size_bytes", "mime_type", "role"}
)


def _has_exact_fields(value: object, expected: frozenset[str]) -> bool:
    try:
        fields = object.__getattribute__(value, "__dict__")
        extra = object.__getattribute__(value, "__pydantic_extra__")
    except Exception:  # noqa: BLE001 - all input failures have one public result
        return False
    return (
        type(fields) is dict
        and len(fields) == len(expected)
        and all(type(field) is str and field in expected for field in fields)
        and (extra is None or (type(extra) is dict and not extra))
    )


def _reject() -> None:
    raise ValueError(_ADMISSION_REJECTED) from None


def _has_exact_source_types(job: ProcessingJobV2, artifact: ArtifactRef) -> bool:
    return (
        type(job.schema_version) is str
        and type(job.job_id) is UUID
        and type(job.session_id) is UUID
        and type(artifact.provider) is ArtifactProvider
        and type(artifact.file_id) is str
        and type(artifact.revision) is str
        and type(artifact.sha256) is str
        and type(artifact.size_bytes) is int
        and type(artifact.mime_type) is str
        and type(artifact.role) is ArtifactRole
    )


def admit_package_input(job: ProcessingJobV2) -> ProcessingJobV2:
    """Return an independent exact snapshot only for an admissible package job."""

    if type(job) is not ProcessingJobV2 or not _has_exact_fields(job, _JOB_FIELDS):
        _reject()

    source_artifact = job.input_artifact
    if type(source_artifact) is not ArtifactRef or not _has_exact_fields(
        source_artifact, _ARTIFACT_FIELDS
    ):
        _reject()
    if not _has_exact_source_types(job, source_artifact):
        _reject()

    snapshot: ProcessingJobV2 | None = None
    try:
        serialized = ProcessingJobV2.model_dump_json(job, warnings="error")
        snapshot = ProcessingJobV2.model_validate_json(serialized)
    except Exception:  # noqa: BLE001,S110 - replace all validation details below
        pass
    if snapshot is None or type(snapshot) is not ProcessingJobV2:
        _reject()

    artifact = snapshot.input_artifact
    if (
        type(artifact) is not ArtifactRef
        or type(artifact.provider) is not ArtifactProvider
        or artifact.provider not in (ArtifactProvider.S3, ArtifactProvider.GOOGLE_DRIVE)
        or type(artifact.role) is not ArtifactRole
        or artifact.role is not ArtifactRole.RAW_PACKAGE
        or type(artifact.mime_type) is not str
        or artifact.mime_type != "application/zip"
        or type(artifact.size_bytes) is not int
        or not 1 <= artifact.size_bytes <= _MAX_PACKAGE_BYTES
    ):
        _reject()

    return snapshot
