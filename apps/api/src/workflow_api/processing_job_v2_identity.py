"""Dormant, pure API payload identity for exact ProcessingJobV2 values."""

from __future__ import annotations

from hashlib import sha256
from uuid import UUID

from workflow_api.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJobV2,
)

PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID = (
    "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
)
PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX = (
    b"workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0"
)

_DIGEST_REJECTED = "payload digest rejected"
_MAX_PACKAGE_BYTES = 536_870_912
_JOB_FIELDS = frozenset({"schema_version", "job_id", "session_id", "input_artifact"})
_ARTIFACT_FIELDS = frozenset(
    {"provider", "file_id", "revision", "sha256", "size_bytes", "mime_type", "role"}
)
_SHORT_ESCAPES = {
    "\x08": "\\b",
    "\x09": "\\t",
    "\x0a": "\\n",
    "\x0c": "\\f",
    "\x0d": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


def _reject() -> None:
    raise ValueError(_DIGEST_REJECTED) from None


def _has_exact_fields(value: object, expected: frozenset[str]) -> bool:
    try:
        fields = object.__getattribute__(value, "__dict__")
        extra = object.__getattribute__(value, "__pydantic_extra__")
    except Exception:  # noqa: BLE001 - every input failure has one public result
        return False
    return (
        type(fields) is dict
        and len(fields) == len(expected)
        and all(type(field) is str and field in expected for field in fields)
        and (extra is None or (type(extra) is dict and not extra))
    )


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


def _admit_processing_job_v2(job: ProcessingJobV2) -> ProcessingJobV2:
    """Return one independent exact API snapshot or fail with the digest error."""

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
        snapshot.schema_version != "2.0"
        or type(snapshot.job_id) is not UUID
        or type(snapshot.session_id) is not UUID
        or type(artifact) is not ArtifactRef
        or type(artifact.provider) is not ArtifactProvider
        or artifact.provider not in (ArtifactProvider.S3, ArtifactProvider.GOOGLE_DRIVE)
        or type(artifact.file_id) is not str
        or not 1 <= len(artifact.file_id) <= 1024
        or type(artifact.revision) is not str
        or not 1 <= len(artifact.revision) <= 255
        or type(artifact.sha256) is not str
        or len(artifact.sha256) != 64
        or any(character not in "0123456789abcdef" for character in artifact.sha256)
        or type(artifact.size_bytes) is not int
        or not 1 <= artifact.size_bytes <= _MAX_PACKAGE_BYTES
        or type(artifact.mime_type) is not str
        or artifact.mime_type != "application/zip"
        or type(artifact.role) is not ArtifactRole
        or artifact.role is not ArtifactRole.RAW_PACKAGE
    ):
        _reject()

    return snapshot


def _validate_scalar_string(value: object) -> str:
    if type(value) is not str:
        _reject()
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _reject()
    return value


def _quote_string(value: object) -> str:
    scalar = _validate_scalar_string(value)
    encoded: list[str] = ['"']
    for character in scalar:
        escaped = _SHORT_ESCAPES.get(character)
        if escaped is not None:
            encoded.append(escaped)
        elif ord(character) <= 0x1F:
            encoded.append(f"\\u{ord(character):04x}")
        else:
            encoded.append(character)
    encoded.append('"')
    return "".join(encoded)


def _utf16_sort_key(value: object) -> bytes:
    return _validate_scalar_string(value).encode("utf-16-be")


def _serialize_restricted_jcs(value: object) -> str:
    """Serialize only the scalar/object subset used by the frozen digest schema."""

    if type(value) is str:
        return _quote_string(value)
    if type(value) is int:
        return str(value)
    if type(value) is dict:
        entries: list[str] = []
        keys = list(value)
        if any(type(key) is not str for key in keys):
            _reject()
        for key in sorted(keys, key=_utf16_sort_key):
            entries.append(f"{_quote_string(key)}:{_serialize_restricted_jcs(value[key])}")
        return "{" + ",".join(entries) + "}"
    _reject()


def _normalized_semantic_object(job: ProcessingJobV2) -> dict[str, object]:
    artifact = job.input_artifact
    return {
        "schema_version": job.schema_version,
        "job_id": str(job.job_id),
        "session_id": str(job.session_id),
        "input_artifact": {
            "provider": artifact.provider.value,
            "file_id": artifact.file_id,
            "revision": artifact.revision,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "mime_type": artifact.mime_type,
            "role": artifact.role.value,
        },
    }


def canonical_processing_job_v2_payload_preimage(job: ProcessingJobV2) -> bytes:
    """Return the domain-separated RFC 8785 preimage for one exact API job."""

    preimage: bytes | None = None
    try:
        snapshot = _admit_processing_job_v2(job)
        semantic_object = _normalized_semantic_object(snapshot)
        canonical_json = _serialize_restricted_jcs(semantic_object).encode("utf-8")
        preimage = PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX + canonical_json
    except Exception:  # noqa: BLE001,S110 - replace all details below
        pass
    if preimage is None:
        _reject()
    return preimage


def processing_job_v2_payload_digest(job: ProcessingJobV2) -> str:
    """Return the lowercase SHA-256 digest for one exact API v2 payload."""

    preimage = canonical_processing_job_v2_payload_preimage(job)
    digest: str | None = None
    try:
        digest = sha256(preimage).hexdigest()
    except Exception:  # noqa: BLE001,S110 - replace all details below
        pass
    if digest is None:
        _reject()
    return digest
