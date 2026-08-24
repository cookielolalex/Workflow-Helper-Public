"""Dormant, pure result-manifest identity for admitted ProcessingJobV2 jobs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256

from workflow_worker.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJobV2,
)
from workflow_worker.package_input_admission import admit_package_input
from workflow_worker.processing_job_v2_identity import (
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID,
    processing_job_v2_payload_digest,
)

PROCESSING_JOB_V2_RESULT_DIGEST_SCHEME_ID = "workflow-helper.processing-job-v2.result.sha256-jcs.v1"
PROCESSING_JOB_V2_RESULT_DIGEST_DOMAIN_PREFIX = (
    b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
)
PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES = 16_777_216

_DIGEST_REJECTED = "result digest rejected"
_JOB_FIELDS = frozenset({"schema_version", "job_id", "session_id", "input_artifact"})
_ARTIFACT_FIELDS = frozenset(
    {"provider", "file_id", "revision", "sha256", "size_bytes", "mime_type", "role"}
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "job_id",
        "session_id",
        "payload_digest_scheme",
        "payload_digest",
        "outputs",
    }
)
_OUTPUT_FIELDS = frozenset({"store_namespace", "artifact_ref"})
_LOWER_SHA256 = re.compile(r"[a-f0-9]{64}", re.ASCII)
_DRIVE_NAMESPACE = re.compile(r"google-drive://[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_-]{1,128}", re.ASCII)
_S3_NAMESPACE = re.compile(
    r"aws-s3://(?:aws|aws-cn|aws-us-gov)/[0-9]{12}/"
    r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]/"
    r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]",
    re.ASCII,
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
_ROLE_MIME = {
    ArtifactRole.TIMELINE: "application/json",
    ArtifactRole.MANIFEST: "application/json",
    ArtifactRole.CROP: "image/png",
}


@dataclass(frozen=True, slots=True)
class ProcessingJobV2ResultOutputBinding:
    """A caller-supplied locator binding; public builders always snapshot it."""

    store_namespace: str
    artifact_ref: ArtifactRef


def _reject() -> None:
    raise ValueError(_DIGEST_REJECTED) from None


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
    """Serialize only object, array, scalar string, and mathematical integer."""

    if type(value) is str:
        return _quote_string(value)
    if type(value) is int:
        return str(value)
    if type(value) is list:
        return "[" + ",".join(_serialize_restricted_jcs(item) for item in value) + "]"
    if type(value) is dict:
        keys = list(value)
        if any(type(key) is not str for key in keys):
            _reject()
        entries = [
            f"{_quote_string(key)}:{_serialize_restricted_jcs(value[key])}"
            for key in sorted(keys, key=_utf16_sort_key)
        ]
        return "{" + ",".join(entries) + "}"
    _reject()


def _has_exact_model_fields(value: object, expected: frozenset[str]) -> bool:
    try:
        fields = object.__getattribute__(value, "__dict__")
        extra = object.__getattribute__(value, "__pydantic_extra__")
    except Exception:  # noqa: BLE001 - all input failures have one public result
        return False
    return (
        type(fields) is dict
        and set(fields) == expected
        and all(type(field) is str for field in fields)
        and (extra is None or (type(extra) is dict and not extra))
    )


def _has_exact_dict_fields(value: object, expected: frozenset[str]) -> bool:
    return (
        type(value) is dict
        and len(value) == len(expected)
        and all(type(field) is str and field in expected for field in value)
    )


def _validate_namespace(namespace: object, provider: ArtifactProvider) -> str:
    scalar = _validate_scalar_string(namespace)
    if provider is ArtifactProvider.GOOGLE_DRIVE:
        if _DRIVE_NAMESPACE.fullmatch(scalar) is None:
            _reject()
        return scalar
    if provider is ArtifactProvider.S3:
        matched = _S3_NAMESPACE.fullmatch(scalar)
        if matched is None:
            _reject()
        region = scalar.split("/", 5)[4]
        if len(region) > 32:
            _reject()
        return scalar
    _reject()


def _snapshot_artifact(artifact: object) -> dict[str, object]:
    if type(artifact) is not ArtifactRef or not _has_exact_model_fields(artifact, _ARTIFACT_FIELDS):
        _reject()
    provider = artifact.provider
    role = artifact.role
    file_id = _validate_scalar_string(artifact.file_id)
    revision = _validate_scalar_string(artifact.revision)
    digest = _validate_scalar_string(artifact.sha256)
    mime_type = _validate_scalar_string(artifact.mime_type)
    if (
        type(provider) is not ArtifactProvider
        or provider not in (ArtifactProvider.S3, ArtifactProvider.GOOGLE_DRIVE)
        or type(role) is not ArtifactRole
        or role not in _ROLE_MIME
        or mime_type != _ROLE_MIME[role]
        or not 1 <= len(file_id) <= 1024
        or not 1 <= len(revision) <= 255
        or len(revision.encode("utf-8")) > 1024
        or _LOWER_SHA256.fullmatch(digest) is None
        or type(artifact.size_bytes) is not int
        or not 1 <= artifact.size_bytes <= 536_870_912
    ):
        _reject()
    return {
        "provider": provider.value,
        "file_id": file_id,
        "revision": revision,
        "sha256": digest,
        "size_bytes": artifact.size_bytes,
        "mime_type": mime_type,
        "role": role.value,
    }


def _snapshot_binding(binding: object) -> dict[str, object]:
    if type(binding) is not ProcessingJobV2ResultOutputBinding:
        _reject()
    try:
        namespace = object.__getattribute__(binding, "store_namespace")
        artifact = object.__getattribute__(binding, "artifact_ref")
    except Exception:  # noqa: BLE001 - fixed public rejection
        _reject()
    artifact_object = _snapshot_artifact(artifact)
    provider = ArtifactProvider(artifact_object["provider"])
    return {
        "store_namespace": _validate_namespace(namespace, provider),
        "artifact_ref": artifact_object,
    }


def _snapshot_outputs(bindings: object) -> list[dict[str, object]]:
    if type(bindings) not in (list, tuple) or not 1 <= len(bindings) <= 1024:
        _reject()
    outputs: list[dict[str, object]] = []
    locators: set[tuple[str, str, str, str]] = set()
    for binding in bindings:
        output = _snapshot_binding(binding)
        artifact = output["artifact_ref"]
        if type(artifact) is not dict:
            _reject()
        locator = (
            artifact["provider"],
            output["store_namespace"],
            artifact["file_id"],
            artifact["revision"],
        )
        if locator in locators:
            _reject()
        locators.add(locator)
        outputs.append(output)
    return outputs


def _bound_job_identity(job: object) -> tuple[ProcessingJobV2, str]:
    if type(job) is not ProcessingJobV2 or not _has_exact_model_fields(job, _JOB_FIELDS):
        _reject()
    admitted = admit_package_input(job)
    payload_digest = processing_job_v2_payload_digest(admitted)
    return admitted, payload_digest


def _build_manifest(job: object, bindings: object) -> dict[str, object]:
    admitted, payload_digest = _bound_job_identity(job)
    return {
        "schema_version": "1.0",
        "job_id": str(admitted.job_id),
        "session_id": str(admitted.session_id),
        "payload_digest_scheme": PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID,
        "payload_digest": payload_digest,
        "outputs": _snapshot_outputs(bindings),
    }


def _snapshot_manifest(job: object, manifest: object) -> dict[str, object]:
    admitted, expected_payload_digest = _bound_job_identity(job)
    if not _has_exact_dict_fields(manifest, _MANIFEST_FIELDS):
        _reject()
    if (
        type(manifest["schema_version"]) is not str
        or manifest["schema_version"] != "1.0"
        or type(manifest["job_id"]) is not str
        or manifest["job_id"] != str(admitted.job_id)
        or type(manifest["session_id"]) is not str
        or manifest["session_id"] != str(admitted.session_id)
        or type(manifest["payload_digest_scheme"]) is not str
        or manifest["payload_digest_scheme"] != PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID
        or type(manifest["payload_digest"]) is not str
        or manifest["payload_digest"] != expected_payload_digest
    ):
        _reject()
    raw_outputs = manifest["outputs"]
    if type(raw_outputs) is not list or not 1 <= len(raw_outputs) <= 1024:
        _reject()
    bindings: list[ProcessingJobV2ResultOutputBinding] = []
    for raw_output in raw_outputs:
        if not _has_exact_dict_fields(raw_output, _OUTPUT_FIELDS):
            _reject()
        raw_artifact = raw_output["artifact_ref"]
        if not _has_exact_dict_fields(raw_artifact, _ARTIFACT_FIELDS):
            _reject()
        try:
            artifact = ArtifactRef.model_validate(raw_artifact)
        except Exception:  # noqa: BLE001 - fixed public rejection below
            _reject()
        bindings.append(
            ProcessingJobV2ResultOutputBinding(
                store_namespace=raw_output["store_namespace"], artifact_ref=artifact
            )
        )
    return {
        "schema_version": "1.0",
        "job_id": str(admitted.job_id),
        "session_id": str(admitted.session_id),
        "payload_digest_scheme": PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID,
        "payload_digest": expected_payload_digest,
        "outputs": _snapshot_outputs(bindings),
    }


def _canonical_preimage(manifest: dict[str, object]) -> bytes:
    canonical_json = _serialize_restricted_jcs(manifest).encode("utf-8")
    preimage = PROCESSING_JOB_V2_RESULT_DIGEST_DOMAIN_PREFIX + canonical_json
    if len(preimage) > PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES:
        _reject()
    return preimage


def build_processing_job_v2_result_manifest(
    job: ProcessingJobV2,
    outputs: list[ProcessingJobV2ResultOutputBinding]
    | tuple[ProcessingJobV2ResultOutputBinding, ...],
) -> dict[str, object]:
    """Build a defensive exact manifest bound to an independently admitted job."""

    result: dict[str, object] | None = None
    try:
        result = _build_manifest(job, outputs)
    except Exception:  # noqa: BLE001,S110 - replace every failure detail below
        pass
    if result is None:
        _reject()
    return result


def canonical_processing_job_v2_result_preimage(
    job: ProcessingJobV2,
    outputs: list[ProcessingJobV2ResultOutputBinding]
    | tuple[ProcessingJobV2ResultOutputBinding, ...],
) -> bytes:
    """Return the bounded, domain-separated JCS preimage for output bindings."""

    preimage: bytes | None = None
    try:
        preimage = _canonical_preimage(_build_manifest(job, outputs))
    except Exception:  # noqa: BLE001,S110 - replace every failure detail below
        pass
    if preimage is None:
        _reject()
    return preimage


def verify_processing_job_v2_result_manifest_preimage(
    job: ProcessingJobV2, manifest: dict[str, object]
) -> bytes:
    """Verify all job-bound identity values, then return the canonical preimage."""

    preimage: bytes | None = None
    try:
        preimage = _canonical_preimage(_snapshot_manifest(job, manifest))
    except Exception:  # noqa: BLE001,S110 - replace every failure detail below
        pass
    if preimage is None:
        _reject()
    return preimage


def processing_job_v2_result_digest(
    job: ProcessingJobV2,
    outputs: list[ProcessingJobV2ResultOutputBinding]
    | tuple[ProcessingJobV2ResultOutputBinding, ...],
) -> str:
    """Return the lowercase SHA-256 digest for admitted result bindings."""

    digest: str | None = None
    try:
        digest = sha256(canonical_processing_job_v2_result_preimage(job, outputs)).hexdigest()
    except Exception:  # noqa: BLE001,S110 - replace every failure detail below
        pass
    if digest is None:
        _reject()
    return digest
