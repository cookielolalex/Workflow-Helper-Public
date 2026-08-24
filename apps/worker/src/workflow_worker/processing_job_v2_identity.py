"""Active pure payload identity for admitted ProcessingJobV2 snapshots.

The default v2 worker path uses this helper for replay-stable processing and
candidate evidence without provider discovery.
"""

from __future__ import annotations

from hashlib import sha256

from workflow_worker.models import ProcessingJobV2
from workflow_worker.package_input_admission import admit_package_input

PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID = (
    "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
)
PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX = (
    b"workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0"
)

_DIGEST_REJECTED = "payload digest rejected"
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
    """Serialize only the scalar/object subset used by the fixed digest schema."""

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
            entries.append(
                f"{_quote_string(key)}:{_serialize_restricted_jcs(value[key])}"
            )
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
    """Return the domain-separated RFC 8785 preimage for an admissible v2 job."""

    preimage: bytes | None = None
    try:
        snapshot = admit_package_input(job)
        semantic_object = _normalized_semantic_object(snapshot)
        canonical_json = _serialize_restricted_jcs(semantic_object).encode("utf-8")
        preimage = PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX + canonical_json
    except Exception:  # noqa: BLE001,S110 - replace all details below
        pass
    if preimage is None:
        _reject()
    return preimage


def processing_job_v2_payload_digest(job: ProcessingJobV2) -> str:
    """Return the lowercase SHA-256 digest for an admissible v2 payload."""

    preimage = canonical_processing_job_v2_payload_preimage(job)
    digest: str | None = None
    try:
        digest = sha256(preimage).hexdigest()
    except Exception:  # noqa: BLE001,S110 - replace all details below
        pass
    if digest is None:
        _reject()
    return digest
