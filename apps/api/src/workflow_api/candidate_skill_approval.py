"""Authoritative, digest-bound approval projection for candidate skills."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from .candidate_skill_semantics import validate_candidate_skill_internal_coherence
from .control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlRole,
)
from .control_service import ControlService
from .control_store import (
    _UNSET,
    ControlConflictError,
    ReviewEvent,
    ReviewProjection,
    SQLiteControlStore,
)

_SCHEMA_VERSION = "1.0"
_APPROVAL_KIND = "candidate_skill_approval"
_APPROVAL_ENVELOPE = frozenset({"approval_status", "human_approval_evidence"})
_REVIEWER_ID_PATTERN = re.compile(r"^reviewer_[a-z0-9][a-z0-9_-]{2,63}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
    re.IGNORECASE,
)
_MAX_DEPTH = 12
_MAX_CONTAINER_ITEMS = 512
_MAX_TOTAL_VALUES = 4096
_MAX_STRING_CHARACTERS = 16_384
_MAX_KEY_CHARACTERS = 256
_MAX_CANONICAL_BYTES = 256 * 1024
_MAX_INTEGER_MAGNITUDE = 10**100
_LOCK_TIMEOUT_SECONDS = 10.0
_PROVENANCE_VALUES = frozenset(
    {"observed", "deterministic", "ai_inferred", "human_supplied"}
)


@dataclass(frozen=True, slots=True)
class CandidateSkillApprovalState:
    """Caller-visible effective state with no qualified control-plane keys."""

    schema_version: str
    skill_id: str
    content_sha256: str
    target_id: str
    approval_status: str
    human_approval_evidence: dict[str, str] | None


@dataclass(frozen=True, slots=True)
class _CandidateIdentity:
    schema_version: str
    skill_id: str
    content_sha256: str
    full_sha256: str
    source_result_sha256: str
    publication_key: str
    target_id: str
    idempotency_key: str
    provenance: dict[str, str]
    detail: dict[str, str]


def candidate_skill_approval_idempotency_key(candidate: Mapping[str, Any]) -> str:
    """Return the only valid approval idempotency key for this schema and skill."""

    return _candidate_identity(candidate).idempotency_key


def canonical_candidate_skill_sha256(candidate: Mapping[str, Any]) -> str:
    """Hash bounded canonical candidate content without producer approval claims."""

    return _candidate_identity(candidate).content_sha256


def approve_candidate_skill(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    *,
    candidate: Mapping[str, Any],
    idempotency_key: str,
    correlation_id: str,
) -> CandidateSkillApprovalState:
    """Append one authenticated approval for the exact canonical candidate content."""

    identity = _candidate_identity(candidate)
    _require_request_text(correlation_id, "correlation_id")
    _require_exact_idempotency_key(idempotency_key, identity.idempotency_key)

    # The OS lock coordinates independent service/store instances for this exact SQLite
    # file.  The store remains the only authority; the lock only serializes this domain's
    # mutation-free replay check with its append.
    with _sqlite_approval_lock(service):
        current = service.read_review(
            principal,
            target_id=identity.target_id,
            correlation_id=correlation_id,
        )
        if current is not None:
            if current.actor_id != principal.subject:
                raise ControlConflictError(
                    "candidate approval idempotency key belongs to another reviewer"
                )
            return _state_from_projection(
                service,
                principal,
                identity,
                current,
                correlation_id,
            )

        if (
            ControlRole.REVIEWER not in principal.roles
            or not _REVIEWER_ID_PATTERN.fullmatch(principal.subject)
        ):
            raise AuthorizationDeniedError("reviewer identity is not contract-compatible")

        transition_candidate_skill_review(
            service,
            principal,
            candidate=candidate,
            status="approved",
            idempotency_key=identity.idempotency_key,
            correlation_id=correlation_id,
            legacy=True,
        )
        projection = service.read_review(
            principal,
            target_id=identity.target_id,
            correlation_id=correlation_id,
        )
        if projection is None:  # pragma: no cover - transactional store invariant
            raise ControlConflictError("candidate approval projection is missing")
        return _state_from_projection(
            service,
            principal,
            identity,
            projection,
            correlation_id,
        )


def read_candidate_skill_approval_state(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    *,
    candidate: Mapping[str, Any],
    correlation_id: str,
) -> CandidateSkillApprovalState:
    """Project effective approval solely from authenticated stored review authority."""

    identity = _candidate_identity(candidate)
    _require_request_text(correlation_id, "correlation_id")
    projection = service.read_review(
        principal,
        target_id=identity.target_id,
        correlation_id=correlation_id,
    )
    if projection is None:
        return _unreviewed_state(identity)
    return _state_from_projection(
        service,
        principal,
        identity,
        projection,
        correlation_id,
    )


def transition_candidate_skill_review(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    *,
    candidate: Mapping[str, Any],
    status: str,
    idempotency_key: str,
    correlation_id: str,
    publication: Any | None = None,
    publication_key: str | None = None,
    review_target_id: str | None = None,
    content_sha256: str | None = None,
    full_sha256: str | None = None,
    source_result_sha256: str | None = None,
    reason: str | None | object = _UNSET,
    evidence: Any = _UNSET,
    expected_prior_state: object = _UNSET,
    expected_prior_version: object = _UNSET,
    expected_prior_event_id: object = _UNSET,
    occurred_at: datetime | None = None,
    now: datetime | None = None,
    legacy: bool = False,
) -> ReviewEvent:
    """Guarded candidate-skill lifecycle operation shared by all decisions.

    The older approval helper calls this operation with ``legacy=True`` only
    to preserve its established event JSON.  New publication callers use the
    fully bound Decision-138 payload produced by the ControlService writer.
    """

    identity = _candidate_identity(candidate)
    _require_request_text(correlation_id, "correlation_id")
    selected_publication = _publication_field(publication, "publication_key")
    selected_target = _publication_field(publication, "review_target_id")
    selected_content = _publication_field(publication, "content_sha256")
    selected_full = _publication_field(publication, "full_sha256")
    selected_source = _publication_field(publication, "source_result_sha256")
    publication_key = _coalesce(
        publication_key, selected_publication, identity.publication_key, "publication_key"
    )
    review_target_id = _coalesce(
        review_target_id, selected_target, identity.target_id, "review_target_id"
    )
    content_sha256 = _coalesce(
        content_sha256, selected_content, identity.content_sha256, "content_sha256"
    )
    full_sha256 = _coalesce(full_sha256, selected_full, identity.full_sha256, "full_sha256")
    source_result_sha256 = _coalesce(
        source_result_sha256,
        selected_source,
        identity.source_result_sha256,
        "source_result_sha256",
    )
    if review_target_id != identity.target_id:
        raise ControlConflictError("candidate review target does not match canonical candidate")
    if legacy:
        if status != "approved":
            raise ValueError("legacy candidate approval only supports approved")
        legacy_provenance = identity.provenance
        legacy_detail = identity.detail
    else:
        legacy_provenance = None
        legacy_detail = None
    return service.append_candidate_review(
        principal,
        publication_key=publication_key,
        review_target_id=review_target_id,
        idempotency_key=idempotency_key,
        status=status,
        correlation_id=correlation_id,
        content_sha256=content_sha256,
        full_sha256=full_sha256,
        source_result_sha256=source_result_sha256,
        skill_id=identity.skill_id,
        reason=reason,
        evidence=evidence,
        expected_prior_state=expected_prior_state,
        expected_prior_version=expected_prior_version,
        expected_prior_event_id=expected_prior_event_id,
        occurred_at=occurred_at,
        now=now,
        legacy_provenance=legacy_provenance,
        legacy_detail=legacy_detail,
    )


review_candidate_skill = transition_candidate_skill_review
append_candidate_skill_review = transition_candidate_skill_review


@contextmanager
def _sqlite_approval_lock(service: ControlService) -> Iterator[None]:
    """Bound the replay-check/append race with an advisory lock on the exact DB file."""

    if type(service) is not ControlService:
        raise TypeError("service must use the exact ControlService type")
    store = getattr(service, "_store", None)
    if type(store) is not SQLiteControlStore:
        raise ControlConflictError("candidate approval requires SQLiteControlStore")
    database_path = getattr(store, "_database_path", None)
    if type(database_path) is not str:
        raise ControlConflictError("SQLite store identity is unavailable")
    try:
        path = Path(database_path).resolve(strict=True)
        before = path.stat()
        identity = hashlib.sha256(f"{before.st_dev}\0{before.st_ino}".encode()).hexdigest()
        lock_path = Path(tempfile.gettempdir()) / (
            f"workflow-helper-candidate-skill-{identity}.lock"
        )
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
    except (OSError, RuntimeError) as exc:
        raise ControlConflictError("SQLite approval coordination is unavailable") from exc

    locked = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ControlConflictError("SQLite approval lock is not a regular file")
        if opened.st_size < 1:
            os.write(descriptor, b"\0")
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while not _try_os_file_lock(descriptor):
            if time.monotonic() >= deadline:
                raise ControlConflictError("candidate approval coordination timed out")
            time.sleep(0.01)
        locked = True
        after = path.stat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ControlConflictError("SQLite store identity changed during coordination")
        yield
    finally:
        if locked:
            _unlock_os_file(descriptor)
        os.close(descriptor)


def _try_os_file_lock(descriptor: int) -> bool:
    if os.name == "nt":  # pragma: no cover - exercised by supported Windows runtime
        import msvcrt

        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock_os_file(descriptor: int) -> None:
    if os.name == "nt":  # pragma: no cover - exercised by supported Windows runtime
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _candidate_identity(candidate: Mapping[str, Any]) -> _CandidateIdentity:
    normalized = _bounded_json_mapping(candidate)
    if len(_canonical_json_bytes(normalized)) > _MAX_CANONICAL_BYTES:
        raise ValueError("candidate JSON exceeds the byte limit")
    _validate_candidate_skill_contract(normalized)
    validate_candidate_skill_internal_coherence(normalized)
    schema_version = normalized.get("schema_version")
    if schema_version != _SCHEMA_VERSION:
        raise ValueError('schema_version must be exactly "1.0"')
    skill_id = _canonical_uuid(normalized.get("skill_id"))
    content = {
        key: value for key, value in normalized.items() if key not in _APPROVAL_ENVELOPE
    }
    canonical = _canonical_json_bytes(content)
    if len(canonical) > _MAX_CANONICAL_BYTES:
        raise ValueError("canonical candidate content exceeds the byte limit")
    digest = hashlib.sha256(canonical).hexdigest()
    full_digest = hashlib.sha256(_canonical_json_bytes(normalized)).hexdigest()
    target_id = f"candidate-skill:{schema_version}:{skill_id}:sha256:{digest}"
    idempotency_key = f"candidate-skill-approval:{schema_version}:{skill_id}"
    publication_key = f"candidate-publication:{schema_version}:{skill_id}"
    basis = (
        "Authenticated scoped review accepted canonical candidate content for "
        f"schema {schema_version}, skill {skill_id}, and SHA-256 {digest}."
    )
    return _CandidateIdentity(
        schema_version=schema_version,
        skill_id=skill_id,
        content_sha256=digest,
        full_sha256=full_digest,
        source_result_sha256=digest,
        publication_key=publication_key,
        target_id=target_id,
        idempotency_key=idempotency_key,
        provenance={
            "source": "candidate_skill_canonical_sha256",
            "artifact_id": skill_id,
            "revision": schema_version,
            "sha256": digest,
        },
        detail={
            "kind": _APPROVAL_KIND,
            "decision": "approve",
            "schema_version": schema_version,
            "skill_id": skill_id,
            "content_sha256": digest,
            "approval_basis": basis,
        },
    )


def _state_from_projection(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    identity: _CandidateIdentity,
    projection: ReviewProjection,
    correlation_id: str,
) -> CandidateSkillApprovalState:
    events = service.list_reviews(
        principal,
        target_id=identity.target_id,
        correlation_id=correlation_id,
        after_sequence=0,
        limit=100,
    )
    if not events or len(events) != projection.version:
        raise ControlConflictError("candidate approval authority is ambiguous")
    event = events[-1]
    if "lifecycle_schema_version" in event.detail:
        if (
            event.target_id != identity.target_id
            or event.status != projection.status
            or event.event_id != projection.last_event_id
            or event.actor_id != projection.actor_id
            or event.provenance != projection.provenance
            or event.detail != projection.detail
            or event.occurred_at != projection.occurred_at
            or event.status not in {"pending", "approved", "rejected", "needs_changes"}
        ):
            raise ControlConflictError("candidate review authority does not match projection")
        return CandidateSkillApprovalState(
            schema_version=identity.schema_version,
            skill_id=identity.skill_id,
            content_sha256=identity.content_sha256,
            target_id=identity.target_id,
            approval_status=event.status,
            human_approval_evidence=None,
        )
    if len(events) != 1:
        raise ControlConflictError("candidate approval authority is ambiguous")
    _require_authoritative_event(identity, projection, event)
    evidence = {
        "reviewer_id": event.actor_id,
        "decision_event_id": event.event_id,
        "decided_at": event.occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "approval_basis": event.detail["approval_basis"],
    }
    return CandidateSkillApprovalState(
        schema_version=identity.schema_version,
        skill_id=identity.skill_id,
        content_sha256=identity.content_sha256,
        target_id=identity.target_id,
        approval_status="approved",
        human_approval_evidence=evidence,
    )


def _require_authoritative_event(
    identity: _CandidateIdentity,
    projection: ReviewProjection,
    event: ReviewEvent,
) -> None:
    try:
        canonical_event_id = str(UUID(event.event_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ControlConflictError("candidate approval event UUID is invalid") from exc
    if canonical_event_id != event.event_id:
        raise ControlConflictError("candidate approval event UUID is not canonical")
    if not _REVIEWER_ID_PATTERN.fullmatch(event.actor_id):
        raise ControlConflictError("candidate approval actor is not contract-compatible")
    if (
        event.sequence != 1
        or event.target_id != identity.target_id
        or event.idempotency_key != identity.idempotency_key
        or event.status != "approved"
        or event.provenance != identity.provenance
        or event.detail != identity.detail
        or projection.target_id != identity.target_id
        or projection.status != "approved"
        or projection.version != 1
        or projection.last_event_id != event.event_id
        or projection.actor_id != event.actor_id
        or projection.provenance != event.provenance
        or projection.detail != event.detail
        or projection.occurred_at != event.occurred_at
    ):
        raise ControlConflictError("candidate approval authority does not match exact content")


def _unreviewed_state(identity: _CandidateIdentity) -> CandidateSkillApprovalState:
    return CandidateSkillApprovalState(
        schema_version=identity.schema_version,
        skill_id=identity.skill_id,
        content_sha256=identity.content_sha256,
        target_id=identity.target_id,
        approval_status="unreviewed",
        human_approval_evidence=None,
    )


def _validate_candidate_skill_contract(candidate: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "skill_id",
        "name",
        "description",
        "trigger",
        "preconditions",
        "inputs",
        "relevant_drawing_state",
        "ordered_actions",
        "parameters",
        "constraints",
        "expected_result",
        "validation_checks",
        "known_exceptions",
        "supporting_examples",
        "confidence",
        "provenance",
        "approval_status",
        "human_approval_evidence",
    }
    _require_exact_object(candidate, "candidate", fields)
    if candidate["schema_version"] != _SCHEMA_VERSION:
        raise ValueError('schema_version must be exactly "1.0"')
    _canonical_uuid(candidate["skill_id"])
    _require_text_contract(candidate["name"], "name", 1, 160)
    _require_text_contract(candidate["description"], "description", 1, 2000)
    _validate_trigger(candidate["trigger"])
    _require_unique_text_array(candidate["preconditions"], "preconditions", 1, 64)
    inputs = _require_array(candidate["inputs"], "inputs", 1, 64)
    for index, value in enumerate(inputs):
        _validate_input(value, f"inputs[{index}]")
    _validate_drawing_state(candidate["relevant_drawing_state"])
    actions = _require_array(candidate["ordered_actions"], "ordered_actions", 1, 256)
    for index, value in enumerate(actions):
        _validate_action(value, f"ordered_actions[{index}]")
    parameters = _require_array(candidate["parameters"], "parameters", 0, 128)
    for index, value in enumerate(parameters):
        _validate_parameter(value, f"parameters[{index}]")
    _require_unique_text_array(candidate["constraints"], "constraints", 1, 128)
    _validate_expected_result(candidate["expected_result"])
    checks = _require_array(candidate["validation_checks"], "validation_checks", 1, 128)
    for index, value in enumerate(checks):
        _validate_validation_check(value, f"validation_checks[{index}]")
    exceptions = _require_array(candidate["known_exceptions"], "known_exceptions", 0, 128)
    for index, value in enumerate(exceptions):
        _validate_known_exception(value, f"known_exceptions[{index}]")
    examples = _require_array(candidate["supporting_examples"], "supporting_examples", 1, 128)
    for index, value in enumerate(examples):
        _validate_supporting_example(value, f"supporting_examples[{index}]")
    _require_number_range(candidate["confidence"], "confidence", 0, 1)
    _require_enum(candidate["provenance"], "provenance", _PROVENANCE_VALUES)
    status = _require_enum(
        candidate["approval_status"],
        "approval_status",
        frozenset({"unreviewed", "approved", "rejected", "needs_changes"}),
    )
    evidence = candidate["human_approval_evidence"]
    if evidence is not None:
        _validate_human_approval_evidence(evidence)
    if status == "approved" and evidence is None:
        raise ValueError("approved candidate requires human_approval_evidence")


def _validate_trigger(value: object) -> None:
    item = _require_exact_object(value, "trigger", {"condition", "signals"})
    _require_text_contract(item["condition"], "trigger.condition", 1, 2000)
    _require_unique_text_array(item["signals"], "trigger.signals", 1, 32)


def _validate_input(value: object, name: str) -> None:
    item = _require_exact_object(value, name, {"name", "kind", "description", "required"})
    _require_text_contract(item["name"], f"{name}.name", 1, 128)
    _require_enum(
        item["kind"],
        f"{name}.kind",
        frozenset(
            {"drawing_state", "artifact", "measurement", "parameter", "instruction"}
        ),
    )
    _require_text_contract(item["description"], f"{name}.description", 1, 2000)
    if type(item["required"]) is not bool:
        raise ValueError(f"{name}.required must be a boolean")


def _validate_drawing_state(value: object) -> None:
    name = "relevant_drawing_state"
    item = _require_exact_object(
        value,
        name,
        {"description", "required_conditions", "excluded_conditions"},
    )
    _require_text_contract(item["description"], f"{name}.description", 1, 2000)
    _require_unique_text_array(
        item["required_conditions"], f"{name}.required_conditions", 0, 64
    )
    _require_unique_text_array(
        item["excluded_conditions"], f"{name}.excluded_conditions", 0, 64
    )


def _validate_action(value: object, name: str) -> None:
    item = _require_exact_object(
        value, name, {"sequence", "instruction", "parameter_names"}
    )
    sequence = item["sequence"]
    if not _is_json_schema_integer(sequence) or sequence < 1 or sequence > 256:
        raise ValueError(f"{name}.sequence must be an integer from 1 through 256")
    _require_text_contract(item["instruction"], f"{name}.instruction", 1, 2000)
    _require_unique_text_array(
        item["parameter_names"],
        f"{name}.parameter_names",
        0,
        32,
        text_maximum=128,
    )


def _validate_parameter(value: object, name: str) -> None:
    item = _require_exact_object(value, name, {"name", "value", "unit", "provenance"})
    _require_text_contract(item["name"], f"{name}.name", 1, 128)
    parameter_value = item["value"]
    if type(parameter_value) not in {str, int, float, bool}:
        raise ValueError(f"{name}.value must be a JSON scalar")
    if type(parameter_value) is str and len(parameter_value) > 512:
        raise ValueError(f"{name}.value exceeds 512 characters")
    unit = item["unit"]
    if unit is not None and (type(unit) is not str or len(unit) > 64):
        raise ValueError(f"{name}.unit must be null or a string up to 64 characters")
    _require_enum(item["provenance"], f"{name}.provenance", _PROVENANCE_VALUES)


def _validate_expected_result(value: object) -> None:
    name = "expected_result"
    item = _require_exact_object(value, name, {"description", "observable_outcomes"})
    _require_text_contract(item["description"], f"{name}.description", 1, 2000)
    _require_unique_text_array(
        item["observable_outcomes"], f"{name}.observable_outcomes", 1, 64
    )


def _validate_validation_check(value: object, name: str) -> None:
    item = _require_exact_object(value, name, {"description", "success_criterion"})
    _require_text_contract(item["description"], f"{name}.description", 1, 2000)
    _require_text_contract(
        item["success_criterion"], f"{name}.success_criterion", 1, 2000
    )


def _validate_known_exception(value: object, name: str) -> None:
    item = _require_exact_object(value, name, {"condition", "handling"})
    _require_text_contract(item["condition"], f"{name}.condition", 1, 2000)
    _require_text_contract(item["handling"], f"{name}.handling", 1, 2000)


def _validate_supporting_example(value: object, name: str) -> None:
    item = _require_exact_object(
        value, name, {"session_id", "summary", "artifact_references"}
    )
    _require_uuid_format(item["session_id"], f"{name}.session_id")
    _require_text_contract(item["summary"], f"{name}.summary", 1, 2000)
    references = _require_array(
        item["artifact_references"], f"{name}.artifact_references", 1, 32
    )
    for index, reference in enumerate(references):
        _validate_artifact_reference(reference, f"{name}.artifact_references[{index}]")


def _validate_artifact_reference(value: object, name: str) -> None:
    item = _require_exact_object(
        value,
        name,
        {"provider", "file_id", "revision", "sha256", "size_bytes", "mime_type", "role"},
    )
    _require_enum(item["provider"], f"{name}.provider", frozenset({"s3", "google_drive"}))
    _require_text_contract(item["file_id"], f"{name}.file_id", 1, 1024)
    _require_text_contract(item["revision"], f"{name}.revision", 1, 255)
    digest = item["sha256"]
    if type(digest) is not str or not _SHA256_PATTERN.fullmatch(digest):
        raise ValueError(f"{name}.sha256 must be a lowercase SHA-256 digest")
    size = item["size_bytes"]
    if not _is_json_schema_integer(size) or size < 0 or size > 536_870_912:
        raise ValueError(f"{name}.size_bytes is outside the contract range")
    _require_text_contract(item["mime_type"], f"{name}.mime_type", 1, 255)
    _require_enum(
        item["role"],
        f"{name}.role",
        frozenset({"raw_package", "timeline", "crop", "manifest"}),
    )


def _validate_human_approval_evidence(value: object) -> None:
    name = "human_approval_evidence"
    item = _require_exact_object(
        value,
        name,
        {"reviewer_id", "decision_event_id", "decided_at", "approval_basis"},
    )
    reviewer_id = item["reviewer_id"]
    if type(reviewer_id) is not str or not _REVIEWER_ID_PATTERN.fullmatch(reviewer_id):
        raise ValueError(f"{name}.reviewer_id does not match the contract")
    _require_uuid_format(item["decision_event_id"], f"{name}.decision_event_id")
    _require_datetime_text(item["decided_at"], f"{name}.decided_at")
    _require_text_contract(item["approval_basis"], f"{name}.approval_basis", 1, 2000)


def _require_exact_object(
    value: object,
    name: str,
    fields: set[str],
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{name} must be an object")
    actual = set(value)
    missing = fields - actual
    additional = actual - fields
    if missing:
        raise ValueError(f"{name} is missing required field {min(missing)}")
    if additional:
        raise ValueError(f"{name} has additional field {min(additional)}")
    return value


def _require_array(value: object, name: str, minimum: int, maximum: int) -> list[Any]:
    if type(value) is not list:
        raise ValueError(f"{name} must be an array")
    if len(value) < minimum or len(value) > maximum:
        raise ValueError(f"{name} item count is outside the contract range")
    return value


def _require_unique_text_array(
    value: object,
    name: str,
    minimum: int,
    maximum: int,
    *,
    text_maximum: int = 2000,
) -> None:
    items = _require_array(value, name, minimum, maximum)
    for index, item in enumerate(items):
        _require_text_contract(item, f"{name}[{index}]", 1, text_maximum)
    if len(set(items)) != len(items):
        raise ValueError(f"{name} items must be unique")


def _require_text_contract(value: object, name: str, minimum: int, maximum: int) -> str:
    if type(value) is not str or len(value) < minimum or len(value) > maximum:
        raise ValueError(f"{name} length is outside the contract range")
    return value


def _require_enum(value: object, name: str, allowed: frozenset[str]) -> str:
    if type(value) is not str or value not in allowed:
        raise ValueError(f"{name} is not an allowed contract value")
    return value


def _require_number_range(value: object, name: str, minimum: float, maximum: float) -> None:
    if type(value) not in {int, float} or not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the contract range")


def _is_json_schema_integer(value: object) -> bool:
    return type(value) is int or (
        type(value) is float and math.isfinite(value) and value.is_integer()
    )


def _require_datetime_text(value: object, name: str) -> None:
    if type(value) is not str or not _RFC3339_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be an RFC 3339 date-time")
    try:
        normalized = value[:10] + "T" + value[11:]
        if normalized[-1].lower() == "z":
            normalized = normalized[:-1] + "Z"
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be an RFC 3339 date-time") from exc
    if parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


def _require_uuid_format(value: object, name: str) -> None:
    if type(value) is not str or len(value) != 36:
        raise ValueError(f"{name} must use UUID format")
    if any(value[position] != "-" for position in (8, 13, 18, 23)):
        raise ValueError(f"{name} must use UUID format")
    try:
        UUID(value)
    except ValueError as exc:
        raise ValueError(f"{name} must use UUID format") from exc


def _bounded_json_mapping(candidate: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(candidate, Mapping):
        raise TypeError("candidate must be a mapping")
    count = [0]
    normalized = _bounded_json_value(candidate, depth=0, count=count, ancestors=set())
    assert isinstance(normalized, dict)
    return normalized


def _bounded_json_value(
    value: object,
    *,
    depth: int,
    count: list[int],
    ancestors: set[int],
) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("candidate JSON exceeds the depth limit")
    count[0] += 1
    if count[0] > _MAX_TOTAL_VALUES:
        raise ValueError("candidate JSON exceeds the total value limit")

    value_type = type(value)
    if value is None or value_type is bool:
        return value
    if value_type is str:
        _require_bounded_string(value, "candidate string", _MAX_STRING_CHARACTERS)
        return value
    if value_type is int:
        if abs(value) > _MAX_INTEGER_MAGNITUDE:
            raise ValueError("candidate integer exceeds the magnitude limit")
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("candidate numbers must be finite")
        return value

    if isinstance(value, Mapping):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise ValueError("candidate object exceeds the item limit")
        marker = id(value)
        if marker in ancestors:
            raise ValueError("candidate JSON must not contain cycles")
        ancestors.add(marker)
        try:
            normalized: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise TypeError("candidate object keys must be strings")
                _require_bounded_string(key, "candidate key", _MAX_KEY_CHARACTERS)
                normalized[key] = _bounded_json_value(
                    item,
                    depth=depth + 1,
                    count=count,
                    ancestors=ancestors,
                )
            return normalized
        finally:
            ancestors.remove(marker)

    if value_type is list:
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise ValueError("candidate array exceeds the item limit")
        marker = id(value)
        if marker in ancestors:
            raise ValueError("candidate JSON must not contain cycles")
        ancestors.add(marker)
        try:
            return [
                _bounded_json_value(
                    item,
                    depth=depth + 1,
                    count=count,
                    ancestors=ancestors,
                )
                for item in value
            ]
        finally:
            ancestors.remove(marker)

    raise TypeError("candidate contains a non-JSON value")


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        text = json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("candidate must have canonical UTF-8 JSON content") from exc


def _canonical_uuid(value: object) -> str:
    if type(value) is not str:
        raise ValueError("skill_id must be a canonical UUID string")
    try:
        canonical = str(UUID(value))
    except (ValueError, AttributeError) as exc:
        raise ValueError("skill_id must be a canonical UUID string") from exc
    if canonical != value:
        raise ValueError("skill_id must be a canonical UUID string")
    return canonical


def _require_exact_idempotency_key(actual: object, expected: str) -> None:
    if actual != expected:
        raise ControlConflictError(
            "idempotency_key must be the deterministic schema-and-skill approval key"
        )


def _require_request_text(value: object, name: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > 128:
        raise ValueError(f"{name} must be a non-empty bounded string")


def _require_bounded_string(value: str, name: str, maximum: int) -> None:
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds the character limit")


def _publication_field(publication: Any, name: str) -> Any:
    if publication is None:
        return None
    if isinstance(publication, Mapping):
        return publication.get(name)
    return getattr(publication, name, None)


def _coalesce(value: Any, supplied: Any, fallback: Any, name: str) -> Any:
    if value is not None and supplied is not None and value != supplied:
        raise ControlConflictError(f"candidate {name} conflicts with publication")
    if value is not None:
        return value
    if supplied is not None:
        return supplied
    return fallback
