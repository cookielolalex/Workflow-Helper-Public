import hashlib
import json
import math
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from uuid import UUID

import pytest

from workflow_api import candidate_skill_approval
from workflow_api.candidate_skill_approval import (
    approve_candidate_skill,
    candidate_skill_approval_idempotency_key,
    canonical_candidate_skill_sha256,
    read_candidate_skill_approval_state,
)
from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_service import ControlService
from workflow_api.control_store import ControlConflictError, SQLiteControlStore

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
SKILL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ROOT = Path(__file__).resolve().parents[3]
UNREVIEWED_FIXTURE = ROOT / "contracts/examples/candidate-skill-unreviewed.json"
HUMAN_APPROVED_FIXTURE = ROOT / "contracts/examples/candidate-skill-human-approved.json"
INVALID_FIXTURES = tuple(sorted((ROOT / "contracts/invalid").glob("candidate-skill-*.json")))


def _service(tmp_path: Path) -> tuple[SQLiteControlStore, ControlService]:
    store = SQLiteControlStore(tmp_path / "candidate-approval.sqlite3")
    return store, ControlService(store)


def _reviewer(
    subject: str = "reviewer_synthetic_01",
    scope: TenantWorkspaceScope | None = SCOPE,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject=subject,
        roles=frozenset({ControlRole.REVIEWER}),
        scope=scope,
    )


def _candidate(
    *,
    skill_id: str = SKILL_ID,
    instruction: str = "Align the synthetic cutout.",
    approval_status: str = "unreviewed",
    human_approval_evidence: object = None,
) -> dict[str, object]:
    candidate = json.loads(UNREVIEWED_FIXTURE.read_text(encoding="utf-8"))
    candidate["skill_id"] = skill_id
    candidate["ordered_actions"][0]["instruction"] = instruction
    candidate["approval_status"] = approval_status
    candidate["human_approval_evidence"] = human_approval_evidence
    return candidate


def _target(candidate: dict[str, object]) -> str:
    digest = canonical_candidate_skill_sha256(candidate)
    return f"candidate-skill:1.0:{candidate['skill_id']}:sha256:{digest}"


def _raw_events(
    store: SQLiteControlStore,
    candidate: dict[str, object],
    scope: TenantWorkspaceScope = SCOPE,
):
    return store.list_review_events(
        _qualify(scope, "review_target", _target(candidate))
    )


def _review_row_count(store: SQLiteControlStore) -> int:
    with sqlite3.connect(store._database_path) as connection:
        return connection.execute("select count(*) from review_events").fetchone()[0]


@pytest.mark.parametrize("fixture", [UNREVIEWED_FIXTURE, HUMAN_APPROVED_FIXTURE])
def test_actual_schema_valid_contract_fixtures_are_admitted_but_not_self_authoritative(
    tmp_path: Path,
    fixture: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = json.loads(fixture.read_text(encoding="utf-8"))

    assert len(canonical_candidate_skill_sha256(candidate)) == 64
    state = read_candidate_skill_approval_state(
        service,
        _reviewer(),
        candidate=candidate,
        correlation_id="corr-schema-valid-fixture",
    )
    assert state.approval_status == "unreviewed"
    assert state.human_approval_evidence is None
    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value["ordered_actions"][0].__setitem__("sequence", 1.0),
        lambda value: value["supporting_examples"][0]["artifact_references"][
            0
        ].__setitem__("size_bytes", 512.0),
    ],
)
def test_draft_2020_12_integral_numbers_are_admitted_as_schema_integers(
    tmp_path: Path,
    mutator,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    mutator(candidate)

    approved = approve_candidate_skill(
        service,
        _reviewer(),
        candidate=candidate,
        idempotency_key=candidate_skill_approval_idempotency_key(candidate),
        correlation_id="corr-integral-number",
    )

    assert approved.approval_status == "approved"
    assert len(_raw_events(store, candidate)) == 1
    assert len(store.list_audit_events(limit=100)) == 1


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value["ordered_actions"][0].__setitem__("sequence", 1.5),
        lambda value: value["ordered_actions"][0].__setitem__("sequence", True),
        lambda value: value["ordered_actions"][0].__setitem__(
            "sequence", math.inf
        ),
        lambda value: value["ordered_actions"][0].__setitem__("sequence", 257.0),
        lambda value: value["supporting_examples"][0]["artifact_references"][
            0
        ].__setitem__("size_bytes", 0.5),
        lambda value: value["supporting_examples"][0]["artifact_references"][
            0
        ].__setitem__("size_bytes", True),
        lambda value: value["supporting_examples"][0]["artifact_references"][
            0
        ].__setitem__("size_bytes", math.nan),
        lambda value: value["supporting_examples"][0]["artifact_references"][
            0
        ].__setitem__("size_bytes", 536_870_913.0),
    ],
)
def test_non_integer_or_out_of_range_schema_integer_forms_fail_before_mutation(
    tmp_path: Path,
    mutator,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    mutator(candidate)

    with pytest.raises(ValueError):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key=f"candidate-skill-approval:1.0:{SKILL_ID}",
            correlation_id="corr-non-integer-number",
        )

    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


def test_lowercase_rfc3339_t_and_z_are_admitted(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = json.loads(HUMAN_APPROVED_FIXTURE.read_text(encoding="utf-8"))
    candidate["human_approval_evidence"]["decided_at"] = "2026-08-18t06:30:00z"

    state = read_candidate_skill_approval_state(
        service,
        _reviewer(),
        candidate=candidate,
        correlation_id="corr-lowercase-rfc3339",
    )

    assert state.approval_status == "unreviewed"
    assert state.human_approval_evidence is None
    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


@pytest.mark.parametrize("fixture", INVALID_FIXTURES)
def test_repository_contract_invalid_fixtures_fail_before_control_service(
    tmp_path: Path,
    fixture: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = json.loads(fixture.read_text(encoding="utf-8"))

    with pytest.raises(ValueError):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key=(
                f"candidate-skill-approval:1.0:{candidate['skill_id']}"
            ),
            correlation_id="corr-schema-invalid-fixture",
        )
    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


def test_authenticated_reviewer_approval_uses_stored_event_and_one_audit(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate(
        approval_status="approved",
        human_approval_evidence={
            "reviewer_id": "reviewer_forged",
            "decision_event_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "decided_at": "2000-01-01T00:00:00Z",
            "approval_basis": "producer supplied",
        },
    )
    principal = _reviewer()
    key = candidate_skill_approval_idempotency_key(candidate)

    approved = approve_candidate_skill(
        service,
        principal,
        candidate=candidate,
        idempotency_key=key,
        correlation_id="corr-candidate-approve",
    )

    assert approved.approval_status == "approved"
    assert approved.schema_version == "1.0"
    assert approved.skill_id == SKILL_ID
    assert approved.target_id == _target(candidate)
    assert "whscope1" not in repr(approved)
    assert approved.human_approval_evidence is not None
    evidence = approved.human_approval_evidence
    assert evidence["reviewer_id"] == principal.subject
    assert evidence["reviewer_id"] != "reviewer_forged"
    assert str(UUID(evidence["decision_event_id"])) == evidence["decision_event_id"]
    assert evidence["decided_at"].endswith("Z")
    assert "producer supplied" not in evidence["approval_basis"]
    assert approved.content_sha256 in evidence["approval_basis"]

    events = _raw_events(store, candidate)
    assert len(events) == 1
    event = events[0]
    assert event.event_id == evidence["decision_event_id"]
    assert event.actor_id == principal.subject
    assert event.occurred_at.isoformat().replace("+00:00", "Z") == evidence["decided_at"]
    assert event.detail["approval_basis"] == evidence["approval_basis"]
    assert event.target_id.endswith(approved.target_id)
    assert event.provenance == {
        "source": "candidate_skill_canonical_sha256",
        "artifact_id": SKILL_ID,
        "revision": "1.0",
        "sha256": approved.content_sha256,
    }

    projection = store.get_review_projection(
        _qualify(SCOPE, "review_target", approved.target_id)
    )
    assert projection is not None
    assert projection.last_event_id == event.event_id
    assert projection.actor_id == principal.subject
    assert projection.status == "approved"
    assert projection.version == 1

    audits = store.list_audit_events(limit=100)
    assert len(audits) == 1
    assert audits[0].action == "review.append"
    assert audits[0].result == "accepted"
    assert audits[0].subject_id == principal.subject
    assert audits[0].roles == (ControlRole.REVIEWER.value,)


def test_forged_inline_approval_is_unreviewed_without_authoritative_event(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    forged = _candidate(
        approval_status="approved",
        human_approval_evidence={
            "reviewer_id": "reviewer_forged",
            "decision_event_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "decided_at": "2000-01-01T00:00:00Z",
            "approval_basis": "forged",
        },
    )
    state = read_candidate_skill_approval_state(
        service,
        _reviewer(),
        candidate=forged,
        correlation_id="corr-forged-read",
    )

    assert state.approval_status == "unreviewed"
    assert state.human_approval_evidence is None
    assert _raw_events(store, forged) == []
    assert store.list_audit_events(limit=100) == []


def test_approval_envelope_is_excluded_from_sorted_compact_utf8_digest() -> None:
    candidate = _candidate()
    candidate["name"] = "Synthetic alignment 測試"
    producer_variant = {
        **candidate,
        "approval_status": "approved",
        "human_approval_evidence": {
            "reviewer_id": "reviewer_synthetic_99",
            "decision_event_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "decided_at": "2026-08-18T00:00:00Z",
            "approval_basis": "Syntactically valid but not authoritative.",
        },
    }
    content = {
        key: value
        for key, value in candidate.items()
        if key not in {"approval_status", "human_approval_evidence"}
    }
    expected = hashlib.sha256(
        json.dumps(
            content,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    assert canonical_candidate_skill_sha256(candidate) == expected
    assert canonical_candidate_skill_sha256(producer_variant) == expected
    assert candidate_skill_approval_idempotency_key(candidate) == (
        f"candidate-skill-approval:1.0:{SKILL_ID}"
    )


def test_exact_replay_returns_same_state_without_duplicate_review_or_audit(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    principal = _reviewer()
    key = candidate_skill_approval_idempotency_key(candidate)
    first = approve_candidate_skill(
        service,
        principal,
        candidate=candidate,
        idempotency_key=key,
        correlation_id="corr-first",
    )
    review_count = len(_raw_events(store, candidate))
    audit_count = len(store.list_audit_events(limit=100))

    replay = approve_candidate_skill(
        service,
        principal,
        candidate=candidate,
        idempotency_key=key,
        correlation_id="corr-replay",
    )

    assert replay == first
    assert len(_raw_events(store, candidate)) == review_count == 1
    assert len(store.list_audit_events(limit=100)) == audit_count == 1


def test_concurrent_exact_replay_across_service_instances_has_one_review_and_audit(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "candidate-approval.sqlite3"
    store_one = SQLiteControlStore(database_path)
    store_two = SQLiteControlStore(database_path)
    services = (ControlService(store_one), ControlService(store_two))
    candidate = _candidate()
    principal = _reviewer()
    key = candidate_skill_approval_idempotency_key(candidate)
    barrier = Barrier(2)

    def approve(service: ControlService):
        barrier.wait()
        return approve_candidate_skill(
            service,
            principal,
            candidate=candidate,
            idempotency_key=key,
            correlation_id="corr-concurrent-replay",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = list(executor.map(approve, services))

    assert states[0] == states[1]
    assert len(_raw_events(store_one, candidate)) == 1
    audits = store_one.list_audit_events(limit=100)
    assert len(audits) == 1
    assert audits[0].result == "accepted"
    assert audits[0].action == "review.append"


def test_different_reviewer_cannot_reuse_existing_approval_as_exact_replay(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    key = candidate_skill_approval_idempotency_key(candidate)
    approve_candidate_skill(
        service,
        _reviewer("reviewer_synthetic_01"),
        candidate=candidate,
        idempotency_key=key,
        correlation_id="corr-original-reviewer",
    )

    with pytest.raises(ControlConflictError, match="another reviewer"):
        approve_candidate_skill(
            service,
            _reviewer("reviewer_synthetic_02"),
            candidate=candidate,
            idempotency_key=key,
            correlation_id="corr-other-reviewer",
        )

    readable = read_candidate_skill_approval_state(
        service,
        _reviewer("reviewer_synthetic_02"),
        candidate=candidate,
        correlation_id="corr-other-reviewer-read",
    )
    assert readable.human_approval_evidence is not None
    assert readable.human_approval_evidence["reviewer_id"] == "reviewer_synthetic_01"
    assert len(_raw_events(store, candidate)) == 1
    assert len(store.list_audit_events(limit=100)) == 1


def test_changed_content_conflicts_before_approval_even_with_different_caller_key(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    original = _candidate()
    changed = _candidate(instruction="Different canonical content.")
    principal = _reviewer()
    approve_candidate_skill(
        service,
        principal,
        candidate=original,
        idempotency_key=candidate_skill_approval_idempotency_key(original),
        correlation_id="corr-original",
    )

    changed_read = read_candidate_skill_approval_state(
        service,
        principal,
        candidate=changed,
        correlation_id="corr-changed-read",
    )
    assert changed_read.approval_status == "unreviewed"
    with pytest.raises(ControlConflictError, match="deterministic schema-and-skill"):
        approve_candidate_skill(
            service,
            principal,
            candidate=changed,
            idempotency_key="different-caller-idempotency-key",
            correlation_id="corr-changed",
        )

    assert _raw_events(store, changed) == []
    assert len(_raw_events(store, original)) == 1
    assert len(store.list_audit_events(limit=100)) == 1


def test_changed_content_with_exact_skill_key_hits_store_conflict_without_mutation(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    original = _candidate()
    changed = _candidate(instruction="Different canonical content.")
    principal = _reviewer()
    key = candidate_skill_approval_idempotency_key(original)
    assert candidate_skill_approval_idempotency_key(changed) == key
    approve_candidate_skill(
        service,
        principal,
        candidate=original,
        idempotency_key=key,
        correlation_id="corr-original",
    )

    with pytest.raises(ControlConflictError, match="idempotency key conflicts"):
        approve_candidate_skill(
            service,
            principal,
            candidate=changed,
            idempotency_key=key,
            correlation_id="corr-changed",
        )

    assert _raw_events(store, changed) == []
    assert len(_raw_events(store, original)) == 1
    assert len(store.list_audit_events(limit=100)) == 1


def test_non_reviewer_and_missing_scope_cannot_append_accepted_review(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    key = candidate_skill_approval_idempotency_key(candidate)
    non_reviewer = AuthenticatedPrincipal(
        subject="worker-synthetic",
        roles=frozenset({ControlRole.DETERMINISTIC_WORKER}),
        scope=SCOPE,
    )
    with pytest.raises(AuthorizationDeniedError, match="action forbidden"):
        approve_candidate_skill(
            service,
            non_reviewer,
            candidate=candidate,
            idempotency_key=key,
            correlation_id="corr-non-reviewer",
        )
    with pytest.raises(AuthorizationDeniedError, match="action forbidden"):
        approve_candidate_skill(
            service,
            _reviewer(scope=None),
            candidate=candidate,
            idempotency_key=key,
            correlation_id="corr-no-scope",
        )

    assert _raw_events(store, candidate) == []
    audits = store.list_audit_events(limit=100)
    assert len(audits) == 1
    assert audits[0].result == "denied"
    assert not any(audit.result == "accepted" for audit in audits)


def test_contract_incompatible_subject_cannot_be_rewritten_into_reviewer_identity(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    principal = _reviewer(subject="alice-reviewer")
    with pytest.raises(AuthorizationDeniedError, match="contract-compatible"):
        approve_candidate_skill(
            service,
            principal,
            candidate=candidate,
            idempotency_key=candidate_skill_approval_idempotency_key(candidate),
            correlation_id="corr-bad-reviewer-id",
        )

    assert _raw_events(store, candidate) == []
    assert store.list_audit_events(limit=100) == []


def test_same_candidate_and_idempotency_are_isolated_by_scope(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    key = candidate_skill_approval_idempotency_key(candidate)
    scope_a = TenantWorkspaceScope("tenant-synthetic", "workspace-alpha")
    scope_b = TenantWorkspaceScope("tenant-synthetic", "workspace-beta")
    state_a = approve_candidate_skill(
        service,
        _reviewer(scope=scope_a),
        candidate=candidate,
        idempotency_key=key,
        correlation_id="corr-scope-a",
    )
    state_b = approve_candidate_skill(
        service,
        _reviewer(scope=scope_b),
        candidate=candidate,
        idempotency_key=key,
        correlation_id="corr-scope-b",
    )

    assert state_a.target_id == state_b.target_id
    assert state_a.content_sha256 == state_b.content_sha256
    assert state_a.human_approval_evidence != state_b.human_approval_evidence
    assert "whscope1" not in repr(state_a)
    assert "whscope1" not in repr(state_b)
    assert len(_raw_events(store, candidate, scope_a)) == 1
    assert len(_raw_events(store, candidate, scope_b)) == 1
    assert len(store.list_audit_events(limit=100)) == 2


def test_sqlite_restart_preserves_identical_effective_readback(tmp_path: Path) -> None:
    database_path = tmp_path / "candidate-approval.sqlite3"
    service = ControlService(SQLiteControlStore(database_path))
    candidate = _candidate()
    principal = _reviewer()
    approved = approve_candidate_skill(
        service,
        principal,
        candidate=candidate,
        idempotency_key=candidate_skill_approval_idempotency_key(candidate),
        correlation_id="corr-before-restart",
    )

    restarted = ControlService(SQLiteControlStore(database_path))
    readback = read_candidate_skill_approval_state(
        restarted,
        principal,
        candidate=candidate,
        correlation_id="corr-after-restart",
    )
    assert readback == approved


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda value: value.pop("trigger"), "missing required field trigger"),
        (
            lambda value: value.__setitem__("undeclared", "synthetic"),
            "additional field undeclared",
        ),
        (
            lambda value: value["trigger"].__setitem__("signals", "not-an-array"),
            "trigger.signals must be an array",
        ),
        (
            lambda value: value["inputs"][0].__setitem__("undeclared", True),
            "inputs[0] has additional field undeclared",
        ),
        (
            lambda value: value["supporting_examples"][0]["artifact_references"][
                0
            ].pop("sha256"),
            "missing required field sha256",
        ),
        (
            lambda value: value["parameters"][0].__setitem__("value", {}),
            "parameters[0].value must be a JSON scalar",
        ),
        (
            lambda value: value["preconditions"].append(value["preconditions"][0]),
            "preconditions items must be unique",
        ),
        (
            lambda value: value.__setitem__("approval_status", "approved"),
            "approved candidate requires human_approval_evidence",
        ),
    ],
)
def test_complete_contract_invalid_candidate_is_rejected_before_control_service(
    tmp_path: Path,
    mutator,
    message: str,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    mutator(candidate)

    with pytest.raises(ValueError, match=re.escape(message)):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key=f"candidate-skill-approval:1.0:{SKILL_ID}",
            correlation_id="corr-contract-invalid",
        )

    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


@pytest.mark.parametrize("operation", ["approve", "read"])
def test_internal_incoherence_fails_before_all_downstream_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    candidate["ordered_actions"][1]["sequence"] = 3
    downstream_calls: list[str] = []

    def unexpected_call(*args, **kwargs):
        downstream_calls.append("called")
        raise AssertionError("incoherent candidate reached a downstream effect")

    monkeypatch.setattr(service, "read_review", unexpected_call)
    monkeypatch.setattr(service, "append_review", unexpected_call)
    monkeypatch.setattr(service, "list_reviews", unexpected_call)
    monkeypatch.setattr(candidate_skill_approval.os, "open", unexpected_call)

    with pytest.raises(ValueError, match="sequences must equal 1..N"):
        if operation == "approve":
            approve_candidate_skill(
                service,
                _reviewer(),
                candidate=candidate,
                idempotency_key=f"candidate-skill-approval:1.0:{SKILL_ID}",
                correlation_id="corr-internal-incoherence",
            )
        else:
            read_candidate_skill_approval_state(
                service,
                _reviewer(),
                candidate=candidate,
                correlation_id="corr-internal-incoherence",
            )

    assert downstream_calls == []
    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


def test_structural_admission_precedes_internal_coherence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    candidate.pop("trigger")

    def unexpected_semantic_validation(*args, **kwargs):
        raise AssertionError("semantic validation ran before structural admission")

    monkeypatch.setattr(
        candidate_skill_approval,
        "validate_candidate_skill_internal_coherence",
        unexpected_semantic_validation,
    )

    with pytest.raises(ValueError, match="missing required field trigger"):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key=f"candidate-skill-approval:1.0:{SKILL_ID}",
            correlation_id="corr-structural-ordering",
        )

    assert _review_row_count(store) == 0
    assert store.list_audit_events(limit=100) == []


@pytest.mark.parametrize(
    ("mutator", "error_type", "message"),
    [
        (lambda value: value.pop("schema_version"), ValueError, "schema_version"),
        (lambda value: value.__setitem__("schema_version", "1.1"), ValueError, "1.0"),
        (lambda value: value.pop("skill_id"), ValueError, "skill_id"),
        (
            lambda value: value.__setitem__("skill_id", SKILL_ID.upper()),
            ValueError,
            "canonical UUID",
        ),
        (
            lambda value: value.__setitem__("skill_id", SKILL_ID.replace("-", "")),
            ValueError,
            "canonical UUID",
        ),
        (lambda value: value.__setitem__("bad", math.nan), ValueError, "finite"),
        (lambda value: value.__setitem__("bad", math.inf), ValueError, "finite"),
        (lambda value: value.__setitem__("bad", (1, 2)), TypeError, "non-JSON"),
        (lambda value: value.__setitem__("bad", b"bytes"), TypeError, "non-JSON"),
        (lambda value: value.__setitem__(1, "bad key"), TypeError, "keys"),
        (
            lambda value: value.__setitem__("bad", 10**101),
            ValueError,
            "magnitude",
        ),
        (
            lambda value: value.__setitem__("x" * 257, "bad key"),
            ValueError,
            "key exceeds",
        ),
        (
            lambda value: value.__setitem__("bad", "x" * 16_385),
            ValueError,
            "string exceeds",
        ),
        (
            lambda value: value.__setitem__("bad", list(range(513))),
            ValueError,
            "array exceeds",
        ),
    ],
)
def test_malformed_non_json_or_unbounded_candidate_is_rejected_before_mutation(
    tmp_path: Path,
    mutator,
    error_type: type[Exception],
    message: str,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    mutator(candidate)
    with pytest.raises(error_type, match=message):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key="not-reached",
            correlation_id="corr-invalid",
        )
    assert store.list_audit_events(limit=100) == []


def test_non_mapping_cycle_depth_total_values_and_bytes_are_bounded_before_mutation(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    invalid_values: list[tuple[object, type[Exception], str]] = [
        (["not", "a", "mapping"], TypeError, "mapping"),
    ]
    cyclic = _candidate()
    cyclic["cycle"] = cyclic
    invalid_values.append((cyclic, ValueError, "cycles"))

    deep = _candidate()
    nested: dict[str, object] = {}
    deep["nested"] = nested
    for _ in range(13):
        child: dict[str, object] = {}
        nested["child"] = child
        nested = child
    invalid_values.append((deep, ValueError, "depth"))

    many = _candidate()
    many["groups"] = [list(range(512)) for _ in range(9)]
    invalid_values.append((many, ValueError, "total value"))

    large = _candidate()
    large["large"] = ["x" * 16_000 for _ in range(17)]
    invalid_values.append((large, ValueError, "byte limit"))

    for value, error_type, message in invalid_values:
        with pytest.raises(error_type, match=message):
            approve_candidate_skill(
                service,
                _reviewer(),
                candidate=value,  # type: ignore[arg-type]
                idempotency_key="not-reached",
                correlation_id="corr-invalid-bounds",
            )
    assert store.list_audit_events(limit=100) == []


def test_invalid_request_text_and_idempotency_fail_before_review_mutation(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    candidate = _candidate()
    with pytest.raises(ValueError, match="correlation_id"):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key=candidate_skill_approval_idempotency_key(candidate),
            correlation_id="",
        )
    with pytest.raises(ControlConflictError, match="deterministic"):
        approve_candidate_skill(
            service,
            _reviewer(),
            candidate=candidate,
            idempotency_key="caller-selected-key",
            correlation_id="corr-wrong-key",
        )
    assert _raw_events(store, candidate) == []
    assert store.list_audit_events(limit=100) == []
