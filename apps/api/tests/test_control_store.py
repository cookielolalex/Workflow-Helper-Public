import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest

from workflow_api.control_scope import TenantWorkspaceScope, _qualify, _scope_prefix
from workflow_api.control_store import (
    MAX_LEASE_SECONDS,
    AuditContext,
    ControlConflictError,
    JobNotFoundError,
    Lease,
    LeaseUnavailableError,
    SQLiteControlStore,
    StaleLeaseError,
)

START = datetime(2026, 8, 17, 4, 0, tzinfo=UTC)


def _store(tmp_path: Path) -> SQLiteControlStore:
    return SQLiteControlStore(tmp_path / "control-plane.sqlite3")


def _provenance(*, artifact_id: str = "artifact-synthetic") -> dict[str, str]:
    return {
        "source": "synthetic_fixture",
        "artifact_id": artifact_id,
        "revision": "revision-1",
        "sha256": "9" * 64,
    }


def test_state_survives_restart_and_same_owner_acquire_is_idempotent(tmp_path: Path) -> None:
    database_path = tmp_path / "control-plane.sqlite3"
    first = SQLiteControlStore(database_path)
    first.register_job("job-restart", "a" * 64, now=START)
    lease = first.acquire("job-restart", "worker-1", now=START, ttl_seconds=30)
    review = first.append_review_event(
        target_id="job-restart",
        idempotency_key="review-restart-1",
        actor_id="reviewer-synthetic",
        status="pending",
        provenance=_provenance(artifact_id="job-restart-input"),
        detail={"note": "not real data"},
        occurred_at=START,
    )

    restarted = SQLiteControlStore(database_path)

    assert restarted.get_job("job-restart").state == "leased"
    assert restarted.acquire(
        "job-restart", "worker-1", now=START + timedelta(seconds=1), ttl_seconds=30
    ) == lease
    projection = restarted.get_review_projection("job-restart")
    assert projection is not None
    assert projection.status == "pending"
    assert projection.last_event_id == review.event_id
    assert projection.version == 1


def test_job_registration_and_completion_are_idempotent_but_conflicts_fail(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    first = store.register_job("job-idempotent", "b" * 64, now=START)
    duplicate = store.register_job(
        "job-idempotent", "b" * 64, now=START + timedelta(seconds=1)
    )
    assert duplicate == first
    with pytest.raises(ControlConflictError):
        store.register_job("job-idempotent", "c" * 64, now=START)

    lease = store.acquire("job-idempotent", "worker-1", now=START, ttl_seconds=30)
    completed = store.complete(
        lease,
        idempotency_key="completion-1",
        result_digest="d" * 64,
        now=START + timedelta(seconds=2),
    )
    retry = store.complete(
        lease,
        idempotency_key="completion-1",
        result_digest="d" * 64,
        now=START + timedelta(seconds=3),
    )
    assert retry == completed
    assert store.get_job("job-idempotent").state == "completed"

    stale_same_result = Lease(
        job_id=lease.job_id,
        owner_id="stale-worker",
        fencing_token=lease.fencing_token - 1,
        attempt=lease.attempt,
        acquired_at=lease.acquired_at,
        expires_at=lease.expires_at,
    )
    with pytest.raises(StaleLeaseError):
        store.complete(
            stale_same_result,
            idempotency_key="completion-1",
            result_digest="d" * 64,
            now=START + timedelta(seconds=3),
        )

    with pytest.raises(ControlConflictError):
        store.complete(
            lease,
            idempotency_key="completion-1",
            result_digest="e" * 64,
            now=START + timedelta(seconds=3),
        )
    with pytest.raises(ControlConflictError):
        store.complete(
            lease,
            idempotency_key="completion-2",
            result_digest="d" * 64,
            now=START + timedelta(seconds=3),
        )


def test_concurrent_acquisition_never_exceeds_three_active_workers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    job_ids = [f"job-race-{index}" for index in range(4)]
    for index, job_id in enumerate(job_ids):
        store.register_job(job_id, f"{index + 1:064x}", now=START)
    barrier = Barrier(len(job_ids))

    def acquire(job_id: str) -> Lease | None:
        barrier.wait()
        try:
            return store.acquire(job_id, f"worker-{job_id}", now=START, ttl_seconds=60)
        except LeaseUnavailableError:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(acquire, job_ids))

    leases = [result for result in results if result is not None]
    assert len(leases) == 3
    assert len({lease.fencing_token for lease in leases}) == 1
    assert sum(store.get_job(job_id).state == "leased" for job_id in job_ids) == 3


def test_racing_owners_cannot_both_acquire_the_same_job(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.register_job("job-single-owner", "f" * 64, now=START)
    barrier = Barrier(2)

    def acquire(owner_id: str) -> Lease | None:
        barrier.wait()
        try:
            return store.acquire(
                "job-single-owner", owner_id, now=START, ttl_seconds=30
            )
        except LeaseUnavailableError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(acquire, ["worker-a", "worker-b"]))

    leases = [result for result in results if result is not None]
    assert len(leases) == 1
    assert leases[0].fencing_token == 1


def test_expiry_reacquisition_fences_the_stale_worker(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.register_job("job-fencing", "1" * 64, now=START)
    first = store.acquire("job-fencing", "worker-a", now=START, ttl_seconds=10)

    with pytest.raises(StaleLeaseError):
        store.heartbeat(first, now=START + timedelta(seconds=10), ttl_seconds=10)

    second = store.acquire(
        "job-fencing", "worker-b", now=START + timedelta(seconds=11), ttl_seconds=10
    )
    assert second.fencing_token == first.fencing_token + 1
    assert second.attempt == first.attempt + 1

    with pytest.raises(StaleLeaseError):
        store.complete(
            first,
            idempotency_key="stale-completion",
            result_digest="2" * 64,
            now=START + timedelta(seconds=12),
        )

    refreshed = store.heartbeat(
        second, now=START + timedelta(seconds=12), ttl_seconds=20
    )
    assert refreshed.expires_at == START + timedelta(seconds=32)
    completion = store.complete(
        refreshed,
        idempotency_key="current-completion",
        result_digest="3" * 64,
        now=START + timedelta(seconds=13),
    )
    assert completion.fencing_token == second.fencing_token


def test_review_events_are_append_only_idempotent_and_project_current_state(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control-plane.sqlite3"
    store = SQLiteControlStore(database_path)
    first = store.append_review_event(
        target_id="artifact-synthetic",
        idempotency_key="review-1",
        actor_id="reviewer-1",
        status="pending",
        provenance={**_provenance(), "tool": "pytest"},
        detail={"reason": "awaiting review"},
        occurred_at=START,
    )
    retry = store.append_review_event(
        target_id="artifact-synthetic",
        idempotency_key="review-1",
        actor_id="reviewer-1",
        status="pending",
        provenance={"tool": "pytest", **_provenance()},
        detail={"reason": "awaiting review"},
        occurred_at=START + timedelta(seconds=30),
    )
    assert retry == first

    with pytest.raises(ControlConflictError):
        store.append_review_event(
            target_id="artifact-synthetic",
            idempotency_key="review-1",
            actor_id="reviewer-1",
            status="approved",
            provenance={**_provenance(), "tool": "pytest"},
            occurred_at=START + timedelta(seconds=1),
        )

    approved = store.append_review_event(
        target_id="artifact-synthetic",
        idempotency_key="review-2",
        actor_id="reviewer-2",
        status="approved",
        provenance={
            **_provenance(),
            "source": "human_review",
            "evidence": "synthetic-only",
        },
        detail={"reason": "fixture accepted"},
        occurred_at=START + timedelta(seconds=2),
    )
    projection = store.get_review_projection("artifact-synthetic")
    assert projection is not None
    assert projection.status == "approved"
    assert projection.version == 2
    assert projection.last_event_id == approved.event_id
    assert [event.status for event in store.list_review_events("artifact-synthetic")] == [
        "pending",
        "approved",
    ]

    with pytest.raises(ControlConflictError):
        store.append_review_event(
            target_id="different-artifact",
            idempotency_key="review-1",
            actor_id="reviewer-1",
            status="pending",
            provenance=_provenance(artifact_id="different-artifact"),
            occurred_at=START + timedelta(seconds=3),
        )

    connection = sqlite3.connect(database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "update review_events set status = 'rejected' where event_id = ?",
                (first.event_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("delete from review_events where event_id = ?", (first.event_id,))
    finally:
        connection.close()


def test_invalid_bounds_and_missing_provenance_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.register_job("job-bounds", "4" * 64, now=START)
    with pytest.raises(ValueError, match="ttl_seconds"):
        store.acquire(
            "job-bounds",
            "worker-1",
            now=START,
            ttl_seconds=MAX_LEASE_SECONDS + 1,
        )
    with pytest.raises(ValueError, match="provenance.source"):
        store.append_review_event(
            target_id="artifact-synthetic",
            idempotency_key="review-no-source",
            actor_id="reviewer-1",
            status="pending",
            provenance={},
            occurred_at=START,
        )
    for missing_field in ("artifact_id", "revision"):
        provenance = _provenance()
        del provenance[missing_field]
        with pytest.raises(ValueError, match=f"provenance.{missing_field}"):
            store.append_review_event(
                target_id="artifact-synthetic",
                idempotency_key=f"review-no-{missing_field}",
                actor_id="reviewer-1",
                status="pending",
                provenance=provenance,
                occurred_at=START,
            )
    with pytest.raises(ValueError, match="provenance.sha256"):
        store.append_review_event(
            target_id="artifact-synthetic",
            idempotency_key="review-bad-sha",
            actor_id="reviewer-1",
            status="pending",
            provenance={**_provenance(), "sha256": "A" * 64},
            occurred_at=START,
        )


def _audit(
    *,
    correlation_id: str = "corr-store",
    action: str = "job.register",
    target_id: str = "job-audited",
    idempotency_key: str | None = None,
) -> AuditContext:
    return AuditContext(
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        subject_id="subject-synthetic",
        roles=("deterministic_worker",),
        action=action,
        target_id=target_id,
        result="accepted",
        occurred_at=START,
    )


def test_accepted_audit_is_atomic_append_only_and_survives_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "control-plane.sqlite3"
    store = SQLiteControlStore(database_path)
    store.register_job("job-audited", "7" * 64, now=START, audit=_audit())
    lease = store.acquire(
        "job-audited",
        "subject-synthetic",
        now=START,
        ttl_seconds=30,
        audit=_audit(
            correlation_id="corr-acquire",
            action="job.acquire",
            idempotency_key="acquire-semantic-1",
        ),
    )
    store.complete(
        lease,
        idempotency_key="completion-audited",
        result_digest="8" * 64,
        now=START + timedelta(seconds=1),
        audit=_audit(
            correlation_id="corr-complete",
            action="job.complete",
            idempotency_key="completion-audited",
        ),
    )

    restarted = SQLiteControlStore(database_path)
    events = restarted.list_audit_events(limit=100)
    assert [event.action for event in events] == [
        "job.register",
        "job.acquire",
        "job.complete",
    ]
    assert [event.correlation_id for event in events] == [
        "corr-store",
        "corr-acquire",
        "corr-complete",
    ]
    assert all(event.subject_id == "subject-synthetic" for event in events)
    assert all(event.roles == ("deterministic_worker",) for event in events)
    assert all(event.result == "accepted" for event in events)

    connection = sqlite3.connect(database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "update audit_events set result = 'denied' where event_id = ?",
                (events[0].event_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "delete from audit_events where event_id = ?", (events[0].event_id,)
            )
    finally:
        connection.close()


def test_audit_insert_failure_rolls_back_first_state_mutation(tmp_path: Path) -> None:
    database_path = tmp_path / "control-plane.sqlite3"
    store = SQLiteControlStore(database_path)
    connection = sqlite3.connect(database_path)
    try:
        connection.executescript(
            """
            create trigger synthetic_reject_accepted_audit
            before insert on audit_events
            when NEW.result = 'accepted'
            begin
                select raise(abort, 'synthetic audit failure');
            end;
            """
        )
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="synthetic audit failure"):
        store.register_job("job-audited", "7" * 64, now=START, audit=_audit())

    with pytest.raises(JobNotFoundError):
        store.get_job("job-audited")
    assert store.list_audit_events(limit=100) == []


def test_idempotent_mutation_retries_each_append_accepted_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.register_job("job-audited", "7" * 64, now=START, audit=_audit())
    retry = store.register_job(
        "job-audited",
        "7" * 64,
        now=START + timedelta(seconds=1),
        audit=_audit(correlation_id="corr-store-retry"),
    )

    assert retry == first
    assert [event.correlation_id for event in store.list_audit_events()] == [
        "corr-store",
        "corr-store-retry",
    ]


def test_sql_scoped_audit_queries_number_and_page_after_scope_predicate(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    scope_a = TenantWorkspaceScope("tenant-synthetic", "workspace-alpha")
    scope_b = TenantWorkspaceScope("tenant-synthetic", "workspace-beta")
    events = []
    for index, scope in enumerate((scope_a, scope_b, scope_a, scope_b), start=1):
        events.append(
            store.append_audit_event(
                _audit(
                    correlation_id=f"corr-{index}",
                    target_id=_qualify(scope, "audit_target", "same-target"),
                )
            )
        )

    scoped_a = store.list_scoped_audit_events(
        _scope_prefix(scope_a),
        after_sequence=0,
        limit=100,
    )
    scoped_b = store.list_scoped_audit_events(
        _scope_prefix(scope_b),
        after_sequence=1,
        limit=1,
    )
    assert [(event.sequence, event.correlation_id) for event in scoped_a] == [
        (1, "corr-1"),
        (2, "corr-3"),
    ]
    assert [(event.sequence, event.correlation_id) for event in scoped_b] == [
        (2, "corr-4")
    ]
    assert (
        store.get_scoped_audit_event(
            events[0].event_id,
            scope_prefix=_scope_prefix(scope_b),
        )
        is None
    )
