from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_compose_waits_for_initialized_localstack_and_bounds_worker_restarts() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "awslocal s3api head-bucket --bucket workflow-helper-raw-dev" in compose
    assert "awslocal sqs get-queue-url --queue-name workflow-helper-processing" in compose
    assert compose.count("condition: service_healthy") >= 3
    assert 'restart: "on-failure:5"' in compose
    assert "WORKER_MAX_SERVICE_FAILURES" in compose
    assert "WORKER_MAX_MESSAGE_ATTEMPTS" in compose


def test_localstack_bootstrap_is_idempotent_and_has_dlq_redrive() -> None:
    bootstrap = (ROOT / "scripts/localstack-init.sh").read_text(encoding="utf-8")

    assert "create_bucket_if_missing" in bootstrap
    assert "head-bucket" in bootstrap
    assert "workflow-helper-processing-dlq" in bootstrap
    assert "RedrivePolicy" in bootstrap
    assert 'maxReceiveCount\\\":\\\"3' in bootstrap
