#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_name="workflow-helper-localstack-smoke-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
compose=(
  docker compose
  --file "$repository_root/docker-compose.yml"
  --project-name "$project_name"
)

cleanup() {
  status=$?

  if (( status != 0 )); then
    echo "LocalStack smoke test failed; collecting diagnostics." >&2
    "${compose[@]}" ps >&2 || true
    "${compose[@]}" logs --no-color localstack >&2 || true
    curl --silent --show-error http://localhost:4566/_localstack/init/ready >&2 || true
  fi

  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

if [[ ! -x "$repository_root/scripts/localstack-init.sh" ]]; then
  echo "scripts/localstack-init.sh must be executable for LocalStack to run it." >&2
  exit 1
fi

"${compose[@]}" up --detach --wait --wait-timeout 120 localstack

python3 "$repository_root/scripts/wait_for_localstack_ready.py" \
  --timeout 120 \
  --interval 1

for bucket in workflow-helper-raw-dev workflow-helper-processed-dev; do
  "${compose[@]}" exec -T localstack \
    awslocal s3api head-bucket --bucket "$bucket" >/dev/null
done

main_queue_url="$(
  "${compose[@]}" exec -T localstack \
    awslocal sqs get-queue-url \
      --queue-name workflow-helper-processing \
      --query QueueUrl \
      --output text |
    tr -d '\r'
)"

"${compose[@]}" exec -T localstack \
  awslocal sqs get-queue-url \
    --queue-name workflow-helper-processing-dlq >/dev/null

redrive_policy="$(
  "${compose[@]}" exec -T localstack \
    awslocal sqs get-queue-attributes \
      --queue-url "$main_queue_url" \
      --attribute-names RedrivePolicy \
      --query Attributes.RedrivePolicy \
      --output text |
    tr -d '\r'
)"

REDRIVE_POLICY="$redrive_policy" python3 - <<'PY'
import json
import os

policy = json.loads(os.environ["REDRIVE_POLICY"])
expected_arn = (
    "arn:aws:sqs:ap-northeast-1:000000000000:"
    "workflow-helper-processing-dlq"
)
if policy.get("deadLetterTargetArn") != expected_arn:
    raise SystemExit(f"Unexpected dead-letter queue ARN: {policy}")
if str(policy.get("maxReceiveCount")) != "3":
    raise SystemExit(f"Unexpected maxReceiveCount: {policy}")
PY

echo "LocalStack init hook and S3/SQS resources are ready."
