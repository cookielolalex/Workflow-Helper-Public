#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/workflow-helper-dev-smoke.XXXXXX")"
runtime_env="$smoke_dir/.env"
project_name="workflow-helper-dev-smoke-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
api_port="${WORKFLOW_API_PORT:-18000}"
base_url="http://127.0.0.1:${api_port}"

capture_proof="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
worker_proof="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
reviewer_proof="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
reviewer_session="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"
reviewer_csrf="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"

cat >"$runtime_env" <<EOF
WORKFLOW_COMPOSE_ENV_FILE=$runtime_env
WORKFLOW_API_PORT=$api_port
ENVIRONMENT=development
LOG_LEVEL=INFO
API_BASE_URL=http://api:8000
NEXT_PUBLIC_API_BASE_URL=http://localhost:$api_port
AWS_REGION=ap-northeast-1
RAW_BUCKET=workflow-helper-raw-dev
PROCESSED_BUCKET=workflow-helper-processed-dev
RAW_RETENTION_DAYS=14
WORKFLOW_DEV_DATA_DIR=/tmp/workflow-helper-dev-data
WORKFLOW_DEV_CAPTURE_PROOF=$capture_proof
WORKFLOW_DEV_WORKER_PROOF=$worker_proof
WORKFLOW_DEV_REVIEWER_PROOF=$reviewer_proof
WORKFLOW_DEV_REVIEWER_SESSION=$reviewer_session
WORKFLOW_DEV_REVIEWER_CSRF=$reviewer_csrf
EOF

compose=(
  docker compose
  --env-file "$runtime_env"
  --file "$repository_root/docker-compose.yml"
  --project-name "$project_name"
)

cleanup() {
  status=$?
  if (( status != 0 )); then
    echo "Synthetic dev-runtime smoke failed; collecting API diagnostics." >&2
    "${compose[@]} ps" >&2 || true
    "${compose[@]} logs --no-color api" >&2 || true
  fi
  "${compose[@]} down --volumes --remove-orphans" >/dev/null 2>&1 || true
  rm -rf "$smoke_dir"
  exit "$status"
}
trap cleanup EXIT

"${compose[@]}" up --detach --wait --wait-timeout 120 api

for attempt in $(seq 1 120); do
  if health_json="$(curl --silent --show-error "$base_url/health" 2>/dev/null)"; then
    HEALTH_JSON="$health_json" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["HEALTH_JSON"])
if payload.get("status") != "ok" or payload.get("environment") != "synthetic":
    raise SystemExit(f"unexpected dev health payload: {payload}")
PY
    break
  fi
  if (( attempt == 120 )); then
    echo "Timed out waiting for the synthetic dev API." >&2
    exit 1
  fi
  sleep 1
done

session_id="00000000-0000-4000-8000-000000000201"
session_payload="$(cat <<EOF
{"schema_version":"1.0","session_id":"$session_id","machine_id":"synthetic-machine-201","project_id":"synthetic-project","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:00:05Z","active_duration_seconds":5,"approved_process":"acad","package_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","package_size_bytes":1}
EOF
)"

status="$({
  curl --silent --show-error --output "$smoke_dir/register.json" --write-out '%{http_code}' \
    --request POST "$base_url/v1/sessions" \
    --header 'Content-Type: application/json' \
    --header "X-Workflow-Dev-Proof: $capture_proof" \
    --data "$session_payload"
} || true)"
if [[ "$status" != "201" ]]; then
  echo "Authorized synthetic session registration returned HTTP $status." >&2
  cat "$smoke_dir/register.json" >&2 || true
  exit 1
fi

status="$({
  curl --silent --show-error --output "$smoke_dir/list.json" --write-out '%{http_code}' \
    --request GET "$base_url/v1/sessions" \
    --header "Cookie: workflow_session=$reviewer_session" \
    --header "X-Workflow-Dev-Reviewer-Proof: $reviewer_proof"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Authorized synthetic reviewer read returned HTTP $status." >&2
  cat "$smoke_dir/list.json" >&2 || true
  exit 1
fi

status="$({
  curl --silent --show-error --output "$smoke_dir/missing-proof.json" --write-out '%{http_code}' \
    --request POST "$base_url/v1/sessions" \
    --header 'Content-Type: application/json' \
    --data "$session_payload"
} || true)"
if [[ "$status" != "401" ]]; then
  echo "Missing synthetic proof returned HTTP $status; fail-closed denial expected." >&2
  cat "$smoke_dir/missing-proof.json" >&2 || true
  exit 1
fi

status="$({
  curl --silent --show-error --output "$smoke_dir/invalid-proof.json" --write-out '%{http_code}' \
    --request POST "$base_url/v1/sessions" \
    --header 'Content-Type: application/json' \
    --header 'X-Workflow-Dev-Proof: invalid-proof' \
    --data "$session_payload"
} || true)"
if [[ "$status" != "401" ]]; then
  echo "Invalid synthetic proof returned HTTP $status; fail-closed denial expected." >&2
  cat "$smoke_dir/invalid-proof.json" >&2 || true
  exit 1
fi

echo "Synthetic dev-runtime smoke passed: health, authorized session registration/read, and missing/invalid proof denial."
