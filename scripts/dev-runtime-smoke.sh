#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="$repository_root/scripts/dev-runtime-smoke.sh"
if (( $# == 0 )); then
  smoke_scenario="needs-changes"
elif (( $# == 1 )) && [[ "$1" == "--scenario=approved" ]]; then
  smoke_scenario="approved"
else
  echo "Unsupported synthetic smoke scenario." >&2
  exit 2
fi
smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/workflow-helper-dev-smoke.XXXXXX")"
runtime_env="$smoke_dir/.env"
project_name="workflow-helper-p3b-${smoke_scenario}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
api_port="${WORKFLOW_API_PORT:-18000}"
web_port="${WORKFLOW_WEB_PORT:-13000}"
api_base="http://127.0.0.1:${api_port}"
web_base="http://127.0.0.1:${web_port}"

capture_proof="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
worker_proof="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
reviewer_proof="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
reviewer_session="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"
reviewer_csrf="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"

cat >"$runtime_env" <<EOF
WORKFLOW_COMPOSE_ENV_FILE=$runtime_env
WORKFLOW_API_PORT=$api_port
WORKFLOW_WEB_PORT=$web_port
ENVIRONMENT=development
LOG_LEVEL=INFO
AWS_REGION=ap-northeast-1
RAW_BUCKET=workflow-helper-raw-dev
PROCESSED_BUCKET=workflow-helper-processed-dev
RAW_RETENTION_DAYS=14
WORKFLOW_DEV_DATA_DIR=/var/lib/workflow-helper/runtime
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
  teardown_status=0
  if (( status != 0 )); then
    echo "Synthetic dev-runtime smoke failed; collecting bounded diagnostics." >&2
    "${compose[@]}" ps >&2 || true
    "${compose[@]}" logs --no-color api seed web >&2 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || teardown_status=$?
  rm -rf "$smoke_dir" || teardown_status=$?
  trap - EXIT
  if (( status == 0 && teardown_status != 0 )); then
    echo "Synthetic smoke teardown did not complete; approved cycle was not started." >&2
    exit 1
  fi
  if (( status == 0 )) && [[ "$smoke_scenario" == "needs-changes" ]]; then
    exec "$script_path" --scenario=approved
  fi
  exit "$status"
}
trap cleanup EXIT

"${compose[@]}" up --detach --wait --wait-timeout 180 web

health_json="$(curl --fail --silent --show-error --max-time 5 "$api_base/health")"
HEALTH_JSON="$health_json" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["HEALTH_JSON"])
if payload != {
    "status": "ok",
    "service": "workflow-helper-api",
    "environment": "synthetic",
}:
    raise SystemExit("unexpected synthetic health payload")
PY

status="$({
  curl --silent --show-error --max-time 5 \
    --output "$smoke_dir/missing-proof.json" --write-out '%{http_code}' \
    --request POST "$api_base/v1/sessions" \
    --header 'Content-Type: application/json' \
    --data '{}'
} || true)"
if [[ "$status" != "401" ]]; then
  echo "Missing synthetic proof did not fail closed." >&2
  exit 1
fi

status="$({
  curl --silent --show-error --max-time 5 \
    --output "$smoke_dir/invalid-proof.json" --write-out '%{http_code}' \
    --request POST "$api_base/v1/sessions" \
    --header 'Content-Type: application/json' \
    --header 'X-Workflow-Dev-Proof: invalid-proof' \
    --data '{}'
} || true)"
if [[ "$status" != "401" ]]; then
  echo "Invalid synthetic proof did not fail closed." >&2
  exit 1
fi

status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/api-candidates.json" --write-out '%{http_code}' \
    "$api_base/v1/control/candidate-publications/review-queue" \
    --header "Cookie: workflow_session=$reviewer_session" \
    --header "Origin: https://review.synthetic.example" \
    --header "X-Workflow-Dev-Reviewer-Proof: $reviewer_proof"
} || true)"
if ! API_CANDIDATES="$smoke_dir/api-candidates.json" python3 - <<'PY' \
  >"$smoke_dir/api-candidate-verdict.txt"
import json
import os
from pathlib import Path

path = Path(os.environ["API_CANDIDATES"])
count = "unknown"
schema = "invalid"
valid = False
try:
    if path.is_file() and path.stat().st_size <= 262_144:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            value = payload.get("count")
            if type(value) is int:
                count = str(value)
            items = payload.get("items")
            item = items[0] if isinstance(items, list) and len(items) == 1 else None
            valid = (
                set(payload) == {"items", "count"}
                and type(value) is int
                and value == 1
                and isinstance(items, list)
                and len(items) == 1
                and isinstance(item, dict)
                and set(item) == {
                    "publication_key",
                    "review_target_id",
                    "command_sequence",
                    "occurrence_count",
                    "provenance",
                    "review_status",
                    "finalized_at_us",
                }
                and item.get("command_sequence") == ["LINE", "TRIM", "LINE", "TRIM"]
                and item.get("occurrence_count") == 4
                and item.get("provenance") == "observed"
                and item.get("review_status") == "unreviewed"
            )
            if valid:
                schema = "valid"
except (OSError, UnicodeDecodeError, json.JSONDecodeError):
    pass
print(f"count={count}; schema={schema}")
raise SystemExit(0 if valid else 1)
PY
then
  api_verdict="$(cat "$smoke_dir/api-candidate-verdict.txt")"
  echo "Live API candidate discovery failed (status=$status; $api_verdict)." >&2
  exit 1
fi
api_verdict="$(cat "$smoke_dir/api-candidate-verdict.txt")"
if [[ "$status" != "200" ]]; then
  echo "Live API candidate discovery failed (status=$status; $api_verdict)." >&2
  exit 1
fi
echo "Live API candidate discovery passed (status=200; $api_verdict)."

status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/dashboard.html" --write-out '%{http_code}' \
    "$web_base/"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Synthetic dashboard returned HTTP $status." >&2
  exit 1
fi

canonical_session="d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350"
status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/session.html" --write-out '%{http_code}' \
    "$web_base/sessions/$canonical_session"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Synthetic session detail returned HTTP $status." >&2
  exit 1
fi

DASHBOARD_HTML="$smoke_dir/dashboard.html" \
SESSION_HTML="$smoke_dir/session.html" \
CAPTURE_PROOF="$capture_proof" \
WORKER_PROOF="$worker_proof" \
REVIEWER_PROOF="$reviewer_proof" \
REVIEWER_SESSION="$reviewer_session" \
REVIEWER_CSRF="$reviewer_csrf" \
CANONICAL_SESSION="$canonical_session" \
python3 - <<'PY'
import os
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)


def visible_text(value):
    parser = VisibleTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(unescape(" ".join(parser.parts)).split())


dashboard = Path(os.environ["DASHBOARD_HTML"]).read_text(encoding="utf-8")
detail = Path(os.environ["SESSION_HTML"]).read_text(encoding="utf-8")
dashboard_visible = visible_text(dashboard)
detail_visible = visible_text(detail)
session_id = os.environ["CANONICAL_SESSION"]

dashboard_required = (
    ("hero", "Expert CAD workflow, made traceable."),
    ("sessions_metric", "CAD sessions"),
    ("machine_label", "synthetic-pilot-machine"),
    ("processed_metric", "processed"),
    ("active_review_metric", "Active review"),
    ("review_outcomes_metric", "Review outcomes"),
    ("approved_workflows_metric", "Approved workflows"),
    ("active_review_count", "1 candidate awaiting review · independent queue snapshot"),
    ("outcomes_empty_state", "No terminal outcomes recorded"),
    ("approved_empty_state", "No approved workflows yet"),
    ("candidate_review_link", "Review candidates"),
)
missing_dashboard_labels = tuple(
    label for label, value in dashboard_required if value not in dashboard_visible
)
if missing_dashboard_labels:
    raise SystemExit(
        "synthetic dashboard visible-text evidence missing labels: "
        + ", ".join(missing_dashboard_labels)
    )
if "Pending review" in dashboard_visible:
    raise SystemExit("synthetic dashboard retained the stale session review metric")
session_links = re.findall(r'href="/sessions/([0-9a-f-]{36})"', dashboard)
if session_links != [session_id]:
    raise SystemExit("synthetic dashboard did not expose exactly one canonical session")
if 'href="/candidate-review"' not in dashboard:
    raise SystemExit("synthetic dashboard did not link to candidate review")
if 'href="/approved-workflows"' not in dashboard:
    raise SystemExit("synthetic dashboard did not link to approved workflows")

detail_required = (
    session_id,
    "Meaningful operations",
    "8 meaningful operations from 8 observed events.",
    "Deterministic operation segments",
    "Segment 1",
    "Segment 4",
    "Commands: LINE",
    "Commands: TRIM",
    "Review candidates",
)
if any(value not in detail_visible for value in detail_required):
    raise SystemExit("synthetic v2 session detail evidence was incomplete")
if 'href="/candidate-review"' not in detail:
    raise SystemExit("synthetic session detail did not link to candidate review")

for html in (dashboard, detail):
    for value in (
        os.environ["CAPTURE_PROOF"],
        os.environ["WORKER_PROOF"],
        os.environ["REVIEWER_PROOF"],
        os.environ["REVIEWER_SESSION"],
        os.environ["REVIEWER_CSRF"],
        "publication_key",
        "review_target_id",
        "reason_code",
        "sha256",
    ):
        if value in html:
            raise SystemExit("session UI exposed private server evidence")
    if re.search(r"candidate-(?:publication|skill):", html, re.IGNORECASE):
        raise SystemExit("session UI exposed a raw candidate identifier")
PY
echo "Dashboard lifecycle pre-review passed: active=1, outcomes=0, approved=0."

status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/candidate.html" --write-out '%{http_code}' \
    "$web_base/candidate-review"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Candidate review page returned HTTP $status." >&2
  exit 1
fi

SMOKE_HTML="$smoke_dir/candidate.html" \
CAPTURE_PROOF="$capture_proof" \
WORKER_PROOF="$worker_proof" \
REVIEWER_PROOF="$reviewer_proof" \
REVIEWER_SESSION="$reviewer_session" \
REVIEWER_CSRF="$reviewer_csrf" \
python3 - <<'PY'
import os
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)


def visible_text(value):
    parser = VisibleTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(unescape(" ".join(parser.parts)).split())


probe = visible_text(
    "Candidate <!-- hidden -->1"
    "<script>Approve hidden-script</script>"
    "<style>Reject hidden-style</style>"
    "<!-- Candidate hidden-comment -->"
)
if probe != "Candidate 1":
    raise SystemExit("visible-text normalization self-test failed")

html = Path(os.environ["SMOKE_HTML"]).read_text(encoding="utf-8")
visible = visible_text(html)
required = (
    "Candidate review queue",
    "Candidates awaiting review",
    "Candidate 1",
    "LINE → TRIM → LINE → TRIM",
    "4",
    "observed / unreviewed",
    "Approve",
    "Start review",
)
if any(value not in visible for value in required):
    raise SystemExit(
        "live API candidate discovery passed; web redacted-view copy was incomplete"
    )
for unsupported_action in ("Reject", "Needs changes"):
    if unsupported_action in visible:
        raise SystemExit("candidate review page exposed an unsupported action")
for value in (
    os.environ["CAPTURE_PROOF"],
    os.environ["WORKER_PROOF"],
    os.environ["REVIEWER_PROOF"],
    os.environ["REVIEWER_SESSION"],
    os.environ["REVIEWER_CSRF"],
    "d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350",
    "publication_key",
    "review_target_id",
):
    if value in html:
        raise SystemExit("candidate review page exposed private server evidence")
if re.search(r"candidate-(?:publication|skill):", html, re.IGNORECASE):
    raise SystemExit("candidate review page exposed a raw candidate identifier")
if re.search(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    html,
    re.IGNORECASE,
):
    raise SystemExit("candidate review page exposed a UUID")
if re.search(r"\b[a-f0-9]{64}\b", html, re.IGNORECASE):
    raise SystemExit("candidate review page exposed a digest")
PY

if [[ "$smoke_scenario" == "approved" ]]; then
  action_body='ordinal=1&action=approve'
  status="$({
    curl --silent --show-error --max-time 10 --max-redirs 0 \
      --dump-header "$smoke_dir/approved.headers" \
      --output "$smoke_dir/approved.body" --write-out '%{http_code}' \
      --request POST "$web_base/candidate-review/action" \
      --header "Host: 127.0.0.1:$web_port" \
      --header "Origin: http://127.0.0.1:$web_port" \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-binary "$action_body"
  } || true)"
  if [[ "$status" != "303" || -s "$smoke_dir/approved.body" ]]; then
    echo "Approved review action did not return the fixed bodyless 303." >&2
    exit 1
  fi

  status="$({
    curl --silent --show-error --max-time 10 \
      --output "$smoke_dir/approved-empty.html" --write-out '%{http_code}' \
      "$web_base/candidate-review"
  } || true)"
  if [[ "$status" != "200" ]]; then
    echo "Approved candidate page returned HTTP $status." >&2
    exit 1
  fi
  status="$({
    curl --silent --show-error --max-time 10 \
      --output "$smoke_dir/approved-dashboard.html" --write-out '%{http_code}' \
      "$web_base/"
  } || true)"
  if [[ "$status" != "200" ]]; then
    echo "Approved dashboard returned HTTP $status." >&2
    exit 1
  fi
  status="$({
    curl --silent --show-error --max-time 10 \
      --output "$smoke_dir/approved-catalog.html" --write-out '%{http_code}' \
      "$web_base/approved-workflows"
  } || true)"
  if [[ "$status" != "200" ]]; then
    echo "Approved workflow catalog returned HTTP $status." >&2
    exit 1
  fi
  status="$({
    curl --silent --show-error --max-time 10 --max-redirs 0 \
      --dump-header "$smoke_dir/download.headers" \
      --output "$smoke_dir/download.json" --write-out '%{http_code}' \
      "$web_base/approved-workflows/download?ordinal=1" \
      --header "Host: 127.0.0.1:$web_port"
  } || true)"
  if [[ "$status" != "200" ]]; then
    echo "Approved workflow download returned HTTP $status." >&2
    exit 1
  fi

  APPROVED_EMPTY_HTML="$smoke_dir/approved-empty.html" \
  APPROVED_DASHBOARD_HTML="$smoke_dir/approved-dashboard.html" \
  APPROVED_CATALOG_HTML="$smoke_dir/approved-catalog.html" \
  DOWNLOAD_HEADERS="$smoke_dir/download.headers" \
  DOWNLOAD_JSON="$smoke_dir/download.json" \
  CAPTURE_PROOF="$capture_proof" \
  WORKER_PROOF="$worker_proof" \
  REVIEWER_PROOF="$reviewer_proof" \
  REVIEWER_SESSION="$reviewer_session" \
  REVIEWER_CSRF="$reviewer_csrf" \
  python3 - <<'PY'
import json
import os
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)


def visible_text(value):
    parser = VisibleTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(unescape(" ".join(parser.parts)).split())


empty_html = Path(os.environ["APPROVED_EMPTY_HTML"]).read_text(encoding="utf-8")
approved_dashboard_html = Path(os.environ["APPROVED_DASHBOARD_HTML"]).read_text(encoding="utf-8")
catalog_html = Path(os.environ["APPROVED_CATALOG_HTML"]).read_text(encoding="utf-8")
empty_visible = visible_text(empty_html)
approved_dashboard_visible = visible_text(approved_dashboard_html)
catalog_visible = visible_text(catalog_html)
for expected in (
    "Active review",
    "Review outcomes",
    "Approved workflows",
    "No candidates awaiting review",
    "1 terminal outcome · independent outcomes snapshot",
    "1 approved workflow · derived from outcomes snapshot",
):
    if expected not in approved_dashboard_visible:
        raise SystemExit("approved dashboard lifecycle counts were incomplete")
if (
    "No candidates awaiting review." not in empty_visible
    or "approved" not in empty_visible
    or "No reason code" not in empty_visible
):
    raise SystemExit("approved decision did not leave an empty active queue")
for expected in (
    "Approved workflows",
    "Approved workflow 1",
    "LINE → TRIM → LINE → TRIM",
    "observed / approved",
    "Download JSON",
):
    if expected not in catalog_visible:
        raise SystemExit("approved workflow catalog visible evidence was incomplete")

headers = Path(os.environ["DOWNLOAD_HEADERS"]).read_text(encoding="iso-8859-1")
header_values = {}
for line in headers.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        header_values.setdefault(name.casefold(), []).append(value.strip())
expected_headers = {
    "cache-control": ["no-store"],
    "content-disposition": ['attachment; filename="approved-workflow.json"'],
    "content-type": ["application/json; charset=utf-8"],
    "referrer-policy": ["no-referrer"],
    "x-content-type-options": ["nosniff"],
}
for name, expected in expected_headers.items():
    if header_values.get(name) != expected:
        raise SystemExit("approved workflow download headers were not exact")

download_path = Path(os.environ["DOWNLOAD_JSON"])
raw = download_path.read_bytes()
if not raw.endswith(b"\n") or len(raw) > 65_536:
    raise SystemExit("approved workflow download bytes were not bounded")
if header_values.get("content-length") != [str(len(raw))]:
    raise SystemExit("approved workflow download length was not exact")
payload = json.loads(raw.decode("utf-8"))
if (
    set(payload) != {
        "schema",
        "version",
        "command_sequence",
        "occurrence_count",
        "provenance",
        "approval_status",
        "decided_at",
    }
    or payload.get("schema") != "workflow-helper.approved-workflow"
    or payload.get("version") != "1.0"
    or payload.get("command_sequence") != ["LINE", "TRIM", "LINE", "TRIM"]
    or payload.get("occurrence_count") != 4
    or payload.get("provenance") != "observed"
    or payload.get("approval_status") != "approved"
    or type(payload.get("decided_at")) is not str
    or "reason_code" in payload
):
    raise SystemExit("approved workflow download schema was not exact")
if "reason_code" in catalog_html or b"reason_code" in raw:
    raise SystemExit("approved workflow catalog or export exposed a reason code")

for surface in (empty_html, catalog_html, raw.decode("utf-8")):
    for value in (
        os.environ["CAPTURE_PROOF"],
        os.environ["WORKER_PROOF"],
        os.environ["REVIEWER_PROOF"],
        os.environ["REVIEWER_SESSION"],
        os.environ["REVIEWER_CSRF"],
        "publication_key",
        "review_target_id",
        "reason_code",
        "sha256",
    ):
        if value in surface:
            raise SystemExit("approved workflow surface exposed private server evidence")
    if re.search(r"candidate-(?:publication|skill):", surface, re.IGNORECASE):
        raise SystemExit("approved workflow surface exposed a raw candidate identifier")
    if re.search(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        surface,
        re.IGNORECASE,
    ):
        raise SystemExit("approved workflow surface exposed a UUID")
    if re.search(r"\b[a-f0-9]{64}\b", surface, re.IGNORECASE):
        raise SystemExit("approved workflow surface exposed a digest")
for value in (
    os.environ["CAPTURE_PROOF"],
    os.environ["WORKER_PROOF"],
    os.environ["REVIEWER_PROOF"],
    os.environ["REVIEWER_SESSION"],
    os.environ["REVIEWER_CSRF"],
    "publication_key",
    "review_target_id",
    "reason_code",
    "sha256",
):
    if value in approved_dashboard_html:
        raise SystemExit("approved dashboard exposed private server evidence")
if re.search(r"candidate-(?:publication|skill):", approved_dashboard_html, re.IGNORECASE):
    raise SystemExit("approved dashboard exposed a raw candidate identifier")
PY
  approved_decided_at="$(DOWNLOAD_JSON="$smoke_dir/download.json" python3 - <<'PY'
import json
import os
from pathlib import Path

print(json.loads(Path(os.environ["DOWNLOAD_JSON"]).read_text(encoding="utf-8"))["decided_at"])
PY
)"

  if ! "${compose[@]}" run --rm --no-deps -T \
    -e "EXPECTED_DECIDED_AT=$approved_decided_at" seed python - \
    >"$smoke_dir/independent-approved-verify.log" <<'PY'
import runpy
from datetime import UTC, datetime

from workflow_api import dev_server

seed = runpy.run_path("/workspace/dev-runtime-seed.py")
driver = seed["_ASGIDriver"](dev_server.open_existing_app())
headers = seed["_reviewer_headers"]()
queue = driver.request(
    "GET",
    "/v1/control/candidate-publications/review-queue",
    headers=headers,
)
outcomes = driver.request(
    "GET",
    "/v1/control/candidate-publications/review-outcomes",
    headers=headers,
)
queue_payload = queue.json()
outcome_payload = outcomes.json()
item = outcome_payload.get("items", [None])[0]
if (
    queue.status != 200
    or queue_payload != {"items": [], "count": 0}
    or outcomes.status != 200
    or type(outcome_payload) is not dict
    or set(outcome_payload) != {"items", "count"}
    or outcome_payload.get("count") != 1
    or type(item) is not dict
    or set(item) != {
        "command_sequence",
        "occurrence_count",
        "provenance",
        "review_status",
        "reason_code",
        "decided_at_us",
    }
    or item.get("command_sequence") != ["LINE", "TRIM", "LINE", "TRIM"]
    or item.get("occurrence_count") != 4
    or item.get("provenance") != "observed"
    or item.get("review_status") != "approved"
    or item.get("reason_code") is not None
    or type(item.get("decided_at_us")) is not int
    or item["decided_at_us"] <= 0
):
    raise SystemExit("independent approved workflow verification failed")
expected = (
    datetime.fromtimestamp(item["decided_at_us"] / 1_000_000, tz=UTC)
    .isoformat(timespec="milliseconds")
    .replace("+00:00", "Z")
)
if expected != __import__("os").environ.get("EXPECTED_DECIDED_AT"):
    raise SystemExit("independent approved decision time verification failed")
print("synthetic approved workflow durability verified")
PY
  then
    echo "Independent approved workflow durability verification failed." >&2
    exit 1
  fi
  if [[ "$(cat "$smoke_dir/independent-approved-verify.log")" != "synthetic approved workflow durability verified" ]]; then
    echo "Independent approved workflow durability verification was not exact." >&2
    exit 1
  fi
  echo "Synthetic approved-workflow smoke passed: dashboard active=0, outcomes=1, approved=1; durable approval, safe catalog export, and independent reopen."
  exit 0
fi

action_body='ordinal=1&action=start_review'
status="$({
  curl --silent --show-error --max-time 10 --max-redirs 0 \
    --dump-header "$smoke_dir/action.headers" \
    --output "$smoke_dir/action.body" --write-out '%{http_code}' \
    --request POST "$web_base/candidate-review/action" \
    --header "Host: 127.0.0.1:$web_port" \
    --header "Origin: http://127.0.0.1:$web_port" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary "$action_body"
} || true)"
if [[ "$status" != "303" || -s "$smoke_dir/action.body" ]]; then
  echo "Candidate review action did not return the fixed bodyless 303." >&2
  exit 1
fi
ACTION_HEADERS="$smoke_dir/action.headers" python3 - <<'PY'
import os
from pathlib import Path

headers = Path(os.environ["ACTION_HEADERS"]).read_text(encoding="iso-8859-1")
locations = [
    line.split(":", 1)[1].strip()
    for line in headers.splitlines()
    if line.lower().startswith("location:")
]
if locations != ["/candidate-review"]:
    raise SystemExit("candidate review redirect was not exact")
PY

status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/pending.html" --write-out '%{http_code}' \
    "$web_base/candidate-review"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Pending candidate page returned HTTP $status." >&2
  exit 1
fi
PENDING_HTML="$smoke_dir/pending.html" \
CAPTURE_PROOF="$capture_proof" \
WORKER_PROOF="$worker_proof" \
REVIEWER_PROOF="$reviewer_proof" \
REVIEWER_SESSION="$reviewer_session" \
REVIEWER_CSRF="$reviewer_csrf" \
python3 - <<'PY'
import os
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)


parser = VisibleTextParser()
html = Path(os.environ["PENDING_HTML"]).read_text(encoding="utf-8")
parser.feed(html)
parser.close()
visible = " ".join(unescape(" ".join(parser.parts)).split())
for value in (
    "Candidate 1",
    "observed / pending",
    "Approve",
    "Reject",
    "Needs changes",
    "Reject reason",
    "Changes reason",
    "Sequence mismatch",
    "Insufficient evidence",
):
    if value not in visible:
        raise SystemExit("pending candidate controls were incomplete")
if "Start review" in visible:
    raise SystemExit("pending candidate exposed an illegal repeated start action")
for value in (
    os.environ["CAPTURE_PROOF"],
    os.environ["WORKER_PROOF"],
    os.environ["REVIEWER_PROOF"],
    os.environ["REVIEWER_SESSION"],
    os.environ["REVIEWER_CSRF"],
    "publication_key",
    "review_target_id",
):
    if value in html:
        raise SystemExit("pending candidate page exposed private server evidence")
if re.search(r"candidate-(?:publication|skill):", html, re.IGNORECASE):
    raise SystemExit("pending candidate page exposed a raw candidate identifier")
if re.search(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    html,
    re.IGNORECASE,
):
    raise SystemExit("pending candidate page exposed a UUID")
if re.search(r"\b[a-f0-9]{64}\b", html, re.IGNORECASE):
    raise SystemExit("pending candidate page exposed a digest")
PY

# This synchronous no-port harness is the quiescent durability window.  It
# must exit successfully before the live web/API is allowed to mutate again.
if ! "${compose[@]}" run --rm --no-deps -T seed python - \
  >"$smoke_dir/independent-pending-verify.log" <<'PY'
import runpy

from workflow_api import dev_server

seed = runpy.run_path("/workspace/dev-runtime-seed.py")
driver = seed["_ASGIDriver"](dev_server.open_existing_app())
response = driver.request(
    "GET",
    "/v1/control/candidate-publications/review-queue",
    headers=seed["_reviewer_headers"](),
)
payload = response.json()
if (
    response.status != 200
    or type(payload) is not dict
    or set(payload) != {"items", "count"}
    or payload.get("count") != 1
    or type(payload.get("items")) is not list
    or len(payload["items"]) != 1
    or type(payload["items"][0]) is not dict
    or set(payload["items"][0]) != {
        "publication_key",
        "review_target_id",
        "command_sequence",
        "occurrence_count",
        "provenance",
        "review_status",
        "finalized_at_us",
    }
    or payload["items"][0].get("review_status") != "pending"
):
    raise SystemExit("independent pending verification failed")
print("synthetic pending candidate durability verified")
PY
then
  echo "Independent pending candidate durability verification failed." >&2
  exit 1
fi
if [[ "$(cat "$smoke_dir/independent-pending-verify.log")" != "synthetic pending candidate durability verified" ]]; then
  echo "Independent pending candidate durability verification was not exact." >&2
  exit 1
fi

action_body='ordinal=1&reason_code=evidence&action=needs_changes'
status="$({
  curl --silent --show-error --max-time 10 --max-redirs 0 \
    --dump-header "$smoke_dir/terminal.headers" \
    --output "$smoke_dir/terminal.body" --write-out '%{http_code}' \
    --request POST "$web_base/candidate-review/action" \
    --header "Host: 127.0.0.1:$web_port" \
    --header "Origin: http://127.0.0.1:$web_port" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary "$action_body"
} || true)"
if [[ "$status" != "303" || -s "$smoke_dir/terminal.body" ]]; then
  echo "Terminal review action did not return the fixed bodyless 303." >&2
  exit 1
fi
TERMINAL_HEADERS="$smoke_dir/terminal.headers" python3 - <<'PY'
import os
from pathlib import Path

headers = Path(os.environ["TERMINAL_HEADERS"]).read_text(encoding="iso-8859-1")
locations = [
    line.split(":", 1)[1].strip()
    for line in headers.splitlines()
    if line.lower().startswith("location:")
]
if locations != ["/candidate-review"]:
    raise SystemExit("terminal review redirect was not exact")
PY

status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/empty.html" --write-out '%{http_code}' \
    "$web_base/candidate-review"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Reviewed candidate page returned HTTP $status." >&2
  exit 1
fi
status="$({
  curl --silent --show-error --max-time 10 \
    --output "$smoke_dir/post-review-dashboard.html" --write-out '%{http_code}' \
    "$web_base/"
} || true)"
if [[ "$status" != "200" ]]; then
  echo "Post-review dashboard returned HTTP $status." >&2
  exit 1
fi
POST_REVIEW_DASHBOARD_HTML="$smoke_dir/post-review-dashboard.html" \
CAPTURE_PROOF="$capture_proof" \
WORKER_PROOF="$worker_proof" \
REVIEWER_PROOF="$reviewer_proof" \
REVIEWER_SESSION="$reviewer_session" \
REVIEWER_CSRF="$reviewer_csrf" \
python3 - <<'PY'
import os
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)


def visible_text(value):
    parser = VisibleTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(unescape(" ".join(parser.parts)).split())


html = Path(os.environ["POST_REVIEW_DASHBOARD_HTML"]).read_text(encoding="utf-8")
visible = visible_text(html)
for expected in (
    "Active review",
    "Review outcomes",
    "Approved workflows",
    "No candidates awaiting review",
    "1 terminal outcome · independent outcomes snapshot",
    "No approved workflows yet",
):
    if expected not in visible:
        raise SystemExit("post-review dashboard lifecycle counts were incomplete")
if "1 candidate awaiting review" in visible:
    raise SystemExit("post-review dashboard retained an active candidate")
for value in (
    os.environ["CAPTURE_PROOF"],
    os.environ["WORKER_PROOF"],
    os.environ["REVIEWER_PROOF"],
    os.environ["REVIEWER_SESSION"],
    os.environ["REVIEWER_CSRF"],
    "publication_key",
    "review_target_id",
    "reason_code",
    "sha256",
):
    if value in html:
        raise SystemExit("post-review dashboard exposed private server evidence")
if re.search(r"candidate-(?:publication|skill):", html, re.IGNORECASE):
    raise SystemExit("post-review dashboard exposed a raw candidate identifier")
PY
EMPTY_HTML="$smoke_dir/empty.html" \
CAPTURE_PROOF="$capture_proof" \
WORKER_PROOF="$worker_proof" \
REVIEWER_PROOF="$reviewer_proof" \
REVIEWER_SESSION="$reviewer_session" \
REVIEWER_CSRF="$reviewer_csrf" \
python3 - <<'PY'
import os
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.casefold() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)


def visible_text(value):
    parser = VisibleTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(unescape(" ".join(parser.parts)).split())


html = Path(os.environ["EMPTY_HTML"]).read_text(encoding="utf-8")
visible = visible_text(html)
for expected in (
    "No candidates awaiting review.",
    "Review outcomes",
    "Outcome 1",
    "LINE → TRIM → LINE → TRIM",
    "needs_changes",
    "Insufficient evidence",
):
    if expected not in visible:
        raise SystemExit("terminal outcome was not visible")
if "Candidate 1" in visible:
    raise SystemExit("reviewed candidate remained visible")
for value in (
    os.environ["CAPTURE_PROOF"],
    os.environ["WORKER_PROOF"],
    os.environ["REVIEWER_PROOF"],
    os.environ["REVIEWER_SESSION"],
    os.environ["REVIEWER_CSRF"],
    "publication_key",
    "review_target_id",
):
    if value in html:
        raise SystemExit("terminal outcome page exposed private server evidence")
if re.search(r"candidate-(?:publication|skill):", html, re.IGNORECASE):
    raise SystemExit("empty candidate page exposed a raw candidate identifier")
if re.search(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    html,
    re.IGNORECASE,
):
    raise SystemExit("empty candidate page exposed a UUID")
if re.search(r"\b[a-f0-9]{64}\b", html, re.IGNORECASE):
    raise SystemExit("empty candidate page exposed a digest")
PY

if ! "${compose[@]}" run --rm --no-deps -T seed python - \
  >"$smoke_dir/independent-outcome-verify.log" <<'PY'
import runpy

from workflow_api import dev_server
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole

seed = runpy.run_path("/workspace/dev-runtime-seed.py")
application = dev_server.open_existing_app()
driver = seed["_ASGIDriver"](application)
response = driver.request(
    "GET",
    "/v1/control/candidate-publications/review-outcomes",
    headers=seed["_reviewer_headers"](),
)
payload = response.json()
expected_item = {
    "command_sequence",
    "occurrence_count",
    "provenance",
    "review_status",
    "reason_code",
    "decided_at_us",
}
if (
    response.status != 200
    or type(payload) is not dict
    or set(payload) != {"items", "count"}
    or payload.get("count") != 1
    or type(payload.get("items")) is not list
    or len(payload["items"]) != 1
    or type(payload["items"][0]) is not dict
    or set(payload["items"][0]) != expected_item
    or payload["items"][0].get("command_sequence") != ["LINE", "TRIM", "LINE", "TRIM"]
    or payload["items"][0].get("occurrence_count") != 4
    or payload["items"][0].get("provenance") != "observed"
    or payload["items"][0].get("review_status") != "needs_changes"
    or payload["items"][0].get("reason_code") != "evidence"
    or type(payload["items"][0].get("decided_at_us")) is not int
    or payload["items"][0]["decided_at_us"] <= 0
):
    raise SystemExit("independent terminal outcome verification failed")
bundle = application.state.runtime_bundle
store = bundle.candidate_publication_store
if store is None:
    raise SystemExit("private terminal reason verification failed")
records = store.list_finalized(dev_server._SCOPE, limit=100)
if len(records) != 1:
    raise SystemExit("private terminal reason verification failed")
principal = AuthenticatedPrincipal(
    "reviewer_synthetic",
    frozenset({ControlRole.REVIEWER}),
    dev_server._SCOPE,
)
projection = bundle.control_service.read_candidate_review(
    principal,
    review_target_id=records[0].review_target_id,
    correlation_id="smoke-private-reason-verification",
)
if (
    projection is None
    or projection.status != "needs_changes"
    or projection.detail.get("reason") != "Synthetic observed evidence is insufficient."
    or projection.detail.get("evidence") != {"reason_code": "evidence"}
):
    raise SystemExit("private terminal reason verification failed")
print("synthetic terminal outcome durability verified")
PY
then
  echo "Independent terminal outcome durability verification failed." >&2
  exit 1
fi
if [[ "$(cat "$smoke_dir/independent-outcome-verify.log")" != "synthetic terminal outcome durability verified" ]]; then
  echo "Independent terminal outcome durability verification was not exact." >&2
  exit 1
fi

"${compose[@]}" run --rm --no-deps seed \
  python /workspace/dev-runtime-seed.py --verify-empty \
  >"$smoke_dir/independent-verify.log"
if [[ "$(cat "$smoke_dir/independent-verify.log")" != "synthetic candidate durability verified" ]]; then
  echo "Independent existing-runtime verification failed." >&2
  exit 1
fi

echo "Synthetic dev-runtime smoke passed: dashboard active=0, outcomes=1, approved=0; v2 seed, independent pending reopen, durable terminal outcome, and empty active queue reopen."
