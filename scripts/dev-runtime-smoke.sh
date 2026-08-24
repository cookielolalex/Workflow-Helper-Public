#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/workflow-helper-dev-smoke.XXXXXX")"
runtime_env="$smoke_dir/.env"
project_name="workflow-helper-p3b-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
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
  if (( status != 0 )); then
    echo "Synthetic dev-runtime smoke failed; collecting bounded diagnostics." >&2
    "${compose[@]}" ps >&2 || true
    "${compose[@]}" logs --no-color api seed web >&2 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$smoke_dir"
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
    "Expert CAD workflow, made traceable.",
    "CAD sessions",
    "synthetic-pilot-machine",
    "processed",
    "pending",
    "Review candidates",
)
if any(value not in dashboard_visible for value in dashboard_required):
    raise SystemExit("synthetic dashboard visible-text evidence was incomplete")
session_links = re.findall(r'href="/sessions/([0-9a-f-]{36})"', dashboard)
if session_links != [session_id]:
    raise SystemExit("synthetic dashboard did not expose exactly one canonical session")
if 'href="/candidate-review"' not in dashboard:
    raise SystemExit("synthetic dashboard did not link to candidate review")

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
    ):
        if value in html:
            raise SystemExit("session UI exposed private server evidence")
    if re.search(r"candidate-(?:publication|skill):", html, re.IGNORECASE):
        raise SystemExit("session UI exposed a raw candidate identifier")
PY

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

action_body='ordinal=1&action=needs_changes'
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

seed = runpy.run_path("/workspace/dev-runtime-seed.py")
driver = seed["_ASGIDriver"](dev_server.open_existing_app())
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
    or type(payload["items"][0].get("decided_at_us")) is not int
    or payload["items"][0]["decided_at_us"] <= 0
):
    raise SystemExit("independent terminal outcome verification failed")
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

echo "Synthetic dev-runtime smoke passed: v2 seed, independent pending reopen, durable terminal outcome, and empty active queue reopen."
