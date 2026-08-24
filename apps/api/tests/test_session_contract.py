import json
from pathlib import Path


def test_session_contract_requires_workflow_state_fields() -> None:
    contract_path = Path(__file__).resolve().parents[3] / "contracts" / "session.schema.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    assert {
        "active_duration_seconds",
        "approved_process",
        "review_status",
    } <= set(contract["required"])
