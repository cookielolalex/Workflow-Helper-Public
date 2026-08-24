import json
from pathlib import Path

import pytest

from workflow_api.candidate_skill_semantics import (
    validate_candidate_skill_internal_coherence,
)

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "contracts/examples/candidate-skill-unreviewed.json"


def _candidate() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(_candidate(), id="existing-v1-fixture"),
        pytest.param(
            {
                **_candidate(),
                "parameters": [],
                "ordered_actions": [
                    {
                        "sequence": 1,
                        "instruction": "Perform a parameter-free action.",
                        "parameter_names": [],
                    }
                ],
            },
            id="empty-parameters-and-references",
        ),
        pytest.param(
            {
                **_candidate(),
                "inputs": [
                    {
                        "name": f"input_{index}",
                        "kind": "parameter",
                        "description": "Synthetic bounded input.",
                        "required": True,
                    }
                    for index in range(64)
                ],
                "parameters": [
                    {
                        "name": f"parameter_{index}",
                        "value": index,
                        "unit": None,
                        "provenance": "deterministic",
                    }
                    for index in range(128)
                ],
                "ordered_actions": [
                    {
                        "sequence": index,
                        "instruction": "Perform a synthetic bounded action.",
                        "parameter_names": [f"parameter_{(index - 1) % 128}"],
                    }
                    for index in range(1, 257)
                ],
            },
            id="contract-bounds",
        ),
    ],
)
def test_valid_internal_coherence(candidate: dict[str, object]) -> None:
    assert validate_candidate_skill_internal_coherence(candidate) is None


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        pytest.param(
            lambda value: value["ordered_actions"][1].__setitem__("sequence", 1),
            "sequences must equal 1..N",
            id="duplicate-sequence",
        ),
        pytest.param(
            lambda value: value["ordered_actions"].reverse(),
            "sequences must equal 1..N",
            id="out-of-order-sequence",
        ),
        pytest.param(
            lambda value: value["ordered_actions"][1].__setitem__("sequence", 3),
            "sequences must equal 1..N",
            id="gapped-sequence",
        ),
        pytest.param(
            lambda value: value["inputs"].append(dict(value["inputs"][0])),
            "input names must be unique",
            id="duplicate-input-name",
        ),
        pytest.param(
            lambda value: value["parameters"].append(
                dict(value["parameters"][0])
            ),
            "parameter names must be unique",
            id="duplicate-parameter-name",
        ),
        pytest.param(
            lambda value: value["ordered_actions"][0]["parameter_names"].append(
                "undeclared_parameter"
            ),
            "must resolve exactly one declared parameter: undeclared_parameter",
            id="undeclared-parameter-reference",
        ),
    ],
)
def test_invalid_internal_coherence(mutator, message: str) -> None:
    candidate = _candidate()
    mutator(candidate)

    with pytest.raises(ValueError, match=message):
        validate_candidate_skill_internal_coherence(candidate)
