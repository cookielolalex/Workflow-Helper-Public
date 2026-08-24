"""Pure internal-coherence checks for structurally admitted candidate skills."""

from __future__ import annotations

from typing import Any


def validate_candidate_skill_internal_coherence(candidate: dict[str, Any]) -> None:
    """Reject cross-field contradictions in a bounded, contract-valid candidate."""

    _require_unique_names(candidate["inputs"], "input")
    parameter_names = _require_unique_names(candidate["parameters"], "parameter")

    for index, action in enumerate(candidate["ordered_actions"], start=1):
        if action["sequence"] != index:
            raise ValueError(
                "ordered action sequences must equal 1..N in array order"
            )
        for parameter_name in action["parameter_names"]:
            if parameter_name not in parameter_names:
                raise ValueError(
                    "ordered action parameter reference must resolve exactly one "
                    f"declared parameter: {parameter_name}"
                )


def _require_unique_names(items: list[dict[str, Any]], kind: str) -> set[str]:
    names: set[str] = set()
    for item in items:
        name = item["name"]
        if name in names:
            raise ValueError(f"{kind} names must be unique: {name}")
        names.add(name)
    return names
