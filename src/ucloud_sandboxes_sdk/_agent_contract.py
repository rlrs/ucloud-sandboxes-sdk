from __future__ import annotations

from typing import Any, Mapping


def require_agent_sandbox_record(
    record: Mapping[str, Any],
    *,
    require_generation: bool = False,
) -> int | None:
    """Validate the one SDK/relay contract for a checkpoint-aware agent."""

    spec = record.get("spec")
    if not isinstance(spec, Mapping):
        if require_generation:
            raise ValueError("agent sandbox record has no sandbox spec")
        return None
    if spec.get("parkable") is not True or spec.get("managed_process") is not True:
        raise ValueError(
            "agent sandboxes require parkable=True and managed_process=True"
        )
    generation = record.get("generation")
    if require_generation and (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation <= 0
    ):
        raise ValueError("agent sandbox record has no positive generation")
    return (
        generation
        if isinstance(generation, int) and not isinstance(generation, bool)
        else None
    )
