"""Detection engine — scans request inputs against the signature patterns."""

from __future__ import annotations

from typing import Any

from .patterns import RULES


def inspect_inputs(inputs: dict[str, Any]) -> dict[str, str] | None:
    """Check every input value against every attack pattern.

    Args:
        inputs: Flat mapping of field name -> value, gathered from a
            request's query string, form data, and JSON body.

    Returns:
        None if nothing matched, otherwise a dict describing the first
        match found: {"attack": ..., "field": ..., "value": ...}.
    """
    for field, value in inputs.items():
        if value is None:
            continue
        text = str(value)

        for attack_name, patterns in RULES:
            for pattern in patterns:
                if pattern.search(text):
                    return {
                        "attack": attack_name,
                        "field": field,
                        "value": text,
                        "matched_pattern": pattern.pattern,
                    }

    return None
