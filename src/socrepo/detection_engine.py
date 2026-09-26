"""Evaluate compiled Wazuh rules against process-creation events in memory.

Why this exists
---------------
The validation half of the coverage matrix is only meaningful if it is computed
by *running the detections*, not by hand-asserting "this fired". This engine
applies the exact PCRE2 field patterns produced by the Sigma compiler to
representative telemetry, so ``validated`` reflects whether a rule genuinely
matches the events an atomic generates.

It is a faithful-enough model of Wazuh field matching for process-creation
events (AND across ``<field>`` tags, case-insensitive PCRE2). It is not a Wazuh
replacement — the real pipeline still runs in the container stack.
"""

from __future__ import annotations

import re
from typing import Any

from .models import WazuhRule
from .sigma_compiler import FIELD_MAP

# Wazuh field name -> Sigma/event field name (inverse of the compiler map).
_INVERSE_FIELD_MAP: dict[str, str] = {v: k for k, v in FIELD_MAP.items()}


def _event_value(event: dict[str, Any], wazuh_field: str) -> str | None:
    """Fetch the value for a Wazuh field from a Sigma-style event dict."""
    sigma_field = _INVERSE_FIELD_MAP.get(wazuh_field)
    if sigma_field is None:
        return None
    val = event.get(sigma_field)
    return None if val is None else str(val)


def rule_matches(rule: WazuhRule, event: dict[str, Any]) -> bool:
    """True iff every field condition in ``rule`` matches ``event`` (AND)."""
    for wazuh_field, patterns in rule.field_matches.items():
        value = _event_value(event, wazuh_field)
        if value is None:
            return False
        for pattern in patterns:
            if re.search(pattern, value) is None:
                return False
    return True


def match_event(rules: list[WazuhRule], event: dict[str, Any]) -> list[int]:
    """Return the ids of all rules that match a single event."""
    return [r.rule_id for r in rules if rule_matches(r, event)]
