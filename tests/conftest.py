"""Shared pytest fixtures.

The whole suite runs offline and deterministically — no network, no API key —
because the heuristic provider is the default triage path. That is a deliberate
property: CI must be able to prove the pipeline works without secrets.
"""

from __future__ import annotations

import datetime as dt

import pytest

from socrepo.models import Alert, SigmaLevel, SigmaRule


@pytest.fixture
def make_alert():
    """Factory for Alerts with sensible defaults; override per test."""

    def _make(**kw) -> Alert:
        base = {
            "id": "ALRT-TEST",
            "timestamp": dt.datetime(2024, 11, 4, 9, 0, tzinfo=dt.UTC),
            "rule_id": "100200",
            "rule_title": "Test Rule",
            "level": SigmaLevel.HIGH,
            "technique_id": "T1105",
            "host": "WKS-1",
            "user": "corp\\user",
            "image": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c echo hi",
            "parent_image": "C:\\Windows\\explorer.exe",
            "parent_command_line": None,
            "signed": True,
        }
        base.update(kw)
        return Alert.model_validate(base)

    return _make


@pytest.fixture
def certutil_rule() -> SigmaRule:
    """A minimal, compilable Sigma rule (certutil download)."""
    return SigmaRule.model_validate(
        {
            "title": "Certutil Download",
            "id": "00000000-0000-0000-0000-000000000001",
            "status": "test",
            "level": "high",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "Image|endswith": "\\certutil.exe",
                    "CommandLine|contains": "-urlcache",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1105"],
        }
    )
