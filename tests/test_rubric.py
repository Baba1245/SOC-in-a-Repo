"""Rubric parsing: model output is untrusted and must be coerced or rejected.

The LLM (and any future provider) returns free-form text. ``parse_result`` is
the boundary that turns that into a validated ``TriageResult`` or raises — so
these tests cover the messy-but-recoverable cases (code fences, prose around the
JSON, out-of-range confidence) and the genuinely-broken ones (bad enum, no JSON).
"""

from __future__ import annotations

import pytest

from socrepo.models import NextAction, Verdict
from socrepo.triage.rubric import RubricParseError, contract_json, parse_result


def test_parse_plain_json():
    raw = (
        '{"verdict": "true_positive", "confidence": 0.9, '
        '"next_action": "escalate", "rationale": "lsass dump", '
        '"key_indicators": ["lsass", "procdump"]}'
    )
    r = parse_result(raw, alert_id="A1", provider="anthropic", model="m")
    assert r.verdict is Verdict.TRUE_POSITIVE
    assert r.next_action is NextAction.ESCALATE
    assert r.confidence == 0.9
    assert r.key_indicators == ["lsass", "procdump"]
    assert r.provider == "anthropic"


def test_parse_tolerates_code_fence_and_prose():
    raw = (
        "Here is my assessment:\n"
        "```json\n"
        '{"verdict": "false_positive", "confidence": 0.8, '
        '"next_action": "close", "rationale": "signed vendor tool"}\n'
        "```\n"
        "Let me know if you need more."
    )
    r = parse_result(raw, alert_id="A2", provider="anthropic")
    assert r.verdict is Verdict.FALSE_POSITIVE
    assert r.next_action is NextAction.CLOSE


def test_confidence_is_clamped_into_unit_interval():
    raw = (
        '{"verdict": "benign_suspicious", "confidence": 1.7, '
        '"next_action": "monitor"}'
    )
    r = parse_result(raw, alert_id="A3", provider="heuristic")
    assert r.confidence == 1.0


def test_dict_input_is_accepted_directly():
    data = {
        "verdict": "benign_suspicious",
        "confidence": 0.5,
        "next_action": "hunt",
        "key_indicators": "single-string-coerced-to-list",
    }
    r = parse_result(data, alert_id="A4", provider="heuristic")
    assert r.key_indicators == ["single-string-coerced-to-list"]


def test_bad_verdict_enum_raises():
    raw = '{"verdict": "definitely_bad", "confidence": 0.5, "next_action": "close"}'
    with pytest.raises(RubricParseError):
        parse_result(raw, alert_id="A5", provider="anthropic")


def test_missing_json_raises():
    with pytest.raises(RubricParseError):
        parse_result("I could not decide.", alert_id="A6", provider="anthropic")


def test_contract_json_is_valid_json():
    import json

    parsed = json.loads(contract_json())
    assert set(parsed) >= {"verdict", "confidence", "next_action"}
