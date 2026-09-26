"""Compiler tests, including the property that unsupported rules are *reported*.

The most important invariant here is negative: a rule the compiler cannot handle
must be surfaced in ``report.skipped``, never silently dropped and never emitted
as a half-working rule. Silent partial compilation inflates coverage, which is
the one thing this whole project exists to avoid.
"""

from __future__ import annotations

import pytest

from socrepo.models import SigmaRule
from socrepo.sigma_compiler import (
    SigmaCompileError,
    compile_directory,
    compile_rule,
    render_rule_xml,
)
from socrepo.utils import DETECTIONS_DIR


def _rule(detection: dict, *, tags=None, level="high") -> SigmaRule:
    return SigmaRule.model_validate(
        {
            "title": "T",
            "id": "00000000-0000-0000-0000-0000000000aa",
            "level": level,
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": detection,
            "tags": tags or ["attack.t1105"],
        }
    )


def test_compiles_simple_endswith_and_contains():
    rule = _rule(
        {
            "selection": {
                "Image|endswith": "\\certutil.exe",
                "CommandLine|contains": "-urlcache",
            },
            "condition": "selection",
        }
    )
    wz = compile_rule(rule, 100200)
    assert wz.rule_id == 100200
    assert wz.mitre_ids == ["T1105"]
    # both fields should be present as PCRE2 matches
    assert "win.eventdata.image" in wz.field_matches
    assert "win.eventdata.commandLine" in wz.field_matches
    xml = render_rule_xml(wz)
    assert 'rule id="100200"' in xml
    assert "pcre2" in xml.lower()


def test_level_maps_to_wazuh_level():
    rule = _rule(
        {"selection": {"Image|endswith": "\\x.exe"}, "condition": "selection"},
        level="critical",
    )
    wz = compile_rule(rule, 100201)
    assert wz.level == 14  # critical -> 14


def test_list_values_become_alternation():
    rule = _rule(
        {
            "selection": {
                "CommandLine|contains": ["-enc", "-encodedcommand"],
            },
            "condition": "selection",
        }
    )
    wz = compile_rule(rule, 100202)
    patterns = wz.field_matches["win.eventdata.commandLine"]
    joined = " ".join(patterns)
    assert "-enc" in joined and "encodedcommand" in joined


def test_unsupported_condition_raises():
    rule = _rule(
        {
            "selection_a": {"Image|endswith": "\\a.exe"},
            "selection_b": {"Image|endswith": "\\b.exe"},
            "condition": "1 of selection_*",
        }
    )
    with pytest.raises(SigmaCompileError):
        compile_rule(rule, 100203)


def test_directory_compile_reports_skips_not_drops():
    """The shipped detections dir contains one intentionally-unsupported rule."""
    report = compile_directory(DETECTIONS_DIR)
    assert report.n_compiled >= 8
    assert report.n_skipped >= 1
    # the skipped rule is reported with a human reason, not swallowed
    reasons = [r for _, r in report.skipped]
    assert any("unsupported" in r.lower() for r in reasons)


def test_every_compiled_rule_has_a_technique():
    report = compile_directory(DETECTIONS_DIR)
    for rule in report.compiled:
        assert rule.mitre_ids, f"rule {rule.rule_id} has no ATT&CK mapping"
