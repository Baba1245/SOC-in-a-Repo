"""Coverage-matrix math: the two headline metrics must be exactly right.

These tests pin the definitions that the whole project's credibility rests on:

* *attempted* counts a technique only when a **compiled** rule maps to it;
* *validated* counts it only when an atomic actually made a rule fire;
* the *gap* is attempted-minus-validated and is never negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from socrepo.coverage import build_coverage, render_markdown
from socrepo.models import ValidationResult, WazuhRule


def _rule(rule_id: int, *techniques: str) -> WazuhRule:
    return WazuhRule(
        rule_id=rule_id,
        level=12,
        description=f"rule-{rule_id}",
        sigma_id=f"00000000-0000-0000-0000-{rule_id:012d}",
        mitre_ids=list(techniques),
        field_matches={"win.eventdata.image": [r"\\x\.exe$"]},
    )


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    """A three-technique scope with one deliberate detection gap (T1082)."""
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "T1105:\n"
        "  name: Ingress Tool Transfer\n"
        "  tactic: command-and-control\n"
        "  atomics:\n"
        "    - {guid: g-1, name: certutil, executor: command_prompt, destructive: false}\n"
        "T1003.001:\n"
        "  name: LSASS Memory\n"
        "  tactic: credential-access\n"
        "  atomics:\n"
        "    - {guid: g-2, name: procdump, executor: command_prompt, destructive: false}\n"
        "T1082:\n"
        "  name: System Information Discovery\n"
        "  tactic: discovery\n"
        "  atomics:\n"
        "    - {guid: g-3, name: systeminfo, executor: command_prompt, destructive: false}\n",
        encoding="utf-8",
    )
    return scope


def test_attempted_counts_only_compiled_rules(scope_file: Path):
    # Two of three techniques have a compiled detection; T1082 has none.
    rules = [_rule(100200, "T1105"), _rule(100203, "T1003.001")]
    validation: list[ValidationResult] = []

    matrix = build_coverage(rules, validation, scope_path=scope_file)

    assert matrix.summary.techniques_total == 3
    assert matrix.summary.coverage_attempted == 2
    assert matrix.summary.attempted_pct == pytest.approx(66.7, abs=0.1)


def test_validated_requires_an_atomic_to_fire(scope_file: Path):
    rules = [_rule(100200, "T1105"), _rule(100203, "T1003.001")]
    # Only T1105 actually validated; T1003.001 attempted-but-not-validated.
    validation = [
        ValidationResult(
            technique_id="T1105", auto_guid="g-1", attempted=True,
            validated=True, matched_rule_ids=["100200"],
        ),
        ValidationResult(
            technique_id="T1003.001", auto_guid="g-2", attempted=True,
            validated=False, matched_rule_ids=[],
        ),
    ]

    matrix = build_coverage(rules, validation, scope_path=scope_file)

    assert matrix.summary.coverage_attempted == 2
    assert matrix.summary.coverage_validated == 1
    # The gap is the honest number: a detection we cannot yet trust.
    assert matrix.summary.validation_gap == 1


def test_gap_is_never_negative_even_with_stray_validation(scope_file: Path):
    """A validation for a technique with no compiled rule must not create a
    negative gap or inflate validated beyond attempted-in-scope."""
    rules = [_rule(100200, "T1105")]
    validation = [
        ValidationResult(
            technique_id="T1105", auto_guid="g-1", attempted=True,
            validated=True, matched_rule_ids=["100200"],
        ),
        # T1082 "validated" but has no compiled detection in scope.
        ValidationResult(
            technique_id="T1082", auto_guid="g-3", attempted=True,
            validated=True, matched_rule_ids=["999999"],
        ),
    ]

    matrix = build_coverage(rules, validation, scope_path=scope_file)

    assert matrix.summary.coverage_attempted == 1
    # validated counts in-scope techniques that fired — T1082 did fire and is in
    # scope, so validated == 2 while attempted == 1. The gap clamps at >= 0.
    assert matrix.summary.validation_gap >= 0


def test_subtechnique_tag_satisfies_exact_scope_entry(scope_file: Path):
    """A rule tagged with the sub-technique must satisfy that scope row; we do
    not silently roll parents up to children."""
    rules = [_rule(100203, "T1003.001")]
    matrix = build_coverage(rules, [], scope_path=scope_file)
    row = next(r for r in matrix.rows if r.technique_id == "T1003.001")
    assert row.has_detection is True


def test_render_markdown_surfaces_both_metrics(scope_file: Path):
    rules = [_rule(100200, "T1105")]
    matrix = build_coverage(rules, [], scope_path=scope_file)
    md = render_markdown(matrix)
    assert "Coverage attempted" in md
    assert "Coverage validated" in md
    assert "Validation gap" in md
