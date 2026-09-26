"""Confusion-matrix arithmetic — the project's central rigor claim.

If these numbers are wrong, every downstream conclusion ("the LLM beats the
baseline by X") is wrong. So the maths is checked against a hand-computed case
with a known layout, including the safety-critical cell: true positives that
were predicted false positive.
"""

from __future__ import annotations

from socrepo.evaluation import confusion, render_markdown
from socrepo.models import NextAction, TriageResult, Verdict


def _result(alert_id: str, verdict: Verdict) -> TriageResult:
    return TriageResult(
        alert_id=alert_id,
        verdict=verdict,
        confidence=0.8,
        next_action=NextAction.MONITOR,
        rationale="x",
        key_indicators=[],
        provider="heuristic",
        model="heuristic-v2",
    )


def test_perfect_agreement_gives_unit_accuracy():
    labels = {"a": "true_positive", "b": "false_positive", "c": "benign_suspicious"}
    results = [
        _result("a", Verdict.TRUE_POSITIVE),
        _result("b", Verdict.FALSE_POSITIVE),
        _result("c", Verdict.BENIGN_SUSPICIOUS),
    ]
    cm = confusion(results, labels)
    assert cm.n == 3
    assert cm.accuracy == 1.0
    assert cm.macro_f1 == 1.0


def test_hand_computed_mixed_case():
    # Truth vs pred, laid out explicitly:
    #   a: TP -> TP  (correct)
    #   b: TP -> FP  (a dangerous miss)
    #   c: FP -> FP  (correct)
    #   d: benign -> benign (correct)
    #   e: benign -> FP (calibration error)
    labels = {
        "a": "true_positive",
        "b": "true_positive",
        "c": "false_positive",
        "d": "benign_suspicious",
        "e": "benign_suspicious",
    }
    results = [
        _result("a", Verdict.TRUE_POSITIVE),
        _result("b", Verdict.FALSE_POSITIVE),
        _result("c", Verdict.FALSE_POSITIVE),
        _result("d", Verdict.BENIGN_SUSPICIOUS),
        _result("e", Verdict.FALSE_POSITIVE),
    ]
    cm = confusion(results, labels)

    assert cm.n == 5
    # 3 of 5 correct.
    assert cm.accuracy == 0.6

    # Label order is [true_positive, benign_suspicious, false_positive].
    i_tp = cm.labels.index("true_positive")
    i_fp = cm.labels.index("false_positive")
    i_bs = cm.labels.index("benign_suspicious")

    # The safety-critical cell: one TP predicted FP.
    assert cm.matrix[i_tp][i_fp] == 1
    # TP recall = 1 correct / 2 actual = 0.5
    assert cm.per_class["true_positive"]["recall"] == 0.5
    # benign support is 2.
    assert cm.support["benign_suspicious"] == 2
    assert cm.matrix[i_bs][i_fp] == 1


def test_unlabelled_results_are_ignored():
    labels = {"a": "true_positive"}
    results = [
        _result("a", Verdict.TRUE_POSITIVE),
        _result("ghost", Verdict.FALSE_POSITIVE),  # no label -> skipped
    ]
    cm = confusion(results, labels)
    assert cm.n == 1
    assert cm.accuracy == 1.0


def test_render_markdown_contains_matrix_and_metrics():
    labels = {"a": "true_positive"}
    cm = confusion([_result("a", Verdict.TRUE_POSITIVE)], labels)
    md = render_markdown(cm)
    assert "confusion matrix" in md.lower()
    assert "accuracy" in md.lower()
    assert "true_positive" in md
