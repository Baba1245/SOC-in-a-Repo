"""Evaluate triage verdicts against hand-applied manual labels.

The confusion matrix here is the rigor step the whole project is built around:
it converts "the model produced plausible output" into "the model agrees with a
human on N labelled alerts, and here is exactly where it disagrees."

Metrics are computed directly (no sklearn) to keep the dependency surface small
and the arithmetic auditable.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from .models import ConfusionMatrix, TriageResult, Verdict

_LABEL_ORDER = [
    Verdict.TRUE_POSITIVE.value,
    Verdict.BENIGN_SUSPICIOUS.value,
    Verdict.FALSE_POSITIVE.value,
]


def load_labels(path: str | Path) -> dict[str, str]:
    """Load ``alert_id -> label`` from a two-column CSV (alert_id,label)."""
    labels: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            labels[row["alert_id"].strip()] = row["label"].strip().lower()
    return labels


def confusion(
    results: list[TriageResult],
    labels: dict[str, str],
) -> ConfusionMatrix:
    idx = {lab: i for i, lab in enumerate(_LABEL_ORDER)}
    n_lab = len(_LABEL_ORDER)
    mat = [[0] * n_lab for _ in range(n_lab)]
    support: dict[str, int] = defaultdict(int)

    n = 0
    for r in results:
        truth = labels.get(r.alert_id)
        if truth is None or truth not in idx:
            continue
        pred = r.verdict.value
        mat[idx[truth]][idx[pred]] += 1
        support[truth] += 1
        n += 1

    correct = sum(mat[i][i] for i in range(n_lab))
    accuracy = round(correct / n, 4) if n else 0.0

    per_class: dict[str, dict[str, float]] = {}
    precisions, recalls, f1s = [], [], []
    for lab, i in idx.items():
        tp = mat[i][i]
        fp = sum(mat[r][i] for r in range(n_lab)) - tp
        fn = sum(mat[i][c] for c in range(n_lab)) - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        per_class[lab] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support.get(lab, 0),
        }
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)

    macro = lambda xs: round(sum(xs) / len(xs), 4) if xs else 0.0  # noqa: E731

    return ConfusionMatrix(
        labels=_LABEL_ORDER,
        matrix=mat,
        support=dict(support),
        accuracy=accuracy,
        macro_precision=macro(precisions),
        macro_recall=macro(recalls),
        macro_f1=macro(f1s),
        per_class=per_class,
        n=n,
    )


def render_markdown(cm: ConfusionMatrix) -> str:
    header = "| true \\ pred | " + " | ".join(cm.labels) + " | support |"
    sep = "|" + "---|" * (len(cm.labels) + 2)
    lines = [
        "## Triage confusion matrix",
        "",
        f"Evaluated on **{cm.n}** manually-labelled alerts.",
        "",
        header,
        sep,
    ]
    for i, lab in enumerate(cm.labels):
        row = " | ".join(str(x) for x in cm.matrix[i])
        lines.append(f"| **{lab}** | {row} | {cm.support.get(lab, 0)} |")
    lines += [
        "",
        f"- **accuracy:** {cm.accuracy}",
        f"- **macro precision / recall / F1:** {cm.macro_precision} / "
        f"{cm.macro_recall} / {cm.macro_f1}",
        "",
        "### Per class",
        "",
        "| class | precision | recall | f1 | support |",
        "|---|---|---|---|---|",
    ]
    for lab in cm.labels:
        pc = cm.per_class[lab]
        lines.append(
            f"| {lab} | {pc['precision']} | {pc['recall']} | {pc['f1']} | "
            f"{int(pc['support'])} |"
        )
    lines.append("")
    return "\n".join(lines)
