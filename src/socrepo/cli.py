"""``socrepo`` command-line interface.

One command per stage of the detection-engineering loop, plus a ``demo`` that
runs the whole thing offline:

    socrepo compile     Sigma -> Wazuh local_rules.xml (+ skip report)
    socrepo validate    replay atomic telemetry through the compiled rules
    socrepo coverage    publish the attempted-vs-validated ATT&CK matrix
    socrepo triage      score alerts with the LLM (or heuristic fallback)
    socrepo evaluate    confusion matrix of triage verdicts vs manual labels
    socrepo demo        compile -> validate -> coverage -> triage -> evaluate

Design notes
------------
* Every command works with **no API key and no network** thanks to the
  heuristic provider, so CI and the sub-10-minute demo are reproducible.
* Human-readable output goes through Rich; machine-readable artifacts are written
  to disk (XML, Markdown, JSON) so the same commands power both the terminal and
  the committed ``docs/`` outputs.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .atomic_runner import run_live, run_simulated
from .coverage import build_coverage
from .coverage import render_markdown as render_coverage_md
from .evaluation import confusion, load_labels
from .evaluation import render_markdown as render_confusion_md
from .models import Alert, Verdict
from .sigma_compiler import compile_directory, render_xml
from .triage import build_default_engine
from .triage.engine import TriageEngine
from .triage.providers import AnthropicProvider, HeuristicProvider
from .utils import (
    CONFIG_DIR,
    DATA_DIR,
    DETECTIONS_DIR,
    DOCS_DIR,
    read_jsonl,
    write_jsonl,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="SOC-in-a-Repo — detection engineering with attempted-vs-validated coverage.",
    rich_markup_mode="rich",
)
console = Console()

# Default artifact locations. Keeping these here (not scattered) makes the demo
# and CI reference identical paths.
DEFAULT_SIGMA = DETECTIONS_DIR
DEFAULT_RULES_OUT = CONFIG_DIR / "wazuh" / "local_rules.xml"
DEFAULT_VALIDATION_OUT = DATA_DIR / "validation" / "results.jsonl"
DEFAULT_COVERAGE_OUT = DOCS_DIR / "coverage_matrix.md"
DEFAULT_ALERTS = DATA_DIR / "sample_alerts" / "alerts.jsonl"
DEFAULT_LABELS = DATA_DIR / "labels" / "manual_labels.csv"
DEFAULT_TRIAGE_OUT = DATA_DIR / "triage_results.jsonl"


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"socrepo {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    _version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """SOC-in-a-Repo command-line interface."""


# --------------------------------------------------------------------------- #
# compile
# --------------------------------------------------------------------------- #
@app.command()
def compile(
    sigma_dir: Path = typer.Option(DEFAULT_SIGMA, "--sigma-dir", "-s",
                                    help="Directory of Sigma rule YAML files."),
    out: Path = typer.Option(DEFAULT_RULES_OUT, "--out", "-o",
                             help="Where to write the Wazuh local_rules.xml."),
    strict: bool = typer.Option(False, "--strict",
                                help="Exit non-zero if any rule is skipped."),
) -> None:
    """Compile a documented Sigma subset into Wazuh rules.

    Unsupported constructs are **reported, never silently dropped** — a silent
    partial compile is worse than a failure because it inflates coverage.
    """
    report = compile_directory(sigma_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_xml(report), encoding="utf-8")

    table = Table(title="Sigma → Wazuh compilation", title_justify="left")
    table.add_column("rule id", style="cyan")
    table.add_column("technique(s)")
    table.add_column("description")
    for rule in report.compiled:
        table.add_row(str(rule.rule_id), ", ".join(rule.mitre_ids) or "—",
                      rule.description)
    console.print(table)

    console.print(
        f"[green]compiled[/] {report.n_compiled}  "
        f"[yellow]skipped[/] {report.n_skipped}  →  {out}"
    )
    if report.skipped:
        skip = Table(title="Skipped (unsupported)", title_style="yellow")
        skip.add_column("sigma id", style="dim")
        skip.add_column("reason", style="yellow")
        for sid, reason in report.skipped:
            skip.add_row(sid, reason)
        console.print(skip)

    if strict and report.skipped:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# validate  (a.k.a. the atomic runner)
# --------------------------------------------------------------------------- #
@app.command()
def validate(
    sigma_dir: Path = typer.Option(DEFAULT_SIGMA, "--sigma-dir", "-s"),
    out: Path = typer.Option(DEFAULT_VALIDATION_OUT, "--out", "-o",
                             help="Where to write validation results (JSONL)."),
    live: bool = typer.Option(
        False, "--live",
        help="Execute REAL Atomic Red Team tests (Windows only, double-gated). "
             "Default is safe simulation that executes nothing.",
    ),
) -> None:
    """Prove which detections actually fire.

    Simulation mode (default) replays captured process-creation telemetry through
    the compiled rules. This is what powers *validated* coverage.
    """
    report = compile_directory(sigma_dir)
    if live:
        console.print(Panel.fit(
            "[bold red]LIVE MODE[/] — this will execute adversary techniques.\n"
            "Requires --live AND env SOCREPO_ALLOW_LIVE_ATOMICS=1, Windows, and "
            "Invoke-AtomicTest installed.",
            border_style="red",
        ))
        results = run_live(report.compiled)  # atomics loaded internally
    else:
        results = run_simulated(report.compiled)

    out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(out, (r.model_dump(mode="json") for r in results))

    table = Table(title="Atomic validation", title_justify="left")
    table.add_column("technique", style="cyan")
    table.add_column("atomic guid", style="dim")
    table.add_column("validated")
    table.add_column("matched rules")
    table.add_column("note")
    n_val = 0
    for r in results:
        n_val += int(r.validated)
        table.add_row(
            r.technique_id, r.auto_guid[:8],
            "[green]✓[/]" if r.validated else "[red]✗[/]",
            ", ".join(r.matched_rule_ids) or "—",
            r.notes or "",
        )
    console.print(table)
    console.print(
        f"[green]validated[/] {n_val}/{len(results)} atomics fired a detection  →  {out}"
    )


# --------------------------------------------------------------------------- #
# coverage
# --------------------------------------------------------------------------- #
@app.command()
def coverage(
    sigma_dir: Path = typer.Option(DEFAULT_SIGMA, "--sigma-dir", "-s"),
    validation: Path = typer.Option(DEFAULT_VALIDATION_OUT, "--validation", "-v",
                                    help="Validation results JSONL (from `validate`)."),
    out: Path = typer.Option(DEFAULT_COVERAGE_OUT, "--out", "-o",
                             help="Where to write the coverage matrix Markdown."),
    json_out: Path | None = typer.Option(None, "--json",
                                            help="Also write the matrix as JSON."),
) -> None:
    """Publish the ATT&CK coverage matrix: attempted vs validated.

    If no validation file exists yet, coverage is computed with zero validated
    techniques (everything shows as an honest gap).
    """
    report = compile_directory(sigma_dir)

    from .models import ValidationResult
    val_results = []
    if validation.exists():
        for row in read_jsonl(validation):
            val_results.append(ValidationResult.model_validate(row))
    else:
        console.print(f"[yellow]no validation file at {validation}; "
                      "run `socrepo validate` first for validated coverage[/]")

    matrix = build_coverage(report.compiled, val_results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_coverage_md(matrix), encoding="utf-8")
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(matrix.model_dump_json(indent=2), encoding="utf-8")

    s = matrix.summary
    panel = Panel.fit(
        f"techniques in scope : [bold]{s.techniques_total}[/]\n"
        f"coverage attempted  : [bold cyan]{s.coverage_attempted}[/] "
        f"({s.attempted_pct}%)\n"
        f"coverage validated  : [bold green]{s.coverage_validated}[/] "
        f"({s.validated_pct}%)\n"
        f"validation gap      : [bold yellow]{s.validation_gap}[/] "
        "detection(s) unproven",
        title="Coverage", border_style="cyan",
    )
    console.print(panel)
    console.print(f"matrix written → {out}" + (f" and {json_out}" if json_out else ""))


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #
def _load_alerts(path: Path) -> list[Alert]:
    return [Alert.model_validate(row) for row in read_jsonl(path)]


def _select_engine(provider: str) -> TriageEngine:
    if provider == "heuristic":
        h = HeuristicProvider()
        return TriageEngine(primary=h, fallback=h)
    if provider == "anthropic":
        return TriageEngine(primary=AnthropicProvider(), fallback=HeuristicProvider())
    return build_default_engine()  # auto


@app.command()
def triage(
    alerts_path: Path = typer.Option(DEFAULT_ALERTS, "--alerts", "-a",
                                     help="Alerts JSONL to triage."),
    out: Path = typer.Option(DEFAULT_TRIAGE_OUT, "--out", "-o",
                             help="Where to write triage results (JSONL)."),
    provider: str = typer.Option("auto", "--provider", "-p",
                                 help="auto | heuristic | anthropic."),
    limit: int | None = typer.Option(None, "--limit", "-n",
                                        help="Triage only the first N alerts."),
    show_costs: bool = typer.Option(True, "--costs/--no-costs",
                                    help="Print the cost/latency table."),
) -> None:
    """Triage alerts into TP / FP / benign-suspicious with a next action.

    The engine guarantees every alert gets a structured verdict: if the LLM is
    unavailable or errors, it falls back to the heuristic per-alert and flags it.
    """
    alerts = _load_alerts(alerts_path)
    if limit:
        alerts = alerts[:limit]
    engine = _select_engine(provider)
    run = engine.run(alerts)

    out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(out, (r.model_dump(mode="json") for r in run.results))

    table = Table(title=f"Triage ({len(run.results)} alerts)", title_justify="left")
    table.add_column("alert", style="cyan")
    table.add_column("verdict")
    table.add_column("conf")
    table.add_column("action")
    table.add_column("fallback")
    table.add_column("rationale", overflow="fold", max_width=54)
    _verdict_style = {
        Verdict.TRUE_POSITIVE: "bold red",
        Verdict.FALSE_POSITIVE: "green",
        Verdict.BENIGN_SUSPICIOUS: "yellow",
    }
    for r in run.results:
        table.add_row(
            r.alert_id,
            f"[{_verdict_style[r.verdict]}]{r.verdict.value}[/]",
            f"{r.confidence:.2f}",
            r.next_action.value,
            "[red]↻ fallback[/]" if r.fell_back else "",
            r.rationale,
        )
    console.print(table)

    if show_costs:
        console.print(Panel.fit(
            run.cost_latency_table_md(engine.primary.name, engine.fallback.name),
            title="Cost / latency", border_style="magenta",
        ))
    console.print(f"triage results written → {out}")


# --------------------------------------------------------------------------- #
# evaluate
# --------------------------------------------------------------------------- #
@app.command()
def evaluate(
    triage_path: Path = typer.Option(DEFAULT_TRIAGE_OUT, "--triage", "-t",
                                     help="Triage results JSONL (from `triage`)."),
    labels_path: Path = typer.Option(DEFAULT_LABELS, "--labels", "-l",
                                     help="Manual labels CSV (alert_id,label)."),
    out: Path | None = typer.Option(None, "--out", "-o",
                                       help="Write the confusion-matrix Markdown."),
) -> None:
    """Score triage verdicts against manual labels (confusion matrix).

    This is the rigor step: it quantifies how often the triage layer agrees with
    a human analyst, per class, rather than reporting a single accuracy number.
    """
    from .models import TriageResult

    results = [TriageResult.model_validate(row) for row in read_jsonl(triage_path)]
    labels = load_labels(labels_path)
    cm = confusion(results, labels)

    # confusion table
    order = cm.labels
    table = Table(title=f"Confusion matrix (n={cm.n})", title_justify="left")
    table.add_column("true ╲ pred", style="dim")
    for lab in order:
        table.add_column(lab, justify="right")
    for i, lab in enumerate(order):
        table.add_row(lab, *[
            (f"[bold]{cm.matrix[i][j]}[/]" if i == j else str(cm.matrix[i][j]))
            for j in range(len(order))
        ])
    console.print(table)

    metrics = Table(title="Per-class metrics", title_justify="left")
    metrics.add_column("class", style="cyan")
    for col in ("precision", "recall", "f1", "support"):
        metrics.add_column(col, justify="right")
    for lab in order:
        pc = cm.per_class[lab]
        metrics.add_row(lab, f"{pc['precision']:.2f}", f"{pc['recall']:.2f}",
                        f"{pc['f1']:.2f}", str(cm.support.get(lab, 0)))
    console.print(metrics)
    console.print(Panel.fit(
        f"accuracy       : [bold]{cm.accuracy:.3f}[/]\n"
        f"macro precision: {cm.macro_precision:.3f}\n"
        f"macro recall   : {cm.macro_recall:.3f}\n"
        f"macro f1       : [bold]{cm.macro_f1:.3f}[/]",
        title="Aggregate", border_style="green",
    ))

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_confusion_md(cm), encoding="utf-8")
        console.print(f"confusion matrix written → {out}")


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #
@app.command()
def demo(
    provider: str = typer.Option("auto", "--provider", "-p",
                                 help="auto | heuristic | anthropic."),
) -> None:
    """Run the whole pipeline end-to-end (offline-safe)."""
    console.rule("[bold]1/5 compile")
    compile(sigma_dir=DEFAULT_SIGMA, out=DEFAULT_RULES_OUT, strict=False)
    console.rule("[bold]2/5 validate (simulated)")
    validate(sigma_dir=DEFAULT_SIGMA, out=DEFAULT_VALIDATION_OUT, live=False)
    console.rule("[bold]3/5 coverage")
    coverage(sigma_dir=DEFAULT_SIGMA, validation=DEFAULT_VALIDATION_OUT,
             out=DEFAULT_COVERAGE_OUT,
             json_out=DOCS_DIR / "coverage_matrix.json")
    console.rule("[bold]4/5 triage")
    triage(alerts_path=DEFAULT_ALERTS, out=DEFAULT_TRIAGE_OUT, provider=provider,
           limit=None, show_costs=True)
    console.rule("[bold]5/5 evaluate")
    evaluate(triage_path=DEFAULT_TRIAGE_OUT, labels_path=DEFAULT_LABELS,
             out=DOCS_DIR / "confusion_matrix.md")
    console.rule("[bold green]done")
    console.print(
        "Artifacts: [cyan]config/wazuh/local_rules.xml[/], "
        "[cyan]docs/coverage_matrix.md[/], [cyan]docs/confusion_matrix.md[/]."
    )


if __name__ == "__main__":
    app()
