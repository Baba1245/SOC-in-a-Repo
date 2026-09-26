"""Triage orchestration: a primary provider with a guaranteed fallback.

The engine's contract: *every* alert gets a valid ``TriageResult``. If the
primary provider is unavailable or errors on an alert, the engine transparently
falls back to the heuristic and flags the result with ``fell_back=True`` so the
degradation is auditable rather than silent.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..models import Alert, TriageResult
from ..utils import get_logger
from .providers import HeuristicProvider, TriageProvider

log = get_logger(__name__)


@dataclass
class TriageRun:
    """The results of triaging a batch, plus operational telemetry."""

    results: list[TriageResult] = field(default_factory=list)
    n_primary: int = 0
    n_fell_back: int = 0

    @property
    def total_cost_usd(self) -> float:
        return round(sum(r.cost_usd or 0.0 for r in self.results), 6)

    @property
    def mean_latency_ms(self) -> float:
        lats = [r.latency_ms for r in self.results if r.latency_ms is not None]
        return round(sum(lats) / len(lats), 2) if lats else 0.0

    @property
    def p95_latency_ms(self) -> float:
        lats = sorted(r.latency_ms for r in self.results if r.latency_ms is not None)
        if not lats:
            return 0.0
        idx = min(len(lats) - 1, int(round(0.95 * (len(lats) - 1))))
        return round(lats[idx], 2)

    def cost_latency_table_md(self, primary_name: str, fallback_name: str) -> str:
        return "\n".join(
            [
                "| metric | value |",
                "|---|---|",
                f"| alerts triaged | {len(self.results)} |",
                f"| primary provider | {primary_name} |",
                f"| fallback provider | {fallback_name} |",
                f"| served by primary | {self.n_primary} |",
                f"| served by fallback | {self.n_fell_back} |",
                f"| total cost (USD) | ${self.total_cost_usd:.4f} |",
                f"| mean latency (ms) | {self.mean_latency_ms} |",
                f"| p95 latency (ms) | {self.p95_latency_ms} |",
            ]
        )


class TriageEngine:
    def __init__(
        self,
        primary: TriageProvider,
        fallback: TriageProvider | None = None,
    ) -> None:
        self.primary = primary
        self.fallback = fallback or HeuristicProvider()

    def triage_one(self, alert: Alert) -> tuple[TriageResult, bool]:
        """Return (result, fell_back)."""
        if self.primary.available():
            try:
                return self.primary.triage(alert), False
            except Exception as exc:  # noqa: BLE001 - resilience is the point
                log.warning("primary provider failed on %s: %s", alert.id, exc)
        # fall back
        result = self.fallback.triage(alert)
        result.fell_back = True
        return result, True

    def run(self, alerts: Iterable[Alert]) -> TriageRun:
        run = TriageRun()
        for alert in alerts:
            result, fell_back = self.triage_one(alert)
            run.results.append(result)
            if fell_back:
                run.n_fell_back += 1
            else:
                run.n_primary += 1
        log.info(
            "triaged %d alerts (primary=%d, fallback=%d, cost=$%.4f)",
            len(run.results),
            run.n_primary,
            run.n_fell_back,
            run.total_cost_usd,
        )
        return run


def build_default_engine() -> TriageEngine:
    """Primary = Anthropic if configured, else heuristic. Fallback = heuristic.

    This means: with an API key, you get LLM triage that degrades to heuristic
    per-alert on error; with no key, the whole batch runs on the heuristic and
    the pipeline still completes end-to-end.
    """
    from .providers import AnthropicProvider

    anthropic = AnthropicProvider()
    heuristic = HeuristicProvider()
    if anthropic.available():
        log.info("triage primary: anthropic (%s)", anthropic.model)
        return TriageEngine(primary=anthropic, fallback=heuristic)
    log.info("triage primary: heuristic (no ANTHROPIC_API_KEY / SDK)")
    return TriageEngine(primary=heuristic, fallback=heuristic)
