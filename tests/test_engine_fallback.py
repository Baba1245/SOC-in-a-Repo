"""Engine orchestration: the fallback path is a v0.3 requirement, so it is
tested as a first-class behaviour, not an afterthought.

Contract under test:

* every alert always receives a valid result (the pipeline never aborts);
* when the primary is unavailable, the whole batch is served by the fallback
  and each result is flagged ``fell_back=True``;
* when the primary raises on *some* alerts, fallback is per-alert, and the run
  telemetry counts primary vs fallback correctly.
"""

from __future__ import annotations

import pytest

from socrepo.models import Alert, NextAction, TriageResult, Verdict
from socrepo.triage.engine import TriageEngine
from socrepo.triage.providers import HeuristicProvider


class _StubProvider:
    """A configurable primary provider for exercising the engine."""

    name = "stub"
    model = "stub-1"

    def __init__(self, *, available: bool = True, fail_on: set[str] | None = None):
        self._available = available
        self._fail_on = fail_on or set()

    def available(self) -> bool:
        return self._available

    def triage(self, alert: Alert) -> TriageResult:
        if alert.id in self._fail_on:
            raise RuntimeError("simulated provider outage")
        return TriageResult(
            alert_id=alert.id,
            verdict=Verdict.BENIGN_SUSPICIOUS,
            confidence=0.6,
            next_action=NextAction.MONITOR,
            rationale="stub",
            key_indicators=[],
            provider=self.name,
            model=self.model,
            latency_ms=1.0,
            cost_usd=0.001,
        )


def test_unavailable_primary_uses_fallback_for_all(make_alert):
    engine = TriageEngine(primary=_StubProvider(available=False),
                          fallback=HeuristicProvider())
    alerts = [make_alert(id=f"A{i}") for i in range(3)]
    run = engine.run(alerts)

    assert len(run.results) == 3
    assert run.n_primary == 0
    assert run.n_fell_back == 3
    assert all(r.fell_back for r in run.results)
    assert all(r.provider == "heuristic" for r in run.results)


def test_available_primary_serves_all(make_alert):
    engine = TriageEngine(primary=_StubProvider(available=True),
                          fallback=HeuristicProvider())
    alerts = [make_alert(id=f"A{i}") for i in range(3)]
    run = engine.run(alerts)

    assert run.n_primary == 3
    assert run.n_fell_back == 0
    assert not any(r.fell_back for r in run.results)
    # cost accrues from the primary only.
    assert run.total_cost_usd == pytest.approx(0.003)


def test_per_alert_fallback_on_partial_failure(make_alert):
    engine = TriageEngine(
        primary=_StubProvider(available=True, fail_on={"A1"}),
        fallback=HeuristicProvider(),
    )
    alerts = [make_alert(id=f"A{i}") for i in range(3)]
    run = engine.run(alerts)

    assert len(run.results) == 3
    assert run.n_primary == 2
    assert run.n_fell_back == 1
    by_id = {r.alert_id: r for r in run.results}
    assert by_id["A1"].fell_back is True
    assert by_id["A1"].provider == "heuristic"
    assert by_id["A0"].fell_back is False


def test_run_telemetry_table_renders(make_alert):
    engine = TriageEngine(primary=_StubProvider(), fallback=HeuristicProvider())
    run = engine.run([make_alert(id="A0")])
    table = run.cost_latency_table_md("stub", "heuristic")
    assert "mean latency" in table
    assert "p95 latency" in table
    assert "total cost" in table.lower()
