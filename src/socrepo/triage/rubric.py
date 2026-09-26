"""The triage rubric and the contract for structured triage output.

The rubric is deliberately explicit and shared verbatim between the heuristic
provider and the LLM prompt, so both are judged against the same definitions.
The output contract is a JSON object that maps 1:1 onto ``TriageResult``.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import NextAction, TriageResult, Verdict

# The rubric text embedded in the LLM system prompt AND used as the human-facing
# definition in docs/TRIAGE_RUBRIC.md.
RUBRIC = """\
You are triaging a single endpoint detection alert. Assign exactly one verdict.

VERDICTS
  true_positive      Malicious or unauthorised activity consistent with the
                     mapped ATT&CK technique. The alert did its job.
  false_positive     Benign activity the rule should not have flagged. The
                     detection logic (not the analyst) is at fault.
  benign_suspicious  Real, unusual, or policy-violating activity that is not
                     (yet) provably malicious. Needs a human or more context.
                     When genuinely unsure between TP and FP, choose this.

CONFIDENCE  A float in [0,1]. Calibrate honestly:
  0.9-1.0  unambiguous          0.6-0.8  likely      0.4-0.6  genuinely unsure

NEXT ACTION  Exactly one:
  close         verdict is false_positive and the rule needs no change now
  monitor       benign_suspicious, low urgency; keep an eye on it
  hunt          benign_suspicious with pivot potential; expand the search
  escalate      true_positive; hand to incident response
  isolate_host  true_positive with active/destructive behaviour; contain now

SIGNALS to weigh: LOLBIN + attacker-style flags; network egress to raw IPs;
parent/child anomalies (e.g. office app -> shell); credential-access targets
(lsass); whether the binary is signed and in a system path; whether the user
is an administrator doing plausible admin work; encoded/obfuscated commands.
"""

# JSON schema description handed to the model (kept small and unambiguous).
OUTPUT_CONTRACT = {
    "verdict": "one of: true_positive | false_positive | benign_suspicious",
    "confidence": "float between 0 and 1",
    "next_action": "one of: close | monitor | hunt | escalate | isolate_host",
    "rationale": "<= 2 sentences, concrete, referencing the evidence",
    "key_indicators": ["short strings naming the signals you used"],
}


class RubricParseError(ValueError):
    """Raised when model output cannot be coerced into a TriageResult."""


def contract_json() -> str:
    return json.dumps(OUTPUT_CONTRACT, indent=2)


def _extract_json(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model response, tolerant of fences."""
    text = text.strip()
    if text.startswith("```"):
        # strip ```json ... ``` fences
        text = text.split("```", 2)[1]
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise RubricParseError(f"no JSON object found in response: {text[:120]!r}")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise RubricParseError(f"invalid JSON: {exc}") from exc


def parse_result(
    raw: str | dict[str, Any],
    *,
    alert_id: str,
    provider: str,
    model: str | None = None,
    latency_ms: float | None = None,
    cost_usd: float | None = None,
    fell_back: bool = False,
) -> TriageResult:
    """Validate raw model/heuristic output into a TriageResult, or raise."""
    data = raw if isinstance(raw, dict) else _extract_json(raw)

    try:
        verdict = Verdict(str(data["verdict"]).strip().lower())
        next_action = NextAction(str(data["next_action"]).strip().lower())
        confidence = float(data["confidence"])
    except (KeyError, ValueError) as exc:
        raise RubricParseError(f"bad field in triage output: {exc}") from exc

    confidence = max(0.0, min(1.0, confidence))
    indicators = data.get("key_indicators") or []
    if isinstance(indicators, str):
        indicators = [indicators]

    return TriageResult(
        alert_id=alert_id,
        verdict=verdict,
        confidence=confidence,
        next_action=next_action,
        rationale=str(data.get("rationale", "")).strip(),
        key_indicators=[str(i) for i in indicators][:8],
        provider=provider,
        model=model,
        latency_ms=latency_ms,
        cost_usd=cost_usd,
        fell_back=fell_back,
    )
