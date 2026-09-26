"""Core domain models for SOC-in-a-Repo.

Everything that crosses a module boundary is a typed model. This keeps the
Sigma compiler, the Atomic runner, the coverage engine and the triage layer
honest about what they produce and consume, and gives us free validation and
JSON (de)serialisation via pydantic v2.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Verdict(StrEnum):
    """The three-way triage verdict.

    A binary TP/FP split hides the most operationally important bucket: the
    activity that is real and unusual but not (yet) malicious. Forcing a
    ``benign_suspicious`` class is what stops an analyst from either closing
    real leads or escalating noise.
    """

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_SUSPICIOUS = "benign_suspicious"


class NextAction(StrEnum):
    """The recommended next step. Ordered roughly by severity."""

    CLOSE = "close"
    MONITOR = "monitor"
    HUNT = "hunt"
    ESCALATE = "escalate"
    ISOLATE_HOST = "isolate_host"


class SigmaLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def wazuh_level(self) -> int:
        """Map a Sigma severity onto a Wazuh alert level (0-16)."""
        return {
            SigmaLevel.INFORMATIONAL: 3,
            SigmaLevel.LOW: 5,
            SigmaLevel.MEDIUM: 9,
            SigmaLevel.HIGH: 12,
            SigmaLevel.CRITICAL: 14,
        }[self]


# --------------------------------------------------------------------------- #
# Detection content
# --------------------------------------------------------------------------- #
class SigmaRule(BaseModel):
    """A parsed Sigma rule (the subset of the spec we support).

    We deliberately support a documented subset rather than pretending to be a
    full Sigma backend. ``LIMITATIONS.md`` states exactly what is and isn't
    handled.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    title: str
    status: str | None = None
    description: str | None = None
    level: SigmaLevel = SigmaLevel.MEDIUM
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @property
    def attack_techniques(self) -> list[str]:
        """Extract ATT&CK technique IDs from Sigma ``attack.tXXXX`` tags."""
        out: list[str] = []
        for tag in self.tags:
            t = tag.lower()
            if t.startswith("attack.t"):
                tech = tag.split(".", 1)[1].upper()
                out.append(tech)
        return out

    @field_validator("level", mode="before")
    @classmethod
    def _coerce_level(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class WazuhRule(BaseModel):
    """The compiled Wazuh rule representation (rendered to XML on write)."""

    rule_id: int
    level: int
    description: str
    sigma_id: str
    mitre_ids: list[str] = Field(default_factory=list)
    field_matches: dict[str, list[str]] = Field(default_factory=dict)
    if_sid: str = "61603"  # Sysmon EventID 1 (process creation) parent rule
    groups: list[str] = Field(default_factory=lambda: ["sysmon", "socrepo"])


# --------------------------------------------------------------------------- #
# Adversary emulation + validation
# --------------------------------------------------------------------------- #
class AtomicTest(BaseModel):
    """A single Atomic Red Team test mapped to a technique."""

    technique_id: str
    technique_name: str
    auto_guid: str
    name: str
    executor: str = "powershell"
    destructive: bool = False


class ValidationResult(BaseModel):
    """Did an executed atomic actually surface a matching alert?

    ``attempted`` means we ran (or intended to run) an atomic for the technique.
    ``validated`` means a detection actually fired on the resulting telemetry.
    These two are the numerator of the two coverage metrics.
    """

    technique_id: str
    auto_guid: str
    attempted: bool = True
    validated: bool = False
    matched_rule_ids: list[str] = Field(default_factory=list)
    notes: str | None = None
    ran_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.now(_dt.UTC))


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #
class TechniqueCoverage(BaseModel):
    """One row of the ATT&CK coverage matrix."""

    technique_id: str
    technique_name: str
    tactic: str
    detection_ids: list[str] = Field(default_factory=list)
    has_detection: bool = False          # coverage *attempted*
    validated: bool = False              # coverage *validated*
    atomic_guids: list[str] = Field(default_factory=list)


class CoverageSummary(BaseModel):
    """The two metrics that matter, plus the denominators behind them."""

    techniques_total: int
    coverage_attempted: int
    coverage_validated: int

    @property
    def attempted_pct(self) -> float:
        return _pct(self.coverage_attempted, self.techniques_total)

    @property
    def validated_pct(self) -> float:
        return _pct(self.coverage_validated, self.techniques_total)

    @property
    def validation_gap(self) -> int:
        """Detections written but never proven to fire. The honest number."""
        return self.coverage_attempted - self.coverage_validated


class CoverageMatrix(BaseModel):
    rows: list[TechniqueCoverage]
    summary: CoverageSummary


# --------------------------------------------------------------------------- #
# Alerts + triage
# --------------------------------------------------------------------------- #
class Alert(BaseModel):
    """A normalised alert as it would arrive from Wazuh/the SIEM.

    The field set is intentionally small and process-creation centric — it is
    the highest-signal Sysmon channel and keeps the demo self-contained.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    timestamp: _dt.datetime
    rule_id: str
    rule_title: str
    level: SigmaLevel
    technique_id: str | None = None
    host: str
    user: str
    image: str
    command_line: str
    parent_image: str | None = None
    parent_command_line: str | None = None
    signed: bool | None = None

    def to_prompt_block(self) -> str:
        """Compact, deterministic textual view handed to the triage layer."""
        lines = [
            f"alert_id:       {self.id}",
            f"rule:           {self.rule_title} ({self.rule_id})",
            f"severity:       {self.level.value}",
            f"attack:         {self.technique_id or 'n/a'}",
            f"host:           {self.host}",
            f"user:           {self.user}",
            f"image:          {self.image}",
            f"command_line:   {self.command_line}",
            f"parent_image:   {self.parent_image or 'n/a'}",
            f"parent_cmdline: {self.parent_command_line or 'n/a'}",
            f"signed_binary:  {self.signed if self.signed is not None else 'unknown'}",
        ]
        return "\n".join(lines)


class TriageResult(BaseModel):
    """Structured triage output. Never a free-text blob."""

    alert_id: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    next_action: NextAction
    rationale: str
    key_indicators: list[str] = Field(default_factory=list)
    provider: str
    model: str | None = None
    latency_ms: float | None = None
    cost_usd: float | None = None
    fell_back: bool = False

    @field_validator("confidence")
    @classmethod
    def _round_conf(cls, v: float) -> float:
        return round(v, 3)


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
class ConfusionMatrix(BaseModel):
    """A labelled confusion matrix over the three verdict classes."""

    labels: list[str]
    matrix: list[list[int]]          # matrix[true][pred]
    support: dict[str, int]

    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    per_class: dict[str, dict[str, float]]
    n: int


def _pct(num: int, denom: int) -> float:
    return round(100.0 * num / denom, 1) if denom else 0.0
