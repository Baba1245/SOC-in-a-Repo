"""Compile a documented subset of Sigma into Wazuh ``local_rules.xml``.

Design stance
-------------
This is **not** a full Sigma backend. It supports the constructs actually used
by the process-creation rules shipped in ``detections/sigma`` and refuses,
loudly and on the record, to compile anything outside that subset. A silent
partial compile is worse than a visible skip: an operator who thinks a rule is
deployed when it isn't has negative coverage. See ``LIMITATIONS.md``.

Supported
~~~~~~~~~
* ``logsource`` ``category: process_creation`` on ``product: windows``
* field modifiers: ``endswith``, ``startswith``, ``contains``, ``all`` and bare
  (exact) matches; list values (OR); ``|all`` (AND of list values)
* conditions: ``selection``, a single selection key, and ``all of selection*``

Not supported (skipped, reported, never silently dropped)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* ``or`` across heterogeneous blocks (``1 of selection*``)
* negation / filters (``and not ...``) — Wazuh single-rule negation is lossy
* ``re``/regex modifiers, ``base64``/encoding modifiers, ``|windash``
* aggregations (``count()``, ``| near`` …)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from .models import SigmaRule, WazuhRule
from .utils import get_logger, iter_sigma_files, read_yaml

log = get_logger(__name__)

# Sigma field name -> Wazuh Sysmon (EventID 1) decoded field name.
FIELD_MAP: dict[str, str] = {
    "Image": "win.eventdata.image",
    "OriginalFileName": "win.eventdata.originalFileName",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "User": "win.eventdata.user",
    "Company": "win.eventdata.company",
    "Description": "win.eventdata.description",
    "Product": "win.eventdata.product",
    "IntegrityLevel": "win.eventdata.integrityLevel",
    "CurrentDirectory": "win.eventdata.currentDirectory",
    "Hashes": "win.eventdata.hashes",
}

SUPPORTED_MODIFIERS = {"endswith", "startswith", "contains", "all"}
_BASE_RULE_ID = 100200  # local_rules.xml block; avoids the reserved ranges


@dataclass
class CompileReport:
    """Outcome of a compile run — the honest tally."""

    compiled: list[WazuhRule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (sigma_id, reason)

    @property
    def n_compiled(self) -> int:
        return len(self.compiled)

    @property
    def n_skipped(self) -> int:
        return len(self.skipped)


class SigmaCompileError(Exception):
    """Raised for an individual rule that falls outside the supported subset."""


# --------------------------------------------------------------------------- #
# Value -> PCRE2 translation
# --------------------------------------------------------------------------- #
def _regex_escape(value: str) -> str:
    """Escape a literal Sigma value for use inside a PCRE2 pattern."""
    return re.escape(str(value))


def _pattern_for(modifier: str | None, value: str) -> str:
    """Turn a single scalar value + modifier into a PCRE2 fragment."""
    esc = _regex_escape(value)
    if modifier == "endswith":
        return f"{esc}$"
    if modifier == "startswith":
        return f"^{esc}"
    if modifier == "contains":
        return esc
    # bare / exact
    return f"^{esc}$"


def _field_to_conditions(
    sigma_field: str, raw_value: object
) -> list[tuple[str, str]]:
    """Translate ``Field|mod: value`` into a list of (wazuh_field, pcre2) pairs.

    Multiple pairs for the same field are ANDed by Wazuh (``|all`` semantics);
    list values without ``all`` are ORed into a single alternation.
    """
    parts = sigma_field.split("|")
    name = parts[0]
    modifiers = [p.lower() for p in parts[1:]]

    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaCompileError(f"unsupported field modifier(s): {sorted(unknown)}")
    if name not in FIELD_MAP:
        raise SigmaCompileError(f"unmapped field '{name}'")

    wazuh_field = FIELD_MAP[name]
    scalar_mod = next((m for m in modifiers if m != "all"), None)
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    values = [str(v) for v in values]

    if "all" in modifiers:
        # every value must match -> one condition per value (Wazuh ANDs them)
        return [(wazuh_field, f"(?i){_pattern_for(scalar_mod, v)}") for v in values]

    # any value may match -> single alternation
    alt = "|".join(_pattern_for(scalar_mod, v) for v in values)
    if len(values) > 1:
        alt = f"(?:{alt})"
    return [(wazuh_field, f"(?i){alt}")]


# --------------------------------------------------------------------------- #
# Condition parsing (deliberately narrow)
# --------------------------------------------------------------------------- #
def _selection_keys_from_condition(condition: str, detection: dict) -> list[str]:
    cond = condition.strip()
    sel_keys = [k for k in detection if k != "condition"]

    if cond in sel_keys:
        return [cond]
    if cond == "selection" and "selection" in detection:
        return ["selection"]

    m = re.fullmatch(r"all of (\w+)\*", cond)
    if m:
        prefix = m.group(1)
        matched = [k for k in sel_keys if k.startswith(prefix)]
        if not matched:
            raise SigmaCompileError(f"'all of {prefix}*' matched no blocks")
        return matched

    if cond == "all of them":
        return sel_keys

    # everything else (or/not/1 of/parenthesised) is out of scope
    raise SigmaCompileError(f"unsupported condition: {condition!r}")


# --------------------------------------------------------------------------- #
# Rule compilation
# --------------------------------------------------------------------------- #
def compile_rule(rule: SigmaRule, rule_id: int) -> WazuhRule:
    logsource = {k: str(v).lower() for k, v in rule.logsource.items()}
    if logsource.get("category") != "process_creation":
        raise SigmaCompileError(
            f"unsupported logsource category: {rule.logsource.get('category')!r}"
        )

    detection = rule.detection
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaCompileError("missing or non-string condition")

    keys = _selection_keys_from_condition(condition, detection)

    field_matches: dict[str, list[str]] = {}
    for key in keys:
        block = detection[key]
        if isinstance(block, list):
            raise SigmaCompileError(
                f"list-of-maps selection block '{key}' (implicit OR) unsupported"
            )
        if not isinstance(block, dict):
            raise SigmaCompileError(f"selection '{key}' is not a mapping")
        for sfield, svalue in block.items():
            for wfield, pattern in _field_to_conditions(sfield, svalue):
                field_matches.setdefault(wfield, []).append(pattern)

    if not field_matches:
        raise SigmaCompileError("no compilable field conditions")

    return WazuhRule(
        rule_id=rule_id,
        level=rule.level.wazuh_level,
        description=rule.title,
        sigma_id=rule.id,
        mitre_ids=rule.attack_techniques,
        field_matches=field_matches,
    )


def compile_directory(directory: str | Path) -> CompileReport:
    report = CompileReport()
    next_id = _BASE_RULE_ID
    for path in iter_sigma_files(directory):
        raw = read_yaml(path)
        try:
            rule = SigmaRule.model_validate(raw)
        except Exception as exc:  # noqa: BLE001 - surface as skip, don't crash
            report.skipped.append((str(path.name), f"parse error: {exc}"))
            continue
        try:
            wrule = compile_rule(rule, next_id)
        except SigmaCompileError as exc:
            report.skipped.append((rule.id, str(exc)))
            log.warning("skip %s: %s", rule.id, exc)
            continue
        report.compiled.append(wrule)
        next_id += 1
    return report


# --------------------------------------------------------------------------- #
# XML rendering
# --------------------------------------------------------------------------- #
_HEADER = """\
<!--
  AUTO-GENERATED by socrepo.sigma_compiler — do not edit by hand.
  Source of truth: detections/sigma/*.yml
  Regenerate with:  socrepo compile
  Requires Wazuh >= 4.7 (PCRE2 field matching) and the Sysmon integration.
-->
<group name="sysmon,socrepo,">
"""
_FOOTER = "</group>\n"


def render_rule_xml(rule: WazuhRule) -> str:
    lines = [
        f'  <rule id="{rule.rule_id}" level="{rule.level}">',
        f'    <if_sid>{rule.if_sid}</if_sid>',
    ]
    for wfield, patterns in rule.field_matches.items():
        for pat in patterns:
            lines.append(
                f'    <field name="{wfield}" type="pcre2">{_xml_escape(pat)}</field>'
            )
    lines.append(f"    <description>{_xml_escape(rule.description)}</description>")
    for tid in rule.mitre_ids:
        lines.append(f'    <mitre><id>{_xml_escape(tid)}</id></mitre>')
    lines.append(f'    <group>{",".join(rule.groups)},</group>')
    lines.append("  </rule>")
    return "\n".join(lines)


def render_xml(report: CompileReport) -> str:
    body = "\n\n".join(render_rule_xml(r) for r in report.compiled)
    return _HEADER + body + "\n" + _FOOTER
