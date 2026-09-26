"""Triage providers.

A provider maps one :class:`~socrepo.models.Alert` to one
:class:`~socrepo.models.TriageResult`. Two are shipped:

* :class:`HeuristicProvider` — deterministic, offline, zero-cost. It encodes the
  rubric as explicit rules over the alert fields. It is the *fallback path for
  when the LLM is unavailable* (a v0.3 requirement) and it is what makes CI and
  the demo reproducible with no API key and no network.
* :class:`AnthropicProvider` — calls a hosted model, parses the structured
  response, and records latency and (approximate, configurable) cost. Any
  failure raises so the engine can fall back.

Both are judged against the same rubric and the same manual labels, so the
evaluation shows exactly how much the LLM buys over the free baseline.
"""

from __future__ import annotations

import os
import re
import time
from typing import Protocol, runtime_checkable

from ..models import Alert, NextAction, TriageResult, Verdict
from ..utils import get_logger
from . import rubric
from .prompts import SYSTEM_PROMPT, build_user_prompt

log = get_logger(__name__)


@runtime_checkable
class TriageProvider(Protocol):
    name: str
    model: str | None

    def available(self) -> bool: ...
    def triage(self, alert: Alert) -> TriageResult: ...


# --------------------------------------------------------------------------- #
# Heuristic provider (deterministic baseline + fallback)
# --------------------------------------------------------------------------- #
_LOLBINS = (
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "schtasks.exe",
    "rundll32.exe",
)
_OFFICE_PARENTS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
_DISCOVERY = ("whoami.exe", "systeminfo.exe", "nltest.exe", "hostname.exe")

# Command-line fragments that indicate a download/transfer LOLBIN *action*.
_DOWNLOAD_MARKERS = ("urlcache", "/transfer", "-transfer")
# Fragments that indicate encoded / hidden execution.
_ENCODED_MARKERS = ("-enc ", "-encodedcommand", "frombase64string", "-w hidden",
                    "downloadstring", "-nop", "iex ")

_URL_RE = re.compile(r"https?://([^/\s\"']+)", re.I)
_FILE_URL_RE = re.compile(r"file://", re.I)
_IP_LITERAL_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)
_INTERNAL_SUFFIXES = (".local", ".corp", ".internal", ".lan")
_REPUTABLE_HOSTS = (
    "raw.githubusercontent.com", "github.com", "cdn.jsdelivr.net",
    "objects.githubusercontent.com",
)
_REMOTE_NODE_RE = re.compile(r"/node:\s*\S+", re.I)


def _classify_destination(command_line: str) -> str:
    """Classify the network destination in a command line.

    Returns one of: ``none``, ``internal``, ``reputable``, ``public_host``,
    ``raw_public_ip``. This is the context a naive tool+flag matcher misses and
    the single biggest driver of triage precision on download LOLBINs.
    """
    m = _URL_RE.search(command_line)
    if not m:
        # file:// is local, treat as no network destination
        return "none"
    host = m.group(1).lower().split(":")[0]
    if _IP_LITERAL_RE.match(host):
        if _PRIVATE_IP_RE.match(host):
            return "internal"
        return "raw_public_ip"
    if host.endswith(_INTERNAL_SUFFIXES):
        return "internal"
    if host in _REPUTABLE_HOSTS:
        return "reputable"
    return "public_host"


class HeuristicProvider:
    """Rule-based triage. No network, no state, fully deterministic.

    This is deliberately a *reasonable* baseline, not a strawman: it incorporates
    the enrichment a detection engineer would add first — destination context
    (internal vs raw public IP), tool *action* (download vs read-only query),
    service-account/maintenance context, and encoded-execution markers.

    What it still cannot do is *reason about business context* — e.g. that a
    `whoami /all` spawned by Outlook seconds after an email open is a phishing
    follow-on, or that a raw-IP download of a named security tool on a test
    subnet is sanctioned. Those context-flip cases are exactly where the LLM
    layer earns its cost, and they show up as the residual errors in the
    confusion matrix.
    """

    name = "heuristic"
    model = "heuristic-v2"

    def available(self) -> bool:  # always
        return True

    # -- signal extraction -------------------------------------------------- #
    @staticmethod
    def _signals(alert: Alert) -> dict[str, bool]:
        img = alert.image.lower()
        cmd = alert.command_line.lower()
        parent = (alert.parent_image or "").lower()
        user = alert.user.lower()

        is_lolbin = any(img.endswith(b) for b in _LOLBINS)
        is_discovery = any(img.endswith(d) for d in _DISCOVERY)
        dest = _classify_destination(alert.command_line)

        is_download_tool = img.endswith(("certutil.exe", "bitsadmin.exe"))
        is_download = is_download_tool and any(mk in cmd for mk in _DOWNLOAD_MARKERS) \
            and dest != "none"
        # read-only / management sub-commands of otherwise-dual-use LOLBINs
        query_only = any(q in cmd for q in (
            " get ", "/list", "/query", "/reset", "csproduct", "bios get",
            "os get", " path ", "triggerschedule", "/change", "/enable",
        )) and not is_download

        remote_exec = ("process call create" in cmd) and bool(_REMOTE_NODE_RE.search(cmd))
        local_wmi_exec = ("process call create" in cmd) and not remote_exec

        squiblydoo = img.endswith("regsvr32.exe") and "/i:" in cmd and "scrobj" in cmd
        mshta_remote = img.endswith("mshta.exe") and (
            bool(_URL_RE.search(alert.command_line)) or bool(_FILE_URL_RE.search(cmd))
        )
        # Inspect the *arguments*, not the whole line — otherwise the ".exe" in
        # "certutil.exe" makes every decode look like it drops an executable.
        args = cmd.split(" ", 1)[1] if " " in cmd else ""
        decode_to_exe = img.endswith("certutil.exe") and (
            "-decode" in cmd or "/decode" in cmd
        ) and any(ext in args for ext in (".exe", ".dll", ".scr", ".bat", ".ps1"))

        # scheduled task *creation* to a user-writable path (persistence)
        task_create_suspicious = img.endswith("schtasks.exe") and "/create" in cmd and \
            any(p in cmd for p in ("\\users\\public\\", "\\appdata\\", "\\temp\\"))
        task_create_benign_path = img.endswith("schtasks.exe") and "/create" in cmd and \
            not task_create_suspicious

        cred_dump = "lsass" in cmd and any(
            t in img for t in ("procdump", "comsvcs", "rundll32")
        )
        # comsvcs.dll MiniDump is credential dumping even when the target is
        # given by PID rather than the literal string "lsass" — a common evasion.
        cred_dump = cred_dump or ("comsvcs" in cmd and "minidump" in cmd)
        # a signed EDR/AV sensor touching lsass is not a dump tool
        cred_dump = cred_dump and not any(
            v in img for v in ("\\edr\\", "sensor.exe", "defender", "mssense")
        )

        office_child_shell = parent.endswith(_OFFICE_PARENTS) and (
            is_lolbin or img.endswith(("powershell.exe", "cmd.exe"))
        )
        system_maintenance = ("system" in user) and (
            parent.endswith(("services.exe", "svchost.exe", "msiexec.exe"))
            or "\\windows\\system32\\" in img
        )
        encoded = any(mk in cmd for mk in _ENCODED_MARKERS)

        # discovery flavour
        recon_flags = is_discovery and any(
            f in cmd for f in ("/all", "/priv", "/groups")
        )
        bare_discovery = is_discovery and not recon_flags

        return {
            "cred_dump": cred_dump,
            "office_child_shell": office_child_shell,
            "download_raw_public_ip": is_download and dest == "raw_public_ip",
            "download_public_host": is_download and dest == "public_host",
            "download_internal": is_download and dest == "internal",
            "download_reputable": is_download and dest == "reputable",
            "remote_exec": remote_exec,
            "local_wmi_exec": local_wmi_exec,
            "squiblydoo_remote": squiblydoo and mshta_remote is False and dest in (
                "raw_public_ip", "public_host"),
            "squiblydoo": squiblydoo,
            "mshta_remote": mshta_remote and dest in ("raw_public_ip", "public_host"),
            "mshta_internal": mshta_remote and dest in ("internal", "reputable"),
            "decode_to_exe": decode_to_exe,
            "task_create_suspicious": task_create_suspicious,
            "task_create_benign_path": task_create_benign_path,
            "encoded_command": encoded,
            "system_maintenance": system_maintenance,
            "query_only": query_only,
            "recon_discovery": recon_flags,
            "bare_discovery": bare_discovery,
        }

    def triage(self, alert: Alert) -> TriageResult:
        t0 = time.perf_counter()
        s = self._signals(alert)

        score = 0.5
        fired: list[str] = []

        def bump(cond: bool, delta: float, label: str) -> None:
            nonlocal score
            if cond:
                score += delta
                fired.append(label)

        # -- escalating signals -------------------------------------------- #
        bump(s["cred_dump"], 0.45, "credential access against lsass")
        bump(s["office_child_shell"], 0.35, "office application spawned a shell/LOLBIN")
        bump(s["squiblydoo"], 0.33, "regsvr32 scriptlet execution (squiblydoo)")
        bump(s["download_raw_public_ip"], 0.32, "download from a raw public IP")
        bump(s["mshta_remote"], 0.30, "mshta fetching a remote payload")
        bump(s["task_create_suspicious"], 0.30, "scheduled task to a user-writable path")
        bump(s["remote_exec"], 0.28, "remote WMI process creation (lateral movement)")
        bump(s["decode_to_exe"], 0.25, "certutil decoding to an executable")
        bump(s["download_public_host"], 0.20, "download from an external host")
        bump(s["encoded_command"], 0.20, "encoded / hidden command line")

        # -- de-escalating signals ----------------------------------------- #
        # Internal/reputable downloads stay in the benign-suspicious band: an
        # unusual tool used against a trusted destination, not a clean close.
        bump(s["download_internal"], -0.12, "download destination is internal")
        bump(s["download_reputable"], -0.08, "download from a reputable host")
        bump(s["system_maintenance"], -0.34, "SYSTEM maintenance context")
        bump(s["query_only"], -0.30, "read-only / management sub-command")
        bump(s["bare_discovery"], -0.34, "routine single discovery command")
        bump(s["mshta_internal"], -0.12, "mshta target is internal")
        bump(s["local_wmi_exec"], -0.12, "local WMI exec with benign payload")
        bump(s["recon_discovery"], -0.05, "verbose discovery flags")

        score = max(0.0, min(1.0, score))

        if score >= 0.70:
            verdict = Verdict.TRUE_POSITIVE
        elif score <= 0.35:
            verdict = Verdict.FALSE_POSITIVE
        else:
            verdict = Verdict.BENIGN_SUSPICIOUS

        # next action
        if verdict is Verdict.TRUE_POSITIVE:
            if score >= 0.9 and (s["cred_dump"] or s["task_create_suspicious"]):
                action = NextAction.ISOLATE_HOST
            else:
                action = NextAction.ESCALATE
        elif verdict is Verdict.BENIGN_SUSPICIOUS:
            action = (
                NextAction.HUNT
                if (s["download_public_host"] or s["office_child_shell"]
                    or s["mshta_internal"] or s["recon_discovery"])
                else NextAction.MONITOR
            )
        else:
            action = NextAction.CLOSE

        confidence = round(min(0.97, 0.5 + abs(score - 0.5) * 0.95), 3)
        if not fired:
            fired = ["no strong signals; severity-only assessment"]
        rationale = (
            f"Heuristic score {score:.2f}. "
            + ("; ".join(fired[:3]) + ".").capitalize()
        )
        latency = (time.perf_counter() - t0) * 1000.0

        return TriageResult(
            alert_id=alert.id,
            verdict=verdict,
            confidence=confidence,
            next_action=action,
            rationale=rationale,
            key_indicators=fired[:6],
            provider=self.name,
            model=self.model,
            latency_ms=round(latency, 3),
            cost_usd=0.0,
            fell_back=False,
        )


# --------------------------------------------------------------------------- #
# Anthropic LLM provider (optional)
# --------------------------------------------------------------------------- #
class AnthropicProvider:
    """Triage via a hosted Anthropic model. Optional dependency + API key.

    Prices are approximate and configurable via env; they exist so the cost
    table is populated, not as a billing source of truth.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str | None = None,
        max_tokens: int = 512,
        price_in_per_mtok: float | None = None,
        price_out_per_mtok: float | None = None,
    ) -> None:
        self.model = model or os.environ.get(
            "SOCREPO_LLM_MODEL", "claude-3-5-haiku-latest"
        )
        self.max_tokens = max_tokens
        self.price_in = price_in_per_mtok or float(
            os.environ.get("SOCREPO_PRICE_IN_PER_MTOK", "0.80")
        )
        self.price_out = price_out_per_mtok or float(
            os.environ.get("SOCREPO_PRICE_OUT_PER_MTOK", "4.00")
        )
        self._client = None

    def available(self) -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def _client_lazy(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic()
        return self._client

    def _estimate_cost(self, usage) -> float:
        try:
            cin = usage.input_tokens / 1_000_000 * self.price_in
            cout = usage.output_tokens / 1_000_000 * self.price_out
            return round(cin + cout, 6)
        except Exception:  # noqa: BLE001
            return 0.0

    def triage(self, alert: Alert) -> TriageResult:
        client = self._client_lazy()
        t0 = time.perf_counter()
        resp = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_user_prompt(alert)}],
        )
        latency = (time.perf_counter() - t0) * 1000.0
        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        )
        return rubric.parse_result(
            text,
            alert_id=alert.id,
            provider=self.name,
            model=self.model,
            latency_ms=round(latency, 2),
            cost_usd=self._estimate_cost(resp.usage),
        )
