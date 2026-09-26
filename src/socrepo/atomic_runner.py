"""Atomic Red Team harness.

Two modes:

``simulate`` (default)
    Executes **nothing**. Replays pre-captured, representative process-creation
    telemetry for each atomic and checks whether the compiled detections match.
    This is what CI and the <10-minute demo use — deterministic, offline, and
    incapable of touching a real host.

``live`` (opt-in, Windows only)
    Shells out to Red Canary's ``Invoke-AtomicTest`` for real adversary
    emulation, then relies on the telemetry actually reaching Wazuh. Guarded by
    an explicit flag *and* an environment variable so it can never fire by
    accident. This is the only code path that can execute test procedures, and
    it is off by default.

The scope/telemetry are data files, so extending coverage means adding YAML/JSON,
not editing code.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from .detection_engine import match_event
from .models import AtomicTest, ValidationResult, WazuhRule
from .utils import DATA_DIR, get_logger, read_jsonl, read_yaml

log = get_logger(__name__)

_TELEMETRY = DATA_DIR / "validation" / "atomic_telemetry.jsonl"
_SCOPE = DATA_DIR / "mappings" / "attack_scope.yaml"
_LIVE_ENV_GUARD = "SOCREPO_ALLOW_LIVE_ATOMICS"


def load_scope(path: str | Path = _SCOPE) -> dict[str, dict]:
    return read_yaml(path)


def load_atomics(path: str | Path = _SCOPE) -> list[AtomicTest]:
    scope = load_scope(path)
    tests: list[AtomicTest] = []
    for tid, meta in scope.items():
        for atomic in meta.get("atomics", []):
            tests.append(
                AtomicTest(
                    technique_id=tid,
                    technique_name=meta["name"],
                    auto_guid=atomic["guid"],
                    name=atomic["name"],
                    executor=atomic.get("executor", "command_prompt"),
                    destructive=atomic.get("destructive", False),
                )
            )
    return tests


# --------------------------------------------------------------------------- #
# simulate mode
# --------------------------------------------------------------------------- #
def _load_telemetry(path: str | Path = _TELEMETRY) -> dict[str, dict]:
    """Map ``auto_guid -> event`` from the captured telemetry fixtures."""
    out: dict[str, dict] = {}
    for row in read_jsonl(path):
        out[row["auto_guid"]] = row["event"]
    return out


def run_simulated(
    rules: list[WazuhRule],
    scope_path: str | Path = _SCOPE,
    telemetry_path: str | Path = _TELEMETRY,
) -> list[ValidationResult]:
    """Replay telemetry and record whether detections fire. Executes nothing."""
    atomics = load_atomics(scope_path)
    telemetry = _load_telemetry(telemetry_path)
    results: list[ValidationResult] = []

    for atomic in atomics:
        event = telemetry.get(atomic.auto_guid)
        if event is None:
            results.append(
                ValidationResult(
                    technique_id=atomic.technique_id,
                    auto_guid=atomic.auto_guid,
                    attempted=True,
                    validated=False,
                    notes="no captured telemetry for this atomic",
                )
            )
            continue

        matched = match_event(rules, event)
        results.append(
            ValidationResult(
                technique_id=atomic.technique_id,
                auto_guid=atomic.auto_guid,
                attempted=True,
                validated=bool(matched),
                matched_rule_ids=[str(m) for m in matched],
                notes=None if matched else "no compiled rule matched the telemetry",
            )
        )
    return results


# --------------------------------------------------------------------------- #
# live mode (opt-in, Windows only)
# --------------------------------------------------------------------------- #
def _invoke_atomic_cmd(guid: str, check_prereqs: bool) -> list[str]:
    """Construct the Invoke-AtomicTest PowerShell invocation for one GUID."""
    verb = "-GetPrereqs" if check_prereqs else ""
    ps = (
        "Import-Module invoke-atomicredteam -Force; "
        f"Invoke-AtomicTest All -TestGuids {guid} {verb} -TimeoutSeconds 120"
    ).strip()
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]


def run_live(atomics: list[AtomicTest]) -> list[ValidationResult]:
    """Execute real atomics. Refuses to run unless explicitly authorised.

    Validation of *detection firing* in live mode is intentionally left to the
    Wazuh pipeline + ``socrepo ingest`` on the resulting alerts — this function
    only performs the emulation and records that it was attempted.
    """
    if os.environ.get(_LIVE_ENV_GUARD) != "1":
        raise RuntimeError(
            f"live atomic execution is disabled. Set {_LIVE_ENV_GUARD}=1 and pass "
            "--live to authorise real adversary emulation on THIS host."
        )
    if platform.system() != "Windows":
        raise RuntimeError(
            "live mode requires Windows with Sysmon + the invoke-atomicredteam "
            "module installed. Use simulate mode elsewhere."
        )
    if shutil.which("powershell") is None:
        raise RuntimeError("powershell not found on PATH")

    results: list[ValidationResult] = []
    for atomic in atomics:
        log.warning("LIVE atomic %s (%s) — executing", atomic.auto_guid, atomic.name)
        proc = subprocess.run(  # noqa: S603 - intentional, guarded, opt-in
            _invoke_atomic_cmd(atomic.auto_guid, check_prereqs=False),
            capture_output=True,
            text=True,
            timeout=180,
        )
        ok = proc.returncode == 0
        results.append(
            ValidationResult(
                technique_id=atomic.technique_id,
                auto_guid=atomic.auto_guid,
                attempted=True,
                validated=False,  # detection firing confirmed via SIEM ingest
                notes=f"executed rc={proc.returncode}; confirm firing via SIEM"
                if ok
                else f"execution failed rc={proc.returncode}: {proc.stderr[:200]}",
            )
        )
    return results
