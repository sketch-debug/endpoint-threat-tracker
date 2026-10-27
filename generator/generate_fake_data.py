"""Realistic fake-data generator for the Endpoint Threat Detection tool.

FAKE DATA ONLY. Generates seven days of exported logs and inventories for a
small office fleet, including a simulated multi-PC cryptomining incident and
a ransomware incident, so the whole workflow (detect -> correlate -> incident
-> workflow -> re-check -> report) can be demoed end to end without any real
systems. A noisy-but-benign PC (PC-MKT-06) adds a lone unsigned process, a
lone off-hours login and a new-software persistence trio; it only crosses the
alert threshold when the meta gates are disabled, so gate tuning is
measurable. Everything is deterministic for a given --seed.

Usage:
    python generator/generate_fake_data.py                 # write into samples/
    python generator/generate_fake_data.py --into-inbox    # write into the inbox
    python generator/generate_fake_data.py --days 3        # shorter story

File naming follows the dispatch prefixes in app/parsers/dispatch.py:
    dns_generic_*.csv, dns_adguard_*.jsonl, dns_technitium_*.csv,
    fw_connections_*.csv, defender_detections_*.csv, events_*.csv,
    process_inv_*, tasks_inv_*, persistence_inv_*, defender_status_*,
    file_activity_*
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---- fake fleet ------------------------------------------------------------
# ip -> hostname (mirrors config/ip_map.txt)
FLEET = {
    "192.168.10.21": "PC-LAB-01",    # miner victim
    "192.168.10.22": "PC-LAB-02",    # miner victim (Defender disabled)
    "192.168.10.23": "PC-OPS-03",    # miner victim (+ RAT, login burst)
    "192.168.10.24": "PC-FIN-02",    # ransomware victim
    "192.168.10.31": "PC-HR-04",     # clean
    "192.168.10.32": "PC-FIN-01",    # clean (one weak signal: office->powershell)
    "192.168.10.33": "PC-DEV-02",    # clean
    "192.168.10.34": "PC-EXEC-05",   # clean
    "192.168.10.35": "PC-MKT-06",    # noisy but benign (meta-gate demo)
}
MINER_PCS = ["192.168.10.21", "192.168.10.22", "192.168.10.23"]
CLEAN_PCS = ["192.168.10.31", "192.168.10.32", "192.168.10.33", "192.168.10.34"]
RANSOM_PC = "192.168.10.24"
NOISY_PC = "192.168.10.35"
NOISY_TOOL = r"C:\Program Files\Acme\AcmeSync.exe"
NOISY_HASH = "b" * 64               # deliberately NOT in bad_hashes.txt

# values matched by config/indicators (all fake)
POOL = "xmr.pool.fake-example.test"
POOL2 = "pool.example-mining.test"
C2 = "c2.fake-malware.test"
MINER_PORT = 14444
MINER_DST = "203.0.113.50"          # TEST-NET-3, documentation range
MINER_DST2 = "203.0.113.51"
MINER_HASH = "a" * 64               # listed in config/indicators/bad_hashes.txt
MINER_PATH = r"C:\Users\Public\Libs\xmrig.exe"   # matches \public\ path list
MINER_TASK = r"\SystemHealthCheck"
MINER_SERVICE = "WinSysHelper"
RANSOM_EXT = ".locked"
RANSOM_NOTE = "README-LOCKED.txt"
MINER_THREAT = "Trojan:Win32/CoinMiner.MS"
RANSOM_THREAT = "Ransom:Win32/Wacatac.B!ml"

BENIGN_DOMAINS = [
    ("www.microsoft.com", "A"), ("login.windows.net", "A"),
    ("outlook.office365.com", "A"), ("cdn.contoso.test", "A"),
    ("docs.python.org", "A"), ("portal.azure.com", "A"),
    ("www.youtube.com", "A"), ("updates.vendor-example.test", "A"),
]
BENIGN_DST = [("40.126.32.10", 443), ("13.107.42.14", 443), ("151.101.1.69", 80)]

USERS = ["alice", "bob", "carol", "dan", "svc_backup", "jenkins_svc"]


def ts(rng: random.Random, day: int, hh: int, mm: int | None = None,
       ss: int | None = None) -> str:
    """Local-time ISO timestamp `day` days ago (day 0 = today)."""
    base = datetime.now().replace(hour=hh, minute=mm if mm is not None
                                  else rng.randrange(0, 60),
                                  second=ss if ss is not None
                                  else rng.randrange(0, 60), microsecond=0)
    return (base - timedelta(days=day)).strftime("%Y-%m-%dT%H:%M:%S")


def utc_ts(day: int, hh: int, mm: int = 0, ss: int = 0) -> str:
    """UTC ISO timestamp for `day` days ago at local hh:mm:ss.

    The rest of the generator writes local wall-clock strings without an
    offset (the parsers treat those as UTC). The off-hours scenario converts
    explicitly so 02:10 is off-hours in local time on any host timezone.
    """
    local = datetime.now().replace(
        hour=hh, minute=mm, second=ss, microsecond=0) - timedelta(days=day)
    return local.astimezone().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_csv(path: Path, header: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


# ---- per-day builders ------------------------------------------------------
def dns_rows(rng: random.Random, day: int) -> list[dict]:
    rows: list[dict] = []
    for ip in FLEET:
        for _ in range(rng.randint(3, 6)):
            domain, qtype = rng.choice(BENIGN_DOMAINS)
            rows.append({"timestamp": ts(rng, day, rng.randrange(8, 18)),
                         "client_ip": ip, "domain": domain, "qtype": qtype})
    if day <= 5:  # miners start querying pools on day 5
        for ip in MINER_PCS:
            for hour in (9, 13, 17, 23):
                rows.append({"timestamp": ts(rng, day, hour),
                             "client_ip": ip, "domain":
                             POOL if hour % 2 else POOL2, "qtype": "A"})
        rows.append({"timestamp": ts(rng, day, 23, 41), "client_ip": MINER_PCS[0],
                     "domain": C2, "qtype": "A"})
    return rows


def adguard_rows(rng: random.Random, day: int) -> list[dict]:
    """AdGuard Home querylog.json (JSON Lines) for one PC/day."""
    rows = []
    ip = MINER_PCS[0]
    for hour in (9, 12, 16, 22):
        rows.append({"T": ts(rng, day, hour), "QH": POOL, "IP": ip, "QT": "A",
                     "OK": True, "AnswerIP": MINER_DST})
    for _ in range(4):
        domain, qtype = rng.choice(BENIGN_DOMAINS)
        rows.append({"T": ts(rng, day, rng.randrange(8, 20)), "QH": domain,
                     "IP": ip, "QT": qtype, "OK": True})
    return rows


def technitium_rows(rng: random.Random, day: int) -> list[dict]:
    """Technitium CSV export (GUI column names)."""
    rows = []
    ip = MINER_PCS[1]
    rows.append({"Time": ts(rng, day, 10), "Client": ip, "Domain": POOL2,
                 "Query Type": "A", "Reply": "NOERROR"})
    for _ in range(3):
        domain, qtype = rng.choice(BENIGN_DOMAINS)
        rows.append({"Time": ts(rng, day, rng.randrange(8, 18)), "Client": ip,
                     "Domain": domain, "Query Type": qtype, "Reply": "NOERROR"})
    return rows


def fw_rows(rng: random.Random, day: int) -> list[dict]:
    rows: list[dict] = []
    for ip in FLEET:
        for _ in range(rng.randint(2, 4)):
            dst, port = rng.choice(BENIGN_DST)
            rows.append({"timestamp": ts(rng, day, rng.randrange(8, 18)),
                         "client_ip": ip, "dst_ip": dst, "port": port,
                         "duration": rng.randint(2, 90), "proto": "tcp"})
    if day <= 5:
        for ip in MINER_PCS:
            rows.append({"timestamp": ts(rng, day, rng.randrange(8, 20)),
                         "client_ip": ip, "dst_ip": MINER_DST,
                         "port": MINER_PORT, "duration": rng.randint(1800, 7200),
                         "proto": "tcp"})
            rows.append({"timestamp": ts(rng, day, rng.randrange(8, 20)),
                         "client_ip": ip, "dst_ip": MINER_DST2,
                         "port": 4444, "duration": rng.randint(900, 3600),
                         "proto": "tcp"})
    return rows


def defender_detection_rows(rng: random.Random, day: int) -> list[dict]:
    rows: list[dict] = []
    if day == 2:
        for ip in (MINER_PCS[0], MINER_PCS[1]):
            rows.append({"timestamp": ts(rng, day, 11), "hostname": FLEET[ip],
                         "threat_name": MINER_THREAT, "severity": "High",
                         "category": "Trojan", "process_name": "xmrig.exe",
                         "resources": MINER_PATH + "|" + MINER_HASH,
                         "action": "Quarantine", "threat_status": "Contained"})
        rows.append({"timestamp": ts(rng, day, 11, 20), "hostname": FLEET[RANSOM_PC],
                     "threat_name": RANSOM_THREAT, "severity": "Severe",
                     "category": "Ransomware", "process_name": "svchostw.exe",
                     "resources": r"C:\Users\Public\Libs\svchostw.exe",
                     "action": "Quarantine", "threat_status": "Contained"})
    return rows


def event_rows(rng: random.Random, day: int) -> list[dict]:
    """Windows Event Log export: 4688/4698/7045/4720/1102/4624/4625/5001/5007."""
    rows: list[dict] = []

    def ev(eid: int, computer: str, hour: int, data: dict,
           provider: str = "Microsoft-Windows-Security-Auditing") -> dict:
        return {"timestamp": ts(rng, day, hour), "event_id": eid,
                "computer": computer, "provider": provider, "level": "Information",
                "data_json": json.dumps(data)}

    if day <= 5:
        for ip in MINER_PCS:
            host = FLEET[ip]
            rows.append(ev(4688, host, 9, {
                "NewProcessName": MINER_PATH,
                "ParentProcessName": r"C:\Windows\System32\svchost.exe",
                "CommandLine": f'"{MINER_PATH}" -o {POOL}:4444 -u '
                               f"worker-{host.lower()} -p x --coin monero",
                "SubjectUserName": "SYSTEM"}))
            rows.append(ev(4698, host, 9, {
                "TaskName": MINER_TASK,
                "TaskContent": f"<Command>{MINER_PATH}</Command>",
                "SubjectUserName": "SYSTEM"}))
            rows.append(ev(7045, host, 9, {
                "ServiceName": MINER_SERVICE,
                "ServiceFileName": MINER_PATH,
                "ServiceType": "user mode service",
                "StartType": "auto start"}))
        rows.append(ev(4688, FLEET[MINER_PCS[0]], 22, {
            "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentProcessName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            "SubjectUserName": "alice"}))
    if day in (0, 1):  # weak single signal on a clean PC: logged, no incident
        rows.append(ev(4688, FLEET["192.168.10.32"], 11, {
            "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentProcessName": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            "CommandLine": "powershell.exe -NoProfile -Command Get-Process | Out-File x.csv",
            "SubjectUserName": "carol"}))
    if day == 3:
        host = FLEET[MINER_PCS[1]]
        rows.append(ev(5001, host, 10, {"Path": "Real-Time Protection",
                                        "NewValue": "Disabled"},
                       provider="Microsoft-Windows-Windows Defender"))
        rows.append(ev(5007, host, 10, {
            "Path": r"Real-Time Protection\Exclusions\Paths",
            "OldValue": "", "NewValue": r"C:\Users\Public\Libs"},
            provider="Microsoft-Windows-Windows Defender"))
    if day == 2:
        host = FLEET[RANSOM_PC]
        rows.append(ev(4688, host, 14, {
            "NewProcessName": r"C:\Windows\System32\vssadmin.exe",
            "CommandLine": "vssadmin delete shadows /all /quiet",
            "SubjectUserName": "svc_backup"}))
        rows.append(ev(1102, host, 14, {"SubjectUserName": "svc_backup"},
                       provider="Microsoft-Windows-Eventlog"))
        rows.append(ev(4720, host, 14, {
            "TargetUserName": "helpdesk_support",
            "SubjectUserName": "svc_backup"}))
        rows.append(ev(4732, host, 14, {
            "MemberName": "helpdesk_support",
            "SubjectUserName": "svc_backup"}))
    if day == 3:  # failed-login burst then success on PC-OPS-03
        host = FLEET[MINER_PCS[2]]
        minute = 5
        for _ in range(6):
            row = ev(4625, host, 2, {
                "TargetUserName": "jenkins_svc", "IpAddress": "10.99.0.55",
                "LogonType": "3"})
            row["timestamp"] = ts(rng, day, 2, minute)
            rows.append(row)
            minute += 1
        row = ev(4624, host, 2, {
            "TargetUserName": "jenkins_svc", "IpAddress": "10.99.0.55",
            "LogonType": "3"})
        row["timestamp"] = ts(rng, day, 2, minute)
        rows.append(row)
    if day in (0, 1):  # normal daytime logons for the clean fleet
        for ip in CLEAN_PCS:
            for _ in range(2):
                rows.append(ev(4624, FLEET[ip], rng.randrange(8, 10), {
                    "TargetUserName": rng.choice(USERS[:4]),
                    "IpAddress": ip, "LogonType": "3"}))

    # Noisy-but-benign PC: known daytime source first, then one lone
    # off-hours login with no burst and no unfamiliar source. With the meta
    # gates on, acct_offhours_login does not score; with them off it adds 5.
    noisy_host = FLEET[NOISY_PC]
    if day in (1, 2):
        for minute in (0, 30):
            row = ev(4624, noisy_host, 10, {
                "TargetUserName": "mkt_svc", "IpAddress": "192.168.10.31",
                "LogonType": "3"})
            row["timestamp"] = utc_ts(day, 10, minute)
            rows.append(row)
    if day == 0:
        row = ev(4624, noisy_host, 2, {
            "TargetUserName": "mkt_svc", "IpAddress": "192.168.10.31",
            "LogonType": "3"})
        row["timestamp"] = utc_ts(day, 2, 10)
        rows.append(row)
    return rows


def process_inv_rows(rng: random.Random, ip: str, day: int, infected: bool,
                     overnight_cpu: bool = False) -> list[dict]:
    host = FLEET[ip]
    hour = 2 if overnight_cpu else 9
    rows = [
        {"timestamp": ts(rng, day, hour), "hostname": host, "ip": ip,
         "pid": 1204, "ppid": 900, "name": "explorer.exe",
         "path": r"C:\Windows\explorer.exe", "user": "alice",
         "cpu_percent": rng.randint(2, 12), "memory_mb": rng.randint(120, 400),
         "signature_status": "Valid", "signer": "Microsoft Windows",
         "sha256": "b1946ac92492d2347c6235b4d2611184" + "0" * 32},
        {"timestamp": ts(rng, day, hour), "hostname": host, "ip": ip,
         "pid": 1310, "ppid": 900, "name": "chrome.exe",
         "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
         "user": "alice", "cpu_percent": rng.randint(5, 30),
         "memory_mb": rng.randint(300, 900), "signature_status": "Valid",
         "signer": "Google LLC", "sha256": "c" * 64},
    ]
    if infected:
        rows.append({
            "timestamp": ts(rng, day, hour), "hostname": host, "ip": ip,
            "pid": 4412, "ppid": 900, "name": "xmrig.exe", "path": MINER_PATH,
            "user": "SYSTEM",
            "cpu_percent": rng.randint(92, 99) if overnight_cpu else rng.randint(40, 80),
            "memory_mb": rng.randint(300, 700), "signature_status": "NotSigned",
            "signer": "", "sha256": MINER_HASH})
        if ip == MINER_PCS[2]:
            rows.append({
                "timestamp": ts(rng, day, hour), "hostname": host, "ip": ip,
                "pid": 4500, "ppid": 4412, "name": "anydesk.exe",
                "path": r"C:\Program Files\AnyDesk\AnyDesk.exe", "user": "alice",
                "cpu_percent": 1, "memory_mb": 60, "signature_status": "Valid",
                "signer": "AnyDesk Software GmbH", "sha256": "d" * 64})
    elif rng.random() < 0.3:
        rows.append({
            "timestamp": ts(rng, day, hour), "hostname": host, "ip": ip,
            "pid": 2210, "ppid": 900, "name": "outlook.exe",
            "path": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            "user": "alice", "cpu_percent": rng.randint(3, 15),
            "memory_mb": rng.randint(200, 500), "signature_status": "Valid",
            "signer": "Microsoft Windows", "sha256": "e" * 64})
    if ip == NOISY_PC and day == 0:
        # Signed-software install left an unsigned vendor helper running from
        # a normal path: proc_unsigned alone, no suspicious path / bad hash.
        rows.append({
            "timestamp": ts(rng, day, hour), "hostname": host, "ip": ip,
            "pid": 3310, "ppid": 900, "name": "AcmeSync.exe",
            "path": NOISY_TOOL, "user": "mkt_svc", "cpu_percent": 2,
            "memory_mb": 90, "signature_status": "NotSigned", "signer": "",
            "sha256": NOISY_HASH})
    return rows


def tasks_inv_rows(rng: random.Random, ip: str, day: int, infected: bool) -> list[dict]:
    host = FLEET[ip]
    rows = [{"timestamp": ts(rng, day, 9), "hostname": host,
             "task_name": r"\MicrosoftEdgeUpdateTaskMachineCore",
             "task_path": "\\", "status": "Ready",
             "command": r"C:\Program Files\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
             "arguments": "/c", "user": "SYSTEM"}]
    if infected:
        rows.append({"timestamp": ts(rng, day, 9), "hostname": host,
                     "task_name": MINER_TASK, "task_path": "\\",
                     "status": "Ready", "command": MINER_PATH,
                     "arguments": "-o stratum+tcp://pool:4444", "user": "SYSTEM"})
    if ip == NOISY_PC and day == 0:
        rows.append({"timestamp": ts(rng, day, 9), "hostname": host,
                     "task_name": r"\AcmeSyncUpdate", "task_path": "\\",
                     "status": "Ready", "command": NOISY_TOOL,
                     "arguments": "--silent", "user": "SYSTEM"})
    return rows


def persistence_inv_rows(rng: random.Random, ip: str, day: int,
                         infected: bool) -> list[dict]:
    host = FLEET[ip]
    # The noisy PC uses a different benign autostart so its correlation keys
    # cannot overlap the miner incident's OneDrive command line.
    base_item = "Dropbox" if ip == NOISY_PC else "OneDrive"
    base_cmd = (r"C:\Program Files\Dropbox\Dropbox.exe" if ip == NOISY_PC
                else r"C:\Program Files\Microsoft OneDrive\OneDrive.exe")
    rows = [{"timestamp": ts(rng, day, 9), "hostname": host, "category": "run_key",
             "item_name": base_item, "details": "sync client",
             "command": base_cmd}]
    if infected:
        rows += [
            {"timestamp": ts(rng, day, 9), "hostname": host, "category": "service",
             "item_name": MINER_SERVICE, "details": "auto start, LocalSystem",
             "command": MINER_PATH},
            {"timestamp": ts(rng, day, 9), "hostname": host, "category": "run_key",
             "item_name": "WindowsHealth", "details": "miner autorun",
             "command": MINER_PATH},
            {"timestamp": ts(rng, day, 9), "hostname": host,
             "category": "scheduled_task", "item_name": MINER_TASK,
             "details": "runs at logon and daily 02:00", "command": MINER_PATH},
        ]
    if ip == NOISY_PC and day == 0:
        # Benign installer footprint: three new-but-harmless persistence items
        # (10 + 10 + 10); combined with the two gated signals it reaches 40.
        rows += [
            {"timestamp": ts(rng, day, 9), "hostname": host, "category": "run_key",
             "item_name": "AcmeSync", "details": "vendor autostart",
             "command": NOISY_TOOL},
            {"timestamp": ts(rng, day, 9), "hostname": host, "category": "service",
             "item_name": "AcmeSyncSvc", "details": "auto start, LocalSystem",
             "command": NOISY_TOOL},
            {"timestamp": ts(rng, day, 9), "hostname": host,
             "category": "scheduled_task", "item_name": r"\AcmeSyncUpdate",
             "details": "daily update check", "command": NOISY_TOOL},
        ]
    return rows


def defender_status_rows(rng: random.Random, ip: str, day: int,
                         tampered: bool) -> list[dict]:
    host = FLEET[ip]
    row = {"timestamp": ts(rng, day, 9), "hostname": host,
           "real_time_protection": "disabled" if tampered else "enabled",
           "service_status": "running",
           "exclusions": json.dumps([r"C:\Users\Public\Libs"]) if tampered else "[]",
           "behavior_monitor": "disabled" if tampered else "enabled",
           "ioav_protection": "enabled", "tamper_protection": "enabled"}
    return [row]


def file_activity_rows(rng: random.Random, day: int) -> list[dict]:
    """Ransomware burst: 24 renames in 4 minutes plus the note file."""
    host = FLEET[RANSOM_PC]
    rows: list[dict] = []
    start = datetime.now().replace(hour=14, minute=20, second=0, microsecond=0) \
        - timedelta(days=day)
    for i in range(24):
        moment = (start + timedelta(seconds=i * 9)).strftime("%Y-%m-%dT%H:%M:%S")
        rows.append({"timestamp": moment, "hostname": host,
                     "file_path": rf"C:\Users\alice\Documents\Q4Report{i:02d}.docx{RANSOM_EXT}",
                     "action": "renamed", "process_name": r"C:\Users\Public\Libs\svchostw.exe",
                     "sha256": "f" * 64})
    rows.append({"timestamp": (start + timedelta(seconds=240)).strftime("%Y-%m-%dT%H:%M:%S"),
                 "hostname": host,
                 "file_path": rf"C:\Users\alice\Documents\{RANSOM_NOTE}",
                 "action": "created",
                 "process_name": r"C:\Users\Public\Libs\svchostw.exe",
                 "sha256": "f" * 64})
    return rows


# ---- orchestration ---------------------------------------------------------
def generate(out_dir: Path, days: int, seed: int) -> list[Path]:
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    def stamp(day: int) -> str:
        return (today - timedelta(days=day)).strftime("%Y%m%d")

    def emit(name: str, header: list[str] | None, rows: list[dict],
             jsonl: bool = False) -> None:
        if not rows:
            return
        path = out_dir / name
        if jsonl:
            write_jsonl(path, rows)
        else:
            write_csv(path, header or list(rows[0].keys()), rows)
        written.append(path)

    for day in range(days, -1, -1):
        d = stamp(day)
        infected_now = day <= 5

        # DNS (generic CSV fleet-wide; AdGuard + Technitium format samples)
        emit(f"dns_generic_{d}.csv",
             ["timestamp", "client_ip", "domain", "qtype"], dns_rows(rng, day))
        if day == 4:
            emit(f"dns_adguard_{d}.jsonl", None, adguard_rows(rng, day), jsonl=True)
        if day == 3:
            emit(f"dns_technitium_{d}.csv",
                 ["Time", "Client", "Domain", "Query Type", "Reply"],
                 technitium_rows(rng, day))

        # firewall connections
        emit(f"fw_connections_{d}.csv",
             ["timestamp", "client_ip", "dst_ip", "port", "duration", "proto"],
             fw_rows(rng, day))

        # Defender detections
        emit(f"defender_detections_{d}.csv",
             ["timestamp", "hostname", "threat_name", "severity", "category",
              "process_name", "resources", "action", "threat_status"],
             defender_detection_rows(rng, day))

        # events
        emit(f"events_{d}.csv",
             ["timestamp", "event_id", "computer", "provider", "level", "data_json"],
             event_rows(rng, day))

        # inventories: baseline + current for everyone; daily for miner PCs
        for ip in list(FLEET):
            infected = infected_now and ip in MINER_PCS
            emit_inventory = day in (days, 0) or infected
            if not emit_inventory:
                continue
            s = stamp(day)
            emit(f"process_inv_{s}_0900_{FLEET[ip]}.csv",
                 ["timestamp", "hostname", "ip", "pid", "ppid", "name", "path",
                  "user", "cpu_percent", "memory_mb", "signature_status",
                  "signer", "sha256"],
                 process_inv_rows(rng, ip, day, infected))
            emit(f"tasks_inv_{s}_0900_{FLEET[ip]}.csv",
                 ["timestamp", "hostname", "task_name", "task_path", "status",
                  "command", "arguments", "user"],
                 tasks_inv_rows(rng, ip, day, infected))
            emit(f"persistence_inv_{s}_0900_{FLEET[ip]}.csv",
                 ["timestamp", "hostname", "category", "item_name", "details",
                  "command"],
                 persistence_inv_rows(rng, ip, day, infected))
            tampered = infected and ip == MINER_PCS[1]
            emit(f"defender_status_{s}_0900_{FLEET[ip]}.csv",
                 ["timestamp", "hostname", "real_time_protection",
                  "service_status", "exclusions", "behavior_monitor",
                  "ioav_protection", "tamper_protection"],
                 defender_status_rows(rng, ip, day, tampered))
            if infected:
                emit(f"process_inv_{s}_0215_{FLEET[ip]}.csv",
                     ["timestamp", "hostname", "ip", "pid", "ppid", "name",
                      "path", "user", "cpu_percent", "memory_mb",
                      "signature_status", "signer", "sha256"],
                     process_inv_rows(rng, ip, day, infected, overnight_cpu=True))

        # ransomware file activity
        if day == 2:
            emit(f"file_activity_{d}_{FLEET[RANSOM_PC]}.csv",
                 ["timestamp", "hostname", "file_path", "action", "process_name",
                  "sha256"], file_activity_rows(rng, day))

    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(ROOT / "samples"),
                        help="output directory (default: samples/)")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--days", type=int, default=6,
                        help="days of history to generate (default 6)")
    parser.add_argument("--into-inbox", action="store_true",
                        help="copy files into the configured inbox folder")
    args = parser.parse_args()

    written = generate(Path(args.out), args.days, args.seed)
    print(f"generated {len(written)} fake files in {args.out} "
          f"(seed={args.seed}, days={args.days})")
    for path in written[:8]:
        print(f"  e.g. {path.name}")
    print("  ...")

    if args.into_inbox:
        from app.config import Settings
        settings = Settings()
        settings.ensure_dirs()
        import shutil
        for path in written:
            shutil.copy2(path, settings.inbox_dir / path.name)
        print(f"copied {len(written)} files into {settings.inbox_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
