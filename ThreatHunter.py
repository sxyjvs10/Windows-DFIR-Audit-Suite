#!/usr/bin/env python3
"""
================================================================================
  WINDOWS THREAT HUNTER — Automated Security Audit Tool
  Author  : Antigravity AI
  Version : 1.0
  Usage   : Run as Administrator → python ThreatHunter.py
  Output  : Console report + ThreatHunter_Report_<timestamp>.txt on Desktop
================================================================================
"""

import subprocess
import os
import sys
import json
import socket
import winreg
import hashlib
import datetime
import platform
from pathlib import Path
from collections import defaultdict

# Fix Windows console Unicode encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ['PYTHONIOENCODING'] = 'utf-8'


# ─── ANSI COLORS ────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"


# ─── GLOBALS ────────────────────────────────────────────────────────────────

FLAGS        = []          # All red flags found
SCORE        = 0           # Risk score
REPORT_LINES = []          # Lines for the text report
START_TIME   = datetime.datetime.now()

DESKTOP = Path(os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Public"),
                             "OneDrive", "Desktop"))
if not DESKTOP.exists():
    DESKTOP = Path(os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Public"),
                                "Desktop"))

REPORT_FILE = DESKTOP / f"ThreatHunter_Report_{START_TIME.strftime('%Y%m%d_%H%M%S')}.txt"


# ─── KNOWN GOOD / BAD LISTS ─────────────────────────────────────────────────

MINER_NAMES = [
    'xmrig','xmr','miner','mine','cryptonight','ethminer','claymore',
    'nicehash','nanominer','minerd','cgminer','bfgminer','cpuminer',
    'nbminer','phoenixminer','lolminer','gminer','teamredminer','trex',
    'wildrig','cast_xmr','srv32','svchosts','taskhost32','winlogin',
    'csrss32','lsm32','conhost32','dllhost32'
]

MINING_PORTS = {3333, 3334, 4444, 5555, 7777, 8888, 9999,
                14444, 14433, 45560, 45700, 20535, 13531}

RAT_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234,
             31337, 1337, 12345, 54321, 65535}

SYSTEM_PROCS_NO_PATH = {
    'idle','system','memory compression','registry',
    'secure system','csrss','smss','wininit','fontdrvhost'
}

LEGIT_SYSTEM_PROCS = {
    'svchost','lsass','csrss','winlogon','explorer',
    'taskhost','taskhostw','sihost','runtimebroker'
}

SYSTEM32 = "c:\\windows\\system32"
SYSWOW64 = "c:\\windows\\syswow64"

# Suspicious base locations — only Temp folders and Public are truly suspicious
# AppData/LocalAppData are semi-trusted (many legit apps install there)
SUSPICIOUS_LOCATIONS = [
    os.environ.get('TEMP',''),
    os.path.join(os.environ.get('LOCALAPPDATA',''), 'Temp'),
    'C:\\Windows\\Temp',
    'C:\\Users\\Public',
]

# Whitelisted AppData sub-paths (known legitimate apps that live in AppData)
APPDATA_WHITELIST = [
    'onedrive', 'bravesoftware', 'greenshot', 'microsoft', 'google',
    'mozilla', 'discord', 'slack', 'vscode', 'code', 'steam', 'spotify',
    'zoom', 'teams', 'telegram', 'whatsapp', 'figma', 'notion',
    '\\programs\\', 'kingsoft', 'agy', 'antigravity', 'nvidia',
    'windowsapps', 'packages', 'kaspersky', 'rider', 'jetbrains',
]

# Run key values that are legitimate even if they look suspicious
RUN_KEY_WHITELIST = [
    'onedrive', 'bravesoftware', 'greenshot', '\\programs\\',
    'microsoft', 'google', 'nvidia', 'realtek', 'kingsoft', 'agy',
    'securityhealth', 'xmousebuttoncontrol', 'nearbyshare',
]

MINING_POOL_DOMAINS = [
    'minexmr.com','supportxmr.com','nanopool.org','slushpool.com',
    'antpool.com','f2pool.com','nicehash.com','pool.hashvault.pro',
    '2miners.com','miningpoolhub.com','viahbtc.com','coinhive.com',
    'coin-hive.com','cryptoloot.pro','webminepool.com'
]


# ─── HELPERS ────────────────────────────────────────────────────────────────

def banner():
    b = f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║          WINDOWS THREAT HUNTER  v1.0  — AUTO SECURITY AUDIT     ║
║          Started : {START_TIME.strftime("%Y-%m-%d %H:%M:%S")}                        ║
║          Host    : {platform.node():<43} ║
╚══════════════════════════════════════════════════════════════════╝
{C.RESET}"""
    print(b)
    report(b, raw=True)


def section(title):
    line = f"\n{'═'*68}\n  {title}\n{'═'*68}"
    print(f"\n{C.CYAN}{C.BOLD}{line}{C.RESET}")
    report(f"\n{'='*68}\n  {title}\n{'='*68}")


def subsection(title):
    print(f"\n{C.BLUE}{C.BOLD}  ▶ {title}{C.RESET}")
    report(f"\n  >> {title}")


def ok(msg):
    print(f"  {C.GREEN}✓{C.RESET}  {msg}")
    report(f"  [OK]  {msg}")


def warn(msg, flag=True):
    global SCORE
    print(f"  {C.YELLOW}⚠{C.RESET}  {C.YELLOW}{msg}{C.RESET}")
    report(f"  [WARN]  {msg}")
    if flag:
        FLAGS.append(("WARN", msg))
        SCORE += 1


def bad(msg, flag=True):
    global SCORE
    print(f"  {C.RED}✗{C.RESET}  {C.RED}{C.BOLD}{msg}{C.RESET}")
    report(f"  [FLAG]  {msg}")
    if flag:
        FLAGS.append(("FLAG", msg))
        SCORE += 2


def info(msg):
    print(f"  {C.DIM}·{C.RESET}  {msg}")
    report(f"  [INFO]  {msg}")


def report(line, raw=False):
    if raw:
        # Strip ANSI for text file
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', line)
        REPORT_LINES.append(clean)
    else:
        REPORT_LINES.append(line)


def ps(command, timeout=30):
    """Run a PowerShell command and return JSON output."""
    try:
        cmd = ["powershell", "-NonInteractive", "-NoProfile",
               "-ExecutionPolicy", "Bypass", "-Command", command]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, encoding='utf-8', errors='replace')
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def ps_json(command, timeout=30):
    """Run PowerShell and parse JSON output."""
    raw = ps(f"{command} | ConvertTo-Json -Depth 3 -Compress", timeout)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def is_suspicious_path(path):
    if not path:
        return False
    p = path.lower().replace('\\', '/')
    for loc in SUSPICIOUS_LOCATIONS:
        if loc and loc.lower().replace('\\', '/') in p:
            return True
    return False


def is_whitelisted_run_key(val):
    """Return True if this Run key value is from a known legitimate app."""
    v = val.lower()
    # Whitelist cmd.exe used for cleanup (e.g., OneDrive RunOnce del/rmdir)
    if 'cmd.exe' in v and any(x in v for x in ['/q /c del ', '/q /c rmdir', 'cachedupdate']):
        return True
    for w in RUN_KEY_WHITELIST:
        if w in v:
            return True
    return False


def is_suspicious_appdata_path(path):
    """For AppData paths, only flag if NOT in the whitelist."""
    p = path.lower()
    for w in APPDATA_WHITELIST:
        if w in p:
            return False
    return True


def sha256(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


# ─── PHASE 1: PROCESS ANALYSIS ─────────────────────────────────────────────

def phase1_processes():
    section("PHASE 1 — PROCESS ANALYSIS")

    subsection("1.1  Top CPU/RAM Consumers")
    procs = ps_json("""
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 |
        Select-Object Name, Id,
            @{N='CPU';E={[math]::Round($_.CPU,1)}},
            @{N='RAM_MB';E={[math]::Round($_.WorkingSet/1MB,1)}},
            Path
    """)
    for p in procs[:10]:
        name = p.get('Name','?')
        pid  = p.get('Id','?')
        cpu  = p.get('CPU', 0) or 0
        ram  = p.get('RAM_MB', 0) or 0
        path = p.get('Path') or ''
        info(f"{name:<30} PID:{pid:<7} CPU:{cpu:<8} RAM:{ram} MB  {path[:60]}")
        if cpu > 80 and name.lower() not in {'agy','code','chrome','firefox','msedge'}:
            warn(f"High CPU ({cpu}s): {name} (PID {pid}) — Path: {path or 'NONE'}")
        for m in MINER_NAMES:
            if m in name.lower():
                bad(f"KNOWN MINER NAME: '{name}' (PID {pid}) CPU:{cpu} RAM:{ram}MB")
                break

    subsection("1.2  Processes With No File Path (Injection/Rootkit Indicator)")
    all_procs = ps_json("""
        Get-Process | Select-Object Name, Id,
            @{N='CPU';E={[math]::Round($_.CPU,1)}},
            @{N='RAM_MB';E={[math]::Round($_.WorkingSet/1MB,1)}},
            Path
    """)
    no_path_flagged = 0
    for p in all_procs:
        name = (p.get('Name') or '').lower()
        path = p.get('Path')
        pid  = p.get('Id','?')
        if not path and name not in SYSTEM_PROCS_NO_PATH:
            if name in LEGIT_SYSTEM_PROCS:
                pass  # svchost/lsass with no path = normal on older PS versions
            else:
                no_path_flagged += 1
                if no_path_flagged <= 10:
                    warn(f"No path: {p.get('Name')} (PID {pid}) RAM:{p.get('RAM_MB')}MB")
    if no_path_flagged == 0:
        ok("All non-system processes have file paths")

    subsection("1.3  Processes From Suspicious Locations")
    found_susp = False
    for p in all_procs:
        path = p.get('Path') or ''
        name = p.get('Name','?')
        pid  = p.get('Id','?')
        if path and is_suspicious_path(path):
            # Only Temp/Public paths — not AppData (too many false positives)
            bad(f"Suspicious location: {name} (PID {pid})")
            bad(f"  Path: {path}")
            found_susp = True
    if not found_susp:
        ok("No processes running from Temp/Public suspicious paths")

    subsection("1.4  Spoofed System Process Names")
    found_spoof = False
    for p in all_procs:
        name = (p.get('Name') or '').lower()
        path = (p.get('Path') or '').lower()
        pid  = p.get('Id','?')
        if name in LEGIT_SYSTEM_PROCS and path:
            if SYSTEM32 not in path and SYSWOW64 not in path:
                bad(f"SPOOFED SYSTEM PROCESS: '{p.get('Name')}' (PID {pid})")
                bad(f"  Running from: {path}  (should be in System32)")
                found_spoof = True
    if not found_spoof:
        ok("No spoofed system process names detected")


# ─── PHASE 2: NETWORK ANALYSIS ─────────────────────────────────────────────

def phase2_network():
    section("PHASE 2 — NETWORK ANALYSIS")

    subsection("2.1  Active Established Connections")
    conns = ps_json("""
        Get-NetTCPConnection -State Established | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Process       = $proc.Name
                PID           = $_.OwningProcess
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                Path          = $proc.Path
            }
        }
    """)
    seen_ips = defaultdict(list)
    for c in conns:
        proc  = c.get('Process','?')
        pid   = c.get('PID','?')
        raddr = c.get('RemoteAddress','?')
        rport = c.get('RemotePort', 0) or 0
        path  = c.get('Path') or ''
        seen_ips[proc].append(raddr)
        info(f"{proc:<28} → {raddr}:{rport:<6}  {path[:55]}")

        if rport in MINING_PORTS:
            bad(f"MINING PORT DETECTED: {proc} (PID {pid}) → {raddr}:{rport}")

        if rport in RAT_PORTS:
            warn(f"Potential RAT port: {proc} (PID {pid}) → {raddr}:{rport}")

        for domain in MINING_POOL_DOMAINS:
            try:
                resolved = socket.gethostbyaddr(raddr)[0]
                if domain in resolved:
                    bad(f"MINING POOL CONNECTION: {proc} → {resolved}")
            except Exception:
                pass

    # Flag processes with too many unique remote IPs
    for proc_name, ips in seen_ips.items():
        unique = set(ips) - {'127.0.0.1', '::1'}
        if len(unique) > 5 and proc_name not in {'svchost','chrome','msedge','firefox','brave'}:
            warn(f"Many simultaneous connections ({len(unique)} unique IPs): {proc_name}")

    if not conns:
        ok("No established connections found")

    subsection("2.2  Listening Ports (Backdoor/RAT Check)")
    listeners = ps_json("""
        Get-NetTCPConnection -State Listen | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Port    = $_.LocalPort
                Process = $proc.Name
                PID     = $_.OwningProcess
                Path    = $proc.Path
            }
        }
    """)
    legit_ports = set(range(49664, 49700)) | {135,445,139,443,80,8080,3389,5040,7680}
    found_backdoor = False
    for l in listeners:
        port = l.get('Port', 0) or 0
        proc = l.get('Process','?')
        pid  = l.get('PID','?')
        path = l.get('Path') or ''
        if port not in legit_ports:
            info(f"Port {port:<6} ← {proc} (PID {pid})  {path[:50]}")
            if port in RAT_PORTS:
                bad(f"KNOWN RAT PORT LISTENING: {port} by {proc} (PID {pid})")
                found_backdoor = True
    if not found_backdoor:
        ok("No known RAT/backdoor listening ports detected")

    subsection("2.3  Hosts File Integrity Check")
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, 'r') as f:
            lines = f.readlines()
        suspicious_entries = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                suspicious_entries.append(stripped)
                parts = stripped.split()
                if len(parts) >= 2:
                    dest = parts[1].lower()
                    for domain in MINING_POOL_DOMAINS:
                        if domain in dest:
                            bad(f"MINING POOL BLOCKED IN HOSTS: {stripped}")
                    if any(av in dest for av in ['kaspersky','malwarebytes','avast','norton','mcafee','defender','microsoft','windowsupdate']):
                        bad(f"AV/UPDATE DOMAIN BLOCKED: {stripped}")
        if suspicious_entries:
            warn(f"Hosts file has {len(suspicious_entries)} non-comment entries:")
            for e in suspicious_entries:
                info(f"  {e}")
        else:
            ok("Hosts file is clean — no custom entries")
    except Exception as e:
        warn(f"Could not read hosts file: {e}")

    subsection("2.4  DNS Cache — Recent Domain Lookups")
    dns_out = ps("ipconfig /displaydns | Select-String 'Record Name'")
    dga_suspects = []
    for line in dns_out.splitlines():
        line = line.strip()
        domain = line.replace('Record Name . . . . . :','').strip().lower()
        for pool in MINING_POOL_DOMAINS:
            if pool in domain:
                bad(f"MINING POOL IN DNS CACHE: {domain}")
        # Detect DGA-like domains (random short strings)
        parts = domain.split('.')
        if parts and len(parts[0]) > 8:
            import re
            entropy = len(set(parts[0])) / len(parts[0])
            if entropy > 0.7 and re.match(r'^[a-z0-9]+$', parts[0]):
                dga_suspects.append(domain)
    if dga_suspects:
        warn(f"Possible DGA domains in DNS cache ({len(dga_suspects)} found):")
        for d in dga_suspects[:5]:
            info(f"  {d}")
    else:
        ok("No obvious DGA or mining pool domains in DNS cache")


# ─── PHASE 3: PERSISTENCE CHECKS ───────────────────────────────────────────

def phase3_persistence():
    section("PHASE 3 — PERSISTENCE MECHANISMS")

    subsection("3.1  Registry Run Keys")
    run_keys = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    found_bad_run = False
    for hive, subkey in run_keys:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        val_lower = val.lower()
                        info(f"[{hive_name}\\Run] {name} = {val[:80]}")
                        # Skip if whitelisted legitimate app
                        if is_whitelisted_run_key(val):
                            i += 1
                            continue
                        if is_suspicious_path(val):
                            bad(f"Run key from suspicious path: [{name}] -> {val}")
                            found_bad_run = True
                        if '-enc' in val_lower or '-encodedcommand' in val_lower:
                            bad(f"Encoded PowerShell in Run key: [{name}]")
                            found_bad_run = True
                        if any(x in val_lower for x in ['mshta','regsvr32','wscript','cscript']) and \
                           'system32' not in val_lower:
                            warn(f"Suspicious script host in Run key: [{name}] -> {val[:80]}")
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
    if not found_bad_run:
        ok("No suspicious entries in registry Run keys")

    subsection("3.2  Scheduled Tasks (Non-Microsoft)")
    tasks = ps_json("""
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } |
        ForEach-Object {
            $action = $_.Actions | Select-Object -First 1
            [PSCustomObject]@{
                Name    = $_.TaskName
                Path    = $_.TaskPath
                State   = $_.State
                Execute = $action.Execute
                Args    = $action.Arguments
            }
        }
    """)
    found_bad_task = False
    for t in tasks:
        name    = t.get('Name','?')
        execute = (t.get('Execute') or '').lower()
        args    = (t.get('Args') or '').lower()
        info(f"Task: {name:<55} → {execute[:60]}")
        if is_suspicious_path(execute):
            bad(f"Scheduled task executing from suspicious path: {name}")
            bad(f"  Execute: {execute}")
            found_bad_task = True
        if '-enc' in args or '-encodedcommand' in args:
            bad(f"Encoded PowerShell in scheduled task: {name}")
            found_bad_task = True
        if any(x in args for x in ['invoke-webrequest','downloadstring','iex ','webclient']):
            bad(f"Download command in scheduled task: {name}")
            found_bad_task = True
    if not found_bad_task:
        ok("No suspicious scheduled tasks found")

    subsection("3.3  Startup Folders")
    startup_dirs = [
        Path(os.environ.get('APPDATA','')) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    ]
    found_startup = False
    for d in startup_dirs:
        if d.exists():
            items = list(d.iterdir())
            for item in items:
                if item.suffix.lower() in {'.exe','.bat','.vbs','.ps1','.js','.cmd','.scr'}:
                    warn(f"Executable in startup folder: {item.name} → {item}")
                    found_startup = True
                else:
                    info(f"Startup item: {item.name}")
    if not found_startup:
        ok("No suspicious executables in startup folders")

    subsection("3.4  Services Running From Suspicious Paths")
    services = ps_json("""
        Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' } |
        Select-Object Name, DisplayName, PathName, StartMode, State
    """)
    found_bad_svc = False
    for s in services:
        path = (s.get('PathName') or '').lower()
        name = s.get('Name','?')
        if path and is_suspicious_path(path.replace('"','')):
            bad(f"Service from suspicious path: {name}")
            bad(f"  Path: {s.get('PathName')}")
            found_bad_svc = True
    if not found_bad_svc:
        ok("All running services are from standard system paths")

    subsection("3.5  Windows Defender / AV Status")
    av = ps_json("""
        Get-MpComputerStatus | Select-Object
            AMServiceEnabled, AntivirusEnabled, AntispywareEnabled,
            RealTimeProtectionEnabled, AMEngineVersion, AMProductVersion
    """)
    if av:
        a = av[0]
        fields = {
            'AMServiceEnabled'        : 'AM Service',
            'AntivirusEnabled'        : 'Antivirus',
            'AntispywareEnabled'      : 'Antispyware',
            'RealTimeProtectionEnabled': 'Real-Time Protection',
        }
        for key, label in fields.items():
            val = a.get(key)
            if val is True:
                ok(f"{label}: Enabled")
            elif val is False:
                warn(f"{label}: DISABLED")
        engine = a.get('AMEngineVersion','?')
        if engine == '0.0.0.0':
            bad("Defender engine not loaded (AMEngineVersion = 0.0.0.0)")
        else:
            ok(f"AM Engine Version: {engine}")

    subsection("3.6  Firewall Status")
    fw = ps_json("Get-NetFirewallProfile | Select-Object Name, Enabled")
    all_disabled = True
    for f in fw:
        enabled = f.get('Enabled')
        name    = f.get('Name','?')
        if enabled:
            ok(f"Firewall [{name}]: Enabled")
            all_disabled = False
        else:
            warn(f"Firewall [{name}]: DISABLED")
    if all_disabled and fw:
        bad("ALL firewall profiles are disabled — common malware action")


# ─── PHASE 4: FILE SYSTEM FORENSICS ────────────────────────────────────────

def phase4_filesystem():
    section("PHASE 4 — FILE SYSTEM FORENSICS")

    subsection("4.1  Recent Executables in Suspicious Locations (Last 30 Days)")
    cutoff = datetime.datetime.now() - datetime.timedelta(days=30)
    extensions = {'.exe','.dll','.bat','.ps1','.vbs','.js','.cmd','.scr','.hta'}
    found_files = []

    for loc in SUSPICIOUS_LOCATIONS:
        if not loc or not os.path.exists(loc):
            continue
        try:
            for root, dirs, files in os.walk(loc):
                dirs[:] = [d for d in dirs if d.lower() not in
                           {'chrome','firefox','brave','edge','code','vscode','steam','.git'}]
                for fname in files:
                    if Path(fname).suffix.lower() in extensions:
                        fpath = Path(root) / fname
                        try:
                            mtime = datetime.datetime.fromtimestamp(fpath.stat().st_mtime)
                            if mtime > cutoff:
                                found_files.append((fpath, mtime))
                        except Exception:
                            pass
        except Exception:
            pass

    if found_files:
        warn(f"Found {len(found_files)} recent executables in suspicious locations:")
        for fpath, mtime in sorted(found_files, key=lambda x: x[1], reverse=True)[:15]:
            h = sha256(str(fpath))
            info(f"  {mtime.strftime('%Y-%m-%d %H:%M')}  {fpath}")
            info(f"    SHA256: {h}")
            info(f"    VirusTotal: https://virustotal.com/gui/file/{h}")
    else:
        ok("No recent suspicious executables found in Temp/AppData/Downloads")

    subsection("4.2  Recently Modified System Binaries (Last 7 Days)")
    sys32 = Path("C:\\Windows\\System32")
    recent_sys = []
    cutoff7 = datetime.datetime.now() - datetime.timedelta(days=7)
    try:
        for f in sys32.glob("*.exe"):
            try:
                mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime)
                if mtime > cutoff7:
                    recent_sys.append((f, mtime))
            except Exception:
                pass
    except Exception:
        pass

    if recent_sys:
        warn(f"{len(recent_sys)} system binaries modified in last 7 days:")
        for fpath, mtime in sorted(recent_sys, key=lambda x: x[1], reverse=True)[:10]:
            info(f"  {mtime.strftime('%Y-%m-%d %H:%M')}  {fpath.name}")
    else:
        ok("No recently modified system binaries found")


# ─── PHASE 5: MINING SPECIFIC CHECKS ───────────────────────────────────────

def phase5_mining():
    section("PHASE 5 — CRYPTO MINER DETECTION")

    subsection("5.1  Known Miner Process Name Scan")
    all_procs = ps_json("""
        Get-Process | Select-Object Name, Id,
            @{N='CPU';E={[math]::Round($_.CPU,1)}},
            @{N='RAM_MB';E={[math]::Round($_.WorkingSet/1MB,1)}},
            Path
    """)
    miner_found = False
    for p in all_procs:
        name = (p.get('Name') or '').lower()
        for m in MINER_NAMES:
            if m in name:
                bad(f"KNOWN MINER NAME DETECTED: {p.get('Name')} PID:{p.get('Id')}")
                bad(f"  CPU:{p.get('CPU')}s  RAM:{p.get('RAM_MB')}MB  Path:{p.get('Path')}")
                miner_found = True
                break
    if not miner_found:
        ok("No known miner process names detected")

    subsection("5.2  GPU Utilization Check")
    gpu_out = ps(r"""
        try {
            Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction Stop |
                Select-Object -ExpandProperty CounterSamples |
                Where-Object { $_.CookedValue -gt 1 } |
                Sort-Object CookedValue -Descending |
                Select-Object -First 5 |
                ForEach-Object { "$($_.InstanceName)|||$([math]::Round($_.CookedValue,1))" }
        } catch { "GPU_ERROR" }
    """)
    if "GPU_ERROR" not in gpu_out and gpu_out.strip():
        for line in gpu_out.strip().splitlines():
            if '|||' in line:
                instance, usage = line.split('|||')
                usage_val = float(usage)
                info(f"GPU: {instance[:60]}  →  {usage}%")
                pid_match = None
                import re
                m = re.search(r'pid_(\d+)', instance)
                if m:
                    pid_match = m.group(1)
                if usage_val > 15:
                    warn(f"High GPU usage ({usage}%) on PID {pid_match} — investigate")
    else:
        ok("GPU usage nominal or counter unavailable")

    subsection("5.3  CPU Delta Sampling (5-second window — catches burst miners)")
    import time
    before = ps_json("""
        Get-Process | Select-Object Id, Name,
            @{N='CPU';E={ if($_.CPU){$_.CPU}else{0} }}
    """)
    info("Sampling CPU for 5 seconds...")
    time.sleep(5)
    after = ps_json("""
        Get-Process | Select-Object Id, Name,
            @{N='CPU';E={ if($_.CPU){$_.CPU}else{0} }}
    """)
    before_map = {p['Id']: p for p in before if 'Id' in p}
    spikes = []
    for p in after:
        pid  = p.get('Id')
        name = p.get('Name','?')
        cpu_after  = float(p.get('CPU') or 0)
        cpu_before = float((before_map.get(pid) or {}).get('CPU') or 0)
        delta = cpu_after - cpu_before
        if delta > 3:
            spikes.append((name, pid, delta))
    if spikes:
        spikes.sort(key=lambda x: x[2], reverse=True)
        for name, pid, delta in spikes[:10]:
            line = f"{name:<30} PID:{pid:<7} +{delta:.1f}s CPU in 5 sec"
            if delta > 20:
                warn(f"High CPU spike: {line}")
            else:
                info(f"CPU active: {line}")
    else:
        ok("No unusual CPU spikes detected in 5-second sample")

    subsection("5.4  Mining Port Connection Scan")
    found_mining_conn = False
    conns = ps_json("""
        Get-NetTCPConnection -State Established |
        Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
    """)
    for c in conns:
        rport = int(c.get('RemotePort', 0) or 0)
        if rport in MINING_PORTS:
            pid  = c.get('OwningProcess','?')
            rip  = c.get('RemoteAddress','?')
            bad(f"MINING POOL PORT ACTIVE: Remote {rip}:{rport}  (PID {pid})")
            found_mining_conn = True
    if not found_mining_conn:
        ok("No active connections to known mining pool ports")


# ─── PHASE 6: SECURITY EVENTS ──────────────────────────────────────────────

def phase6_events():
    section("PHASE 6 — SECURITY EVENT LOG ANALYSIS")

    subsection("6.1  Critical Security Events (Last 7 Days)")
    event_map = {
        4625: "Failed Login Attempt",
        4648: "Login With Explicit Credentials",
        4672: "Special Privileges Assigned",
        4698: "Scheduled Task Created",
        4702: "Scheduled Task Modified",
        4720: "New User Account Created",
        4728: "User Added to Global Group",
        4732: "User Added to Local Group",
    }
    events = ps_json(f"""
        $startTime = (Get-Date).AddDays(-7)
        Get-WinEvent -FilterHashtable @{{
            LogName   = 'Security'
            StartTime = $startTime
            Id        = @({','.join(str(k) for k in event_map.keys())})
        }} -ErrorAction SilentlyContinue |
        Select-Object -First 50 Id, TimeCreated,
            @{{N='Msg'; E={{$_.Message.Substring(0, [Math]::Min(120,$_.Message.Length))}}}}
    """, timeout=20)

    counts = defaultdict(int)
    for e in events:
        eid = e.get('Id')
        counts[eid] += 1

    if not events:
        ok("No critical security events found in last 7 days")
    else:
        for eid, label in event_map.items():
            count = counts.get(eid, 0)
            if count > 0:
                if eid == 4625 and count > 10:
                    bad(f"Event {eid} [{label}]: {count} occurrences — possible brute force!")
                elif eid in {4720, 4698, 4702}:
                    warn(f"Event {eid} [{label}]: {count} occurrences")
                else:
                    info(f"Event {eid} [{label}]: {count} occurrences")


# ─── PHASE 7: PROCESS HOLLOWING HINTS ──────────────────────────────────────

def phase7_hollowing():
    section("PHASE 7 — PROCESS HOLLOWING INDICATORS")
    subsection("7.1  PowerShell with Encoded Commands (Obfuscation)")
    ps_procs = ps_json("""
        Get-WmiObject Win32_Process |
            Where-Object { $_.Name -like '*powershell*' -or $_.Name -like '*pwsh*' } |
            Select-Object ProcessId, Name, CommandLine, ParentProcessId
    """)
    found_enc = False
    for p in ps_procs:
        cmd = (p.get('CommandLine') or '').lower()
        pid = p.get('ProcessId','?')
        if '-enc' in cmd or '-encodedcommand' in cmd:
            bad(f"Encoded PowerShell detected! PID:{pid}")
            bad(f"  Command: {p.get('CommandLine','')[:120]}")
            found_enc = True
        if '-windowstyle hidden' in cmd or '-w hidden' in cmd:
            warn(f"Hidden PowerShell window: PID {pid}")
        if any(x in cmd for x in ['invoke-webrequest','downloadstring','webclient','iex ']):
            bad(f"PowerShell download cradle: PID {pid}")
            bad(f"  Command: {p.get('CommandLine','')[:120]}")
            found_enc = True
    if not found_enc:
        ok("No encoded or download-cradle PowerShell detected")

    subsection("7.2  Tool Recommendations for Deep Hollowing Check")
    tools = [
        ("PE-sieve",       "https://github.com/hasherezade/pe-sieve/releases",
         "pe-sieve.exe --pid <PID> — detects hollowed processes"),
        ("Hollows Hunter", "https://github.com/hasherezade/hollows_hunter/releases",
         "hollows_hunter.exe — auto-scans ALL processes"),
        ("Process Hacker",  "https://processhacker.sf.net",
         "Memory tab → look for RWX regions with no mapped file"),
    ]
    for name, url, usage in tools:
        info(f"{name:<18} {url}")
        info(f"  Usage: {usage}")


# ─── FINAL REPORT ───────────────────────────────────────────────────────────

def final_report():
    section("FINAL REPORT & RISK ASSESSMENT")

    duration = (datetime.datetime.now() - START_TIME).seconds
    total_flags = len(FLAGS)

    if SCORE == 0:
        risk = "LOW — System appears clean"
        color = C.GREEN
    elif SCORE <= 4:
        risk = "MEDIUM — Some suspicious findings, investigate further"
        color = C.YELLOW
    elif SCORE <= 10:
        risk = "HIGH — Multiple red flags, assume compromised"
        color = C.RED
    else:
        risk = "CRITICAL — Strong indicators of active compromise"
        color = C.RED

    print(f"\n{C.BOLD}  Risk Score  : {color}{SCORE} points{C.RESET}")
    print(f"{C.BOLD}  Risk Level  : {color}{risk}{C.RESET}")
    print(f"{C.BOLD}  Total Flags : {total_flags}{C.RESET}")
    print(f"{C.BOLD}  Scan Time   : {duration} seconds{C.RESET}")

    report(f"\n  Risk Score  : {SCORE} points")
    report(f"  Risk Level  : {risk}")
    report(f"  Total Flags : {total_flags}")
    report(f"  Scan Time   : {duration} seconds")

    if FLAGS:
        print(f"\n{C.RED}{C.BOLD}  ════ FLAGS RAISED ════{C.RESET}")
        report(f"\n  ==== FLAGS RAISED ====")
        for i, (ftype, msg) in enumerate(FLAGS, 1):
            prefix = "🚩" if ftype == "FLAG" else "⚠️"
            print(f"  {prefix} [{i:02d}] {msg[:100]}")
            report(f"  [{ftype}] [{i:02d}] {msg}")
    else:
        print(f"\n{C.GREEN}  ✓ No flags raised — system appears clean!{C.RESET}")
        report(f"\n  No flags raised — system appears clean!")

    # Score interpretation
    print(f"""
{C.DIM}  SCORE GUIDE:
   0     = Low risk, system likely clean
   1-4   = Medium risk, investigate flagged items
   5-10  = High risk, likely compromised
   10+   = Critical, isolate system immediately{C.RESET}""")

    # Save report
    report(f"\n\n{'='*68}")
    report(f"  Scan completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report(f"  System: {platform.node()} | {platform.version()}")
    report(f"{'='*68}")

    try:
        DESKTOP.mkdir(parents=True, exist_ok=True)
        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(REPORT_LINES))
        print(f"\n{C.GREEN}  ✓ Report saved to: {REPORT_FILE}{C.RESET}\n")
        report(f"\n  Report saved to: {REPORT_FILE}")
    except Exception as e:
        print(f"{C.RED}  Could not save report: {e}{C.RESET}")


# ─── MAIN ───────────────────────────────────────────────────────────────────

def main():
    # Enable ANSI on Windows
    os.system('color')

    if not sys.platform.startswith('win'):
        print("This tool is for Windows only.")
        sys.exit(1)

    banner()

    print(f"{C.YELLOW}  [!] Make sure you are running this as Administrator for full results.{C.RESET}")
    print(f"{C.DIM}  Starting scan...{C.RESET}\n")
    report("  [!] Run as Administrator for full results.")

    try:
        phase1_processes()
        phase2_network()
        phase3_persistence()
        phase4_filesystem()
        phase5_mining()
        phase6_events()
        phase7_hollowing()
        final_report()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Scan interrupted by user.{C.RESET}")
        final_report()
    except Exception as e:
        bad(f"Unexpected error: {e}", flag=False)
        import traceback
        traceback.print_exc()
        final_report()


if __name__ == "__main__":
    main()
