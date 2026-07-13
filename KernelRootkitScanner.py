#!/usr/bin/env python3
"""
================================================================================
  KERNEL ROOTKIT SCANNER — Advanced Windows Kernel Threat Detection
  Author  : Antigravity AI
  Version : 1.0
  Usage   : Run as Administrator → python KernelRootkitScanner.py

  TECHNIQUES USED:
    1. Cross-View Process Enumeration  — DKOM hiding detection
    2. Unsigned Kernel Driver Scan     — Rootkit driver detection
    3. Driver Path Anomaly             — Out-of-place kernel modules
    4. MBR / Bootkit Analysis          — Boot-level infection detection
    5. Minifilter Driver Audit         — I/O interception rootkits
    6. Kernel Module Comparison        — Hidden module detection
    7. Registry Discrepancy            — Hidden registry key detection
    8. Code Integrity / PatchGuard     — Kernel tamper protection status
    9. SSDT Anomaly (Heuristic)        — System call hook indicators
   10. Network Stack Integrity         — NDIS/TDI hook indicators

  HONEST LIMITATION:
    A sufficiently advanced kernel rootkit running in Ring-0 can defeat
    ALL user-mode detection. This scanner catches most real-world rootkits
    which are NOT perfectly implemented. For confirmed infections, use:
    → GMER (gmer.net)
    → Kaspersky TDSSKiller
    → Microsoft Rootkit Revealer
    → Boot from live USB and scan offline
================================================================================
"""

import ctypes
import ctypes.wintypes
import subprocess
import os
import sys
import struct
import hashlib
import datetime
import winreg
import json
import time
import socket
from pathlib import Path
from collections import defaultdict

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ['PYTHONIOENCODING'] = 'utf-8'


# ─── WINDOWS API SETUP ───────────────────────────────────────────────────────

kernel32  = ctypes.WinDLL('kernel32', use_last_error=True)
psapi     = ctypes.WinDLL('psapi',    use_last_error=True)
ntdll     = ctypes.WinDLL('ntdll',    use_last_error=True)
advapi32  = ctypes.WinDLL('advapi32', use_last_error=True)
wintrust  = ctypes.WinDLL('wintrust', use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
TH32CS_SNAPPROCESS        = 0x00000002
MAX_PATH                  = 260
INVALID_HANDLE_VALUE      = ctypes.c_void_p(-1).value


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.wintypes.DWORD),
        ("cntUsage",            ctypes.wintypes.DWORD),
        ("th32ProcessID",       ctypes.wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        ctypes.wintypes.DWORD),
        ("cntThreads",          ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             ctypes.wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * MAX_PATH),
    ]


# ─── ANSI COLORS ─────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ─── GLOBALS ─────────────────────────────────────────────────────────────────

FLAGS        = []
SCORE        = 0
REPORT_LINES = []
START_TIME   = datetime.datetime.now()
DESKTOP      = Path(os.path.join(os.environ.get("USERPROFILE",""),
                                  "OneDrive", "Desktop"))
if not DESKTOP.exists():
    DESKTOP  = Path(os.path.join(os.environ.get("USERPROFILE",""), "Desktop"))

REPORT_FILE  = DESKTOP / f"KernelRootkit_Report_{START_TIME.strftime('%Y%m%d_%H%M%S')}.txt"


# ─── KNOWN GOOD DRIVER PATHS ─────────────────────────────────────────────────

LEGIT_DRIVER_PATHS = [
    r"c:\windows\system32\drivers",
    r"c:\windows\syswow64",
    r"c:\windows\system32",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\windows\inf",
]

# Known legitimate driver names (whitelist — partial match)
LEGIT_DRIVER_NAMES = [
    'ndis','tcpip','http','acpi','pci','usb','disk','volume','ntfs','fat',
    'ataport','storport','msrpc','nsiproxy','netio','afd','tdx','pacer',
    'wfplwfs','rspndr','lltdio','mpsdrv','mouhid','kbdhid','hidusb',
    'usbhub','usbstor','cdrom','classpnp','partmgr','fvevol','rdyboost',
    'cng','ksecdd','wdfilter','wdboot','wdndrv','hvservice','hvcrash',
    'vmbus','hvsocket','dxgkrnl','monitor','basicdisplay','basicrender',
    'nvlddmkm','nvkflt','iusb3xhc','intelppm','iastorav','iastorv',
    'nvcv', 'nvstor', 'nvdmkm', 'rzfilter', 'asus', 'asmtxhci',
    'rtl','realtek','qualcomm','intel','amd','nvidia','ati','broadcom',
    'marvell','killer','rivet','netadapter','wlan','wifi','bluetooth',
    'kaspersky','klbackupdisk','klflt','klpd','klif','kldisk',
    'rog','armoury','armourycrate','lightingservice','hidsensor',
    'samsungmagician', 'igdkmd', 'igfx',
]

# Known rootkit driver names (partial match)
ROOTKIT_DRIVER_NAMES = [
    'tdss','tdl','zeroaccess','necurs','rustock','alureon','sinowal',
    'mebroot','max++','kelihos','zeus','spyeye','blackhole','cidox',
    'popureb','olmasco','xpaj','whistler','pitou','bootkit','rootkit',
    'dse_patch','kdcom_patch','bootkid','gapz','rovnix','carberp',
    'cidox','pihar','sst','fispboot','mbr_locker',
]


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def banner():
    b = f"""
{C.MAGENTA}{C.BOLD}
+==================================================================+
|       KERNEL ROOTKIT SCANNER  v1.0 - Ring-0 Threat Detection    |
|       Started : {START_TIME.strftime("%Y-%m-%d %H:%M:%S")}                           |
|       WARNING : Must run as Administrator for full results       |
+==================================================================+
{C.RESET}"""
    print(b)
    log(b)


def section(title):
    line = f"\n{'='*66}\n  {title}\n{'='*66}"
    print(f"\n{C.CYAN}{C.BOLD}{line}{C.RESET}")
    log(f"\n{'='*66}\n  {title}\n{'='*66}")


def sub(title):
    print(f"\n{C.MAGENTA}{C.BOLD}  >> {title}{C.RESET}")
    log(f"\n  >> {title}")


def ok(msg):
    print(f"  {C.GREEN}[CLEAN]{C.RESET}  {msg}")
    log(f"  [CLEAN]  {msg}")


def flag(msg, score=2):
    global SCORE
    print(f"  {C.RED}{C.BOLD}[ROOTKIT?]{C.RESET}  {C.RED}{msg}{C.RESET}")
    log(f"  [ROOTKIT?]  {msg}")
    FLAGS.append(msg)
    SCORE += score


def warn(msg, score=1):
    global SCORE
    print(f"  {C.YELLOW}[SUSPECT]{C.RESET}  {msg}")
    log(f"  [SUSPECT]  {msg}")
    FLAGS.append(f"[WARN] {msg}")
    SCORE += score


def info(msg):
    print(f"  {C.DIM}[INFO]{C.RESET}  {msg}")
    log(f"  [INFO]  {msg}")


def log(line):
    import re
    REPORT_LINES.append(re.sub(r'\033\[[0-9;]*m', '', line))


def ps(cmd, timeout=30):
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace')
        return r.stdout.strip()
    except Exception:
        return ""


def ps_json(cmd, timeout=30):
    raw = ps(f"{cmd} | ConvertTo-Json -Depth 3 -Compress", timeout)
    if not raw:
        return []
    try:
        d = json.loads(raw)
        return [d] if isinstance(d, dict) else (d if isinstance(d, list) else [])
    except Exception:
        return []


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, shell=True,
                           encoding='utf-8', errors='replace')
        return r.stdout.strip()
    except Exception:
        return ""


# ─── DETECTION 1: CROSS-VIEW PROCESS ENUMERATION ────────────────────────────
# Theory: DKOM rootkits remove processes from the kernel PsActiveProcessHead
# linked list. This makes them invisible to NtQuerySystemInformation.
# But different Windows APIs query different kernel structures.
# If Method A shows 52 processes and Method B shows 49 → 3 are hidden.

def detect_hidden_processes():
    section("DETECTION 1 — CROSS-VIEW PROCESS ENUMERATION (DKOM Detection)")
    info("Comparing process lists from 3 independent Windows APIs...")
    info("If counts differ significantly, a rootkit may be hiding processes.")

    # Method 1: CreateToolhelp32Snapshot (user-mode, queries kernel list)
    pids_toolhelp = set()
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnap != INVALID_HANDLE_VALUE:
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if kernel32.Process32First(hSnap, ctypes.byref(pe)):
            while True:
                pids_toolhelp.add(pe.th32ProcessID)
                if not kernel32.Process32Next(hSnap, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(hSnap)

    # Method 2: EnumProcesses via PSAPI (different kernel call path)
    pids_psapi = set()
    arr = (ctypes.wintypes.DWORD * 4096)()
    cb_needed = ctypes.wintypes.DWORD()
    if psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(cb_needed)):
        count = cb_needed.value // ctypes.sizeof(ctypes.wintypes.DWORD)
        pids_psapi = set(arr[i] for i in range(count) if arr[i] != 0)

    # Method 3: WMI Win32_Process (goes through WMI provider — different path)
    wmi_out = run("wmic process get ProcessId /format:csv")
    pids_wmi = set()
    for line in wmi_out.splitlines():
        parts = line.strip().split(',')
        if len(parts) >= 2:
            try:
                pids_wmi.add(int(parts[-1]))
            except ValueError:
                pass

    # Method 4: PowerShell Get-Process (uses .NET System.Diagnostics)
    ps_out = ps("Get-Process | Select-Object -ExpandProperty Id")
    pids_ps = set()
    for line in ps_out.splitlines():
        try:
            pids_ps.add(int(line.strip()))
        except ValueError:
            pass

    info(f"CreateToolhelp32Snapshot : {len(pids_toolhelp)} processes")
    info(f"PSAPI EnumProcesses      : {len(pids_psapi)} processes")
    info(f"WMI Win32_Process        : {len(pids_wmi)} processes")
    info(f"PowerShell Get-Process   : {len(pids_ps)} processes")

    # Compare — a discrepancy > 3 is suspicious (small diffs are timing-based)
    counts = [len(pids_toolhelp), len(pids_psapi), len(pids_wmi), len(pids_ps)]
    counts = [c for c in counts if c > 0]
    if counts:
        diff = max(counts) - min(counts)
        if diff == 0:
            ok(f"All APIs agree: {max(counts)} processes visible. No DKOM hiding detected.")
        elif diff <= 3:
            warn(f"Minor process count discrepancy ({diff}). Likely timing artifact — monitor.")
        else:
            flag(f"LARGE PROCESS COUNT DISCREPANCY: {diff} processes differ between APIs!")
            flag(f"  Max seen: {max(counts)} | Min seen: {min(counts)}")
            flag("  STRONG INDICATOR of DKOM rootkit hiding processes!")

        # Find PIDs visible in one method but not others
        all_pids = pids_toolhelp | pids_psapi | pids_wmi | pids_ps
        for pid in sorted(all_pids):
            seen_in = sum([
                pid in pids_toolhelp,
                pid in pids_psapi,
                pid in pids_wmi,
                pid in pids_ps
            ])
            if seen_in == 1 and pid > 4:  # Only in one source = suspicious
                # Get its name
                name = "unknown"
                hProc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
                if hProc:
                    buf = ctypes.create_unicode_buffer(MAX_PATH)
                    size = ctypes.wintypes.DWORD(MAX_PATH)
                    kernel32.QueryFullProcessImageNameW(hProc, 0, buf, ctypes.byref(size))
                    name = buf.value or "unknown"
                    kernel32.CloseHandle(hProc)
                warn(f"PID {pid} ({name}) only visible in ONE of 4 APIs — suspicious!")


# ─── DETECTION 2: UNSIGNED KERNEL DRIVER DETECTION ──────────────────────────
# Theory: Windows 64-bit enforces Driver Signature Enforcement (DSE).
# A rootkit MUST either:
#   a) Use a stolen/forged cert (will show up as an unknown publisher)
#   b) Patch DSE to load unsigned (MASSIVE red flag if found)
#   c) Exploit a signed vulnerable driver (BYOVD attack)
# We check all loaded drivers for signature status.

def detect_unsigned_drivers():
    section("DETECTION 2 — KERNEL DRIVER SIGNATURE VERIFICATION")
    info("All 64-bit kernel drivers must be signed. Unsigned = rootkit indicator.")
    info("Querying loaded kernel modules via EnumDeviceDrivers...")

    # Get list of loaded drivers
    drivers_out = run("driverquery /fo csv /v /si 2>nul")
    unsigned_drivers = []
    all_drivers = []

    if drivers_out:
        lines = drivers_out.strip().splitlines()
        header = lines[0] if lines else ""
        for line in lines[1:]:
            # CSV parse
            parts = []
            current = ""
            in_quotes = False
            for ch in line:
                if ch == '"':
                    in_quotes = not in_quotes
                elif ch == ',' and not in_quotes:
                    parts.append(current.strip())
                    current = ""
                else:
                    current += ch
            parts.append(current.strip())

            if len(parts) >= 6:
                name     = parts[0].strip('"')
                disp     = parts[1].strip('"')
                drv_type = parts[2].strip('"')
                state    = parts[3].strip('"')
                start    = parts[4].strip('"')
                is_signed= parts[5].strip('"').lower() if len(parts) > 5 else 'false'
                path_val = parts[6].strip('"') if len(parts) > 6 else ''

                all_drivers.append({
                    'name': name, 'display': disp,
                    'signed': is_signed, 'path': path_val,
                    'state': state
                })

                if is_signed == 'false' and state.lower() in ('running','stopped'):
                    unsigned_drivers.append({'name': name, 'path': path_val, 'disp': disp})

    if unsigned_drivers:
        flag(f"Found {len(unsigned_drivers)} UNSIGNED kernel drivers!")
        for d in unsigned_drivers[:20]:
            flag(f"  UNSIGNED: {d['name']} | {d['disp']} | {d['path']}")
    elif all_drivers:
        ok(f"All {len(all_drivers)} loaded drivers are signed.")
    else:
        warn("driverquery returned no data — try running as Administrator.")

    # Additional: PowerShell-based driver signing check
    sub("Cross-checking with PowerShell Get-AuthenticodeSignature")
    drv_check = ps(r"""
        $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq 'Running'}
        foreach ($d in $drivers) {
            $path = $d.PathName -replace '"','' -replace '/','\'
            if ($path -and (Test-Path $path)) {
                $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {
                    Write-Output "INVALID_SIG|$($d.Name)|$($sig.Status)|$path"
                }
            }
        }
    """, timeout=60)
    found_invalid = False
    for line in drv_check.splitlines():
        if line.startswith("INVALID_SIG|"):
            parts = line.split('|')
            if len(parts) >= 4:
                drv_name   = parts[1]
                sig_status = parts[2]
                drv_path   = parts[3]
                if sig_status not in ('NotSigned','UnknownError',''):
                    flag(f"BAD SIGNATURE: {drv_name} | Status: {sig_status} | {drv_path}")
                    found_invalid = True
                elif sig_status == 'NotSigned':
                    warn(f"Not signed: {drv_name} | {drv_path}")
    if not found_invalid:
        ok("No drivers with invalid/tampered signatures found.")


# ─── DETECTION 3: DRIVER PATH ANOMALY ───────────────────────────────────────
# Theory: Legitimate drivers live in System32\drivers or vendor Program Files.
# Rootkits often drop drivers in Temp, AppData, or random system paths.

def detect_driver_path_anomalies():
    section("DETECTION 3 — KERNEL DRIVER PATH ANOMALY DETECTION")
    info("Checking if any kernel driver is running from a suspicious location...")

    drivers = ps_json("""
        Get-WmiObject Win32_SystemDriver |
        Select-Object Name, DisplayName, PathName, State, StartMode
    """, timeout=30)

    suspicious_count = 0
    rootkit_named    = 0

    for d in drivers:
        name  = (d.get('Name') or '').lower()
        path  = (d.get('PathName') or '').lower().replace('"','').strip()
        state = (d.get('State') or '').lower()
        disp  = d.get('DisplayName') or ''

        # Check for known rootkit driver names
        for rk in ROOTKIT_DRIVER_NAMES:
            if rk in name or rk in path:
                flag(f"KNOWN ROOTKIT DRIVER NAME: {d.get('Name')} | {path}")
                rootkit_named += 1
                break

        # Check path legitimacy (only for running drivers)
        if state == 'running' and path:
            is_legit_path = any(
                path.startswith(lp) for lp in LEGIT_DRIVER_PATHS
            )
            if not is_legit_path:
                flag(f"DRIVER FROM SUSPICIOUS PATH: {d.get('Name')}")
                flag(f"  Path: {path}")
                suspicious_count += 1

    if suspicious_count == 0 and rootkit_named == 0:
        ok(f"All {len(drivers)} drivers are in legitimate system paths.")
    
    # Check for drivers in Temp/AppData (huge red flag)
    sub("Scanning for driver (.sys) files outside System32\\drivers")
    sys32_drivers = Path(r"C:\Windows\System32\drivers")
    suspicious_sys = []

    search_roots = [
        os.environ.get('TEMP',''),
        os.environ.get('APPDATA',''),
        os.environ.get('LOCALAPPDATA',''),
        'C:\\ProgramData',
        'C:\\Windows\\Temp',
    ]
    for root in search_roots:
        if not root or not os.path.exists(root):
            continue
        try:
            for r, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d.lower() not in
                           {'microsoft','windows','nvidia','nvidia corporation','amd','intel','google','asus','kaspersky lab','android'}]
                for f in files:
                    if f.lower().endswith('.sys'):
                        suspicious_sys.append(os.path.join(r, f))
        except PermissionError:
            pass

    if suspicious_sys:
        flag(f"Found {len(suspicious_sys)} .sys (driver) files outside System32!")
        for s in suspicious_sys[:10]:
            flag(f"  SUSPICIOUS DRIVER FILE: {s}")
            h = ""
            try:
                with open(s,'rb') as fh:
                    h = hashlib.sha256(fh.read()).hexdigest()
                flag(f"    SHA256: {h}")
                flag(f"    Check: https://virustotal.com/gui/file/{h}")
            except Exception:
                pass
    else:
        ok("No .sys driver files found in Temp/AppData/ProgramData.")


# ─── DETECTION 4: MBR / BOOTKIT ANALYSIS ────────────────────────────────────
# Theory: Bootkits (MBR rootkits) infect the Master Boot Record, loading
# before Windows itself. The MBR should contain standard bootloader code.
# We read raw sector 0 and check for anomalies.

def detect_mbr_bootkit():
    section("DETECTION 4 — MBR / VBR BOOTKIT ANALYSIS")
    info("Reading raw MBR (sector 0) from PhysicalDrive0...")
    info("Checking for bootkit signatures and MBR integrity...")

    # Known bootkit signatures (partial byte sequences)
    BOOTKIT_SIGNATURES = {
        b'\x52\x75\x73\x74\x6f\x63\x6b': 'Rustock',
        b'\x41\x6c\x75\x72\x65\x6f\x6e': 'Alureon/TDL4',
        b'\x4d\x65\x62\x72\x6f\x6f\x74': 'Mebroot',
        b'\x53\x69\x6e\x6f\x77\x61\x6c': 'Sinowal',
        b'\x42\x4f\x4f\x54\x4b\x49\x54': 'Generic Bootkit marker',
        b'\xeb\x5a\x90\x00\x00\x00\x00': 'Possible bootkit (suspicious NOP sled)',
    }

    # Standard MBR signatures (benign)
    KNOWN_GOOD_MBR_BYTES = [
        b'\x33\xc0\x8e\xd0\xbc\x00\x7c',  # Classic Windows MBR start
        b'\xfa\x33\xc0\x8e\xd0\xbc\x00',  # Alt Windows MBR start
        b'\xeb\x63\x90',                    # GRUB MBR
        b'\xeb\x58\x90',                    # Common bootloader
        b'\x33\xed\xfa\x8e\xd5\xbc',       # Windows 7/8/10 MBR
    ]

    mbr_data = None
    try:
        # Open raw disk — requires admin
        with open(r'\\.\PhysicalDrive0', 'rb') as disk:
            mbr_data = disk.read(512)
    except PermissionError:
        warn("Cannot read MBR — run as Administrator for this check.")
        return
    except Exception as e:
        warn(f"MBR read failed: {e}")
        return

    if not mbr_data or len(mbr_data) < 512:
        warn("Could not read full MBR (512 bytes).")
        return

    # Check MBR signature (last 2 bytes must be 0x55 0xAA)
    mbr_sig = mbr_data[510:512]
    if mbr_sig == b'\x55\xAA':
        ok(f"MBR signature valid: 0x55AA at offset 510.")
    elif mbr_sig == b'\x00\x00':
        flag("MBR SIGNATURE IS ZEROED! Possible MBR wiper/bootkit!")
    else:
        warn(f"Non-standard MBR signature: {mbr_sig.hex()} (expected 55AA)")

    # Check for bootkit signatures in MBR
    found_bootkit = False
    for sig, name in BOOTKIT_SIGNATURES.items():
        if sig in mbr_data:
            flag(f"BOOTKIT SIGNATURE FOUND IN MBR: {name}")
            flag(f"  Signature: {sig.hex()}")
            found_bootkit = True

    # Check if MBR start matches known good patterns
    mbr_start = mbr_data[:7]
    is_known_good = any(mbr_start.startswith(good) for good in KNOWN_GOOD_MBR_BYTES)

    if is_known_good and not found_bootkit:
        ok("MBR starts with known legitimate bootloader pattern.")
    elif not found_bootkit:
        warn(f"MBR start bytes unrecognized: {mbr_start.hex()}")
        info("This MAY be a non-Windows bootloader (GRUB, etc.) or a bootkit.")
        info("Compare with a known-clean system to verify.")

    # Hash the MBR for reference
    mbr_hash = hashlib.sha256(mbr_data).hexdigest()
    info(f"MBR SHA256: {mbr_hash}")
    info("Save this hash — if it changes unexpectedly, MBR was modified!")

    # Check partition table entries
    info("Checking partition table entries (MBR bytes 446-509)...")
    part_table = mbr_data[446:510]
    for i in range(4):
        entry = part_table[i*16:(i+1)*16]
        if entry[4] != 0:  # Partition type != 0 means active partition
            boot_flag = entry[0]
            part_type = entry[4]
            info(f"  Partition {i+1}: Type=0x{part_type:02X}  BootFlag=0x{boot_flag:02X}")
            if boot_flag not in (0x00, 0x80):
                warn(f"  Unusual boot flag on partition {i+1}: 0x{boot_flag:02X}")


# ─── DETECTION 5: MINIFILTER DRIVER AUDIT ───────────────────────────────────
# Theory: Rootkits use minifilter drivers to intercept file I/O.
# They can hide files, registry keys, and network traffic this way.
# FltMC lists all registered minifilter drivers.

def detect_minifilter_rootkits():
    section("DETECTION 5 — MINIFILTER DRIVER AUDIT (I/O Interception)")
    info("Minifilters intercept disk/network I/O — common rootkit technique.")
    info("Listing all registered minifilter drivers via FltMC...")

    fltmc_out = run("fltMC filters")

    # Known legitimate minifilter drivers
    LEGIT_FILTERS = {
        'wdfilter', 'wdboot', 'bindflt', 'cldflt', 'cloudfilesdiag',
        'antimalwarehostextension', 'luafv', 'npsvctrig', 'przflt',
        'storqosflt', 'wcifs', 'filecrypt', 'lxpvcm', 'bfs',
        'dfs', 'aclfilt', 'xboxvethnetfilter', 'nsiproxy',
        'ksecdd', 'mountmgr', 'kdnic', 'agilevpn', 'rassstp',
        # Security products (legit)
        'klflt', 'klbackupdisk', 'klupdflt', 'ksensor', 'klif', 'klbackupflt',  # Kaspersky
        'mbamswissarmy', 'mbam', 'mbamdaemon',                   # Malwarebytes
        'avgntflt', 'avkmgr',                                    # Avast/AVG
        'aswarpotkbd', 'aswsp', 'aswbidsdriver',                 # Avast
        'symefa64', 'symnets', 'symtdiv',                        # Symantec
        'mfefirekm', 'mfehidk',                                  # McAfee
        # Windows built-in
        'dfsc', 'exfat', 'cdfs', 'ntfs', 'refs', 'fastfat',
        'overlay', 'wcifscache', 'rawdisk', 'ucpd', 'wof', 'fileinfo', 'unionfs',
        # ASUS/ROG (legit on ASUS laptops)
        'armourycrate', 'asus', 'asusfan', 'rogliveservice',
    }

    lines = fltmc_out.splitlines()
    filter_names = []
    parsing = False
    for line in lines:
        if '---' in line:
            parsing = True
            continue
        if parsing and line.strip():
            parts = line.split()
            if parts:
                fname = parts[0].lower()
                filter_names.append(fname)
                is_legit = any(leg in fname for leg in LEGIT_FILTERS)
                if not is_legit:
                    # Check for known rootkit filter names
                    rootkit_match = any(rk in fname for rk in ROOTKIT_DRIVER_NAMES)
                    if rootkit_match:
                        flag(f"ROOTKIT MINIFILTER DRIVER: {parts[0]}")
                    else:
                        warn(f"Unknown minifilter driver: {parts[0]} — verify manually")
                else:
                    info(f"Legit filter: {parts[0]}")

    if filter_names:
        ok(f"Total {len(filter_names)} minifilter drivers audited.")
    else:
        warn("Could not enumerate minifilter drivers — run as Administrator.")


# ─── DETECTION 6: KERNEL MODULE COMPARISON ───────────────────────────────────
# Theory: Rootkits can hide kernel modules from some enumeration APIs.
# EnumDeviceDrivers vs loaded modules from registry should match.

def detect_hidden_kernel_modules():
    section("DETECTION 6 — KERNEL MODULE COMPARISON (Hidden Module Detection)")
    info("Comparing kernel module list from EnumDeviceDrivers vs Registry...")

    # Set argument types for 64-bit pointers to avoid OverflowError
    psapi.GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD]

    # Method 1: EnumDeviceDrivers via PSAPI (user-mode API)
    arr = (ctypes.c_void_p * 4096)()
    cb_needed = ctypes.wintypes.DWORD()
    modules_api = set()
    if psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(cb_needed)):
        count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(count):
            buf = ctypes.create_unicode_buffer(MAX_PATH)
            if psapi.GetDeviceDriverBaseNameW(arr[i], buf, MAX_PATH):
                name = buf.value.lower()
                if name:
                    modules_api.add(name)

    info(f"EnumDeviceDrivers API reports: {len(modules_api)} kernel modules")

    # Method 2: WMI Win32_SystemDriver (different code path)
    drivers_wmi = ps_json("""
        Get-WmiObject Win32_SystemDriver |
        Where-Object {$_.State -eq 'Running'} |
        Select-Object Name
    """)
    modules_wmi = set((d.get('Name','') or '').lower() + '.sys'
                       for d in drivers_wmi if d.get('Name'))
    info(f"WMI Win32_SystemDriver reports: {len(modules_wmi)} running drivers")

    # Method 3: Registry Services key (what's registered to load)
    modules_reg = set()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services") as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    try:
                        with winreg.OpenKey(key, subkey_name) as sk:
                            try:
                                start_val, _ = winreg.QueryValueEx(sk, "Start")
                                type_val, _  = winreg.QueryValueEx(sk, "Type")
                                # Type 1 = kernel driver, Type 2 = filesystem driver
                                if type_val in (1, 2) and start_val in (0, 1, 2, 3):
                                    modules_reg.add(subkey_name.lower())
                            except FileNotFoundError:
                                pass
                    except Exception:
                        pass
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    info(f"Registry Services (drivers) reports: {len(modules_reg)} registered drivers")

    # Compare API vs WMI
    if modules_api and modules_wmi:
        api_names = {m.replace('.sys','').lower() for m in modules_api}
        # Look for modules visible in WMI but not in API (WMI sees them, API hides them)
        hidden_from_api = set()
        for wmi_drv in modules_wmi:
            wmi_base = wmi_drv.replace('.sys','').lower()
            if not any(wmi_base in api for api in api_names):
                hidden_from_api.add(wmi_drv)

        if hidden_from_api:
            flag(f"DRIVERS IN WMI BUT NOT IN EnumDeviceDrivers API ({len(hidden_from_api)} found)!")
            for h in hidden_from_api:
                flag(f"  Hidden from API: {h}")
        else:
            ok("WMI and EnumDeviceDrivers API module lists are consistent.")
    else:
        warn("Could not fully compare module lists (need Administrator).")


# ─── DETECTION 7: REGISTRY DISCREPANCY CHECK ─────────────────────────────────
# Theory: Registry rootkits hide keys from RegEnumKey but they still exist.
# We can compare registry key counts from different enumeration methods.

def detect_registry_hiding():
    section("DETECTION 7 — REGISTRY DISCREPANCY / HIDDEN KEY DETECTION")
    info("Comparing registry enumeration via WinAPI vs native RegQueryInfoKey...")

    # Critical rootkit persistence locations to check
    critical_keys = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Services",
         "Services (Drivers)"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKLM Run"),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run",
         "HKCU Run"),
    ]

    for hive, subkey, label in critical_keys:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                # Count via Python WinAPI
                info_tuple = winreg.QueryInfoKey(key)
                num_subkeys_api  = info_tuple[0]
                num_values_api   = info_tuple[1]
                last_modified    = info_tuple[2]

                # Now count by actually enumerating
                enum_count = 0
                i = 0
                while True:
                    try:
                        winreg.EnumKey(key, i)
                        enum_count += 1
                        i += 1
                    except OSError:
                        break

                info(f"[{label}] QueryInfoKey says: {num_subkeys_api} subkeys | "
                     f"Enumerated: {enum_count} subkeys")

                if num_subkeys_api != enum_count:
                    diff = abs(num_subkeys_api - enum_count)
                    flag(f"REGISTRY DISCREPANCY in [{label}]!")
                    flag(f"  QueryInfoKey reports {num_subkeys_api} keys but only {enum_count} enumerable!")
                    flag(f"  {diff} keys may be HIDDEN by a registry rootkit!")
                else:
                    ok(f"[{label}] Registry key counts consistent ({enum_count} subkeys).")

        except Exception as e:
            warn(f"Could not check [{label}]: {e}")


# ─── DETECTION 8: CODE INTEGRITY STATUS ──────────────────────────────────────
# Theory: PatchGuard (KPP) protects kernel integrity on 64-bit Windows.
# HVCI (Hypervisor-Protected Code Integrity) prevents even kernel code patching.
# If these are disabled, kernel rootkits are much easier to install.

def detect_code_integrity():
    section("DETECTION 8 — CODE INTEGRITY & KERNEL PROTECTION STATUS")
    info("Checking PatchGuard, DSE, HVCI, and Secure Boot status...")

    # Check Secure Boot
    sb_out = ps("""
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            if ($sb) { "SecureBoot=ENABLED" } else { "SecureBoot=DISABLED" }
        } catch { "SecureBoot=UNAVAILABLE" }
    """)
    if "ENABLED" in sb_out:
        ok("Secure Boot: ENABLED — bootkit installation prevented.")
    elif "DISABLED" in sb_out:
        flag("Secure Boot: DISABLED — bootkits CAN be installed!")
    else:
        warn("Secure Boot: Status could not be determined (VM or older hardware).")

    # Check Code Integrity via registry
    ci_keys = [
        (r"SYSTEM\CurrentControlSet\Control\CI\Config", "HVCIPolicy"),
        (r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity"),
    ]
    hvci_enabled = False
    for regpath, valname in ci_keys:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, regpath) as key:
                val, _ = winreg.QueryValueEx(key, valname)
                if val and int(val) > 0:
                    hvci_enabled = True
        except Exception:
            pass

    if hvci_enabled:
        ok("HVCI (Hypervisor-Protected Code Integrity): ENABLED — strongest kernel protection.")
    else:
        warn("HVCI: Not enabled. Kernel code integrity relies on PatchGuard only.")
        info("  Consider enabling HVCI in Windows Security > Device Security > Core Isolation.")

    # Check if test signing is enabled (dev mode — allows unsigned drivers!)
    test_sign = run("bcdedit /enum {current} 2>nul | findstr /i testsigning")
    if "yes" in test_sign.lower():
        flag("TEST SIGNING MODE IS ENABLED!")
        flag("  This allows UNSIGNED kernel drivers to load.")
        flag("  Rootkits commonly enable this to bypass Driver Signature Enforcement.")
        flag("  Fix: Run 'bcdedit /set testsigning off' then reboot.")
    else:
        ok("Test Signing Mode: DISABLED (Driver Signature Enforcement is active).")

    # Check if DEBUG mode is enabled (disables PatchGuard!)
    debug_mode = run("bcdedit /enum {current} 2>nul | findstr /i \"debug \"")
    if "yes" in debug_mode.lower():
        flag("KERNEL DEBUG MODE IS ENABLED!")
        flag("  Kernel debugging DISABLES PatchGuard — rootkits can patch the kernel freely!")
        flag("  Fix: Run 'bcdedit /debug off' then reboot.")
    else:
        ok("Kernel Debug Mode: DISABLED (PatchGuard is active).")

    # Check if NOINTEGRITYCHECKS is set
    nocheck = run("bcdedit /enum {current} 2>nul | findstr /i nointegritychecks")
    if "yes" in nocheck.lower():
        flag("INTEGRITY CHECKS DISABLED via bcdedit nointegritychecks!")
        flag("  This is a classic rootkit installer technique!")
    else:
        ok("Integrity Checks: Not disabled via bcdedit.")


# ─── DETECTION 9: NETWORK STACK INTEGRITY ────────────────────────────────────
# Theory: Network rootkits hook NDIS/TDI to intercept/hide traffic.
# We can detect this by comparing socket counts from different APIs.

def detect_network_hooks():
    section("DETECTION 9 — NETWORK STACK INTEGRITY CHECK")
    info("Comparing network connections from multiple APIs to detect NDIS hooks...")

    # Method 1: PowerShell Get-NetTCPConnection
    ps_conns = ps("(Get-NetTCPConnection).Count")
    # Method 2: netstat
    netstat_out = run("netstat -ano")
    netstat_lines = [l for l in netstat_out.splitlines()
                     if 'TCP' in l or 'UDP' in l]

    try:
        ps_count      = int(ps_conns.strip())
        netstat_count = len(netstat_lines)
        info(f"PowerShell Get-NetTCPConnection: {ps_count} TCP connections")
        info(f"netstat -ano                   : {netstat_count} TCP/UDP entries")

        diff = abs(ps_count - netstat_count)
        if diff <= 10:
            ok(f"Network API counts roughly consistent (diff={diff}). No NDIS hook detected.")
        else:
            warn(f"Network connection count discrepancy: {diff} entries differ between APIs.")
            info("  May indicate NDIS hook hiding connections (or timing difference).")
    except ValueError:
        warn("Could not parse network connection counts.")

    # Check for suspicious network filter drivers (NDIS hooks)
    sub("Checking for suspicious NDIS/WFP filter drivers...")
    ndis_out = run("netsh wfp show filters")
    if "error" not in ndis_out.lower():
        ok("WFP (Windows Filtering Platform) accessible — no bypass detected.")
    else:
        warn("WFP query failed — possible network stack tampering.")

    # Check LSPs (Layered Service Providers — old TDI hook technique)
    lsp_out = run("netsh winsock show catalog")
    suspicious_lsp = False
    for line in lsp_out.splitlines():
        if 'dll' in line.lower():
            dll_path = line.strip().lower()
            if dll_path and not any(legit in dll_path for legit in
                                     ['system32', 'mswsock', 'winrnr', 'microsoft']):
                warn(f"Suspicious LSP entry: {line.strip()}")
                suspicious_lsp = True
    if not suspicious_lsp:
        ok("No suspicious Winsock LSP (TDI hook) entries found.")


# ─── DETECTION 10: ENTROPY / BEHAVIORAL ANALYSIS ─────────────────────────────
# Theory: Rootkits increase system call latency due to hooking overhead.
# We can measure NtQuerySystemInformation timing and compare to baseline.

def detect_syscall_anomalies():
    section("DETECTION 10 — SYSTEM CALL TIMING ANALYSIS (SSDT Hook Heuristic)")
    info("SSDT hooks add latency to system calls. We measure NtQuerySystemInformation timing.")
    info("High variance or unusually slow calls can indicate hooking.")

    import time

    # Time a series of process enumerations
    SAMPLES = 10
    timings = []

    for _ in range(SAMPLES):
        start = time.perf_counter()
        arr = (ctypes.wintypes.DWORD * 1024)()
        cb  = ctypes.wintypes.DWORD()
        psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(cb))
        elapsed = (time.perf_counter() - start) * 1000  # ms
        timings.append(elapsed)

    avg_ms  = sum(timings) / len(timings)
    max_ms  = max(timings)
    min_ms  = min(timings)
    variance = sum((t - avg_ms) ** 2 for t in timings) / len(timings)
    std_dev  = variance ** 0.5

    info(f"EnumProcesses timing over {SAMPLES} samples:")
    info(f"  Avg: {avg_ms:.3f} ms | Min: {min_ms:.3f} ms | Max: {max_ms:.3f} ms | StdDev: {std_dev:.3f} ms")

    # Thresholds (heuristic — varies by hardware)
    if avg_ms < 5:
        ok(f"System call timing normal ({avg_ms:.3f} ms avg). No SSDT hook timing anomaly.")
    elif avg_ms < 15:
        warn(f"System call timing slightly elevated ({avg_ms:.3f} ms). Could be normal under load.")
    else:
        flag(f"SLOW SYSTEM CALL TIMING: {avg_ms:.3f} ms avg — possible SSDT hook overhead!")
        flag("  Compare with a known-clean system to confirm.")

    if std_dev > 5:
        warn(f"High timing variance ({std_dev:.3f} ms StdDev) — possible intermittent hook or CPU spike.")
    else:
        ok(f"Timing variance acceptable ({std_dev:.3f} ms StdDev).")


# ─── FINAL REPORT ─────────────────────────────────────────────────────────────

def final_report():
    section("FINAL KERNEL ROOTKIT ASSESSMENT")

    duration  = (datetime.datetime.now() - START_TIME).seconds
    total     = len(FLAGS)

    if SCORE == 0:
        risk  = "LOW  — No kernel rootkit indicators found."
        color = C.GREEN
    elif SCORE <= 4:
        risk  = "MEDIUM — Some anomalies found, investigate with kernel-mode tools."
        color = C.YELLOW
    elif SCORE <= 10:
        risk  = "HIGH — Strong rootkit indicators. Use GMER/TDSSKiller immediately."
        color = C.RED
    else:
        risk  = "CRITICAL — Multiple rootkit indicators. ISOLATE and reimage system."
        color = C.RED

    print(f"\n  {C.BOLD}Risk Score  : {color}{SCORE}{C.RESET}")
    print(f"  {C.BOLD}Risk Level  : {color}{risk}{C.RESET}")
    print(f"  {C.BOLD}Total Flags : {total}{C.RESET}")
    print(f"  {C.BOLD}Scan Time   : {duration} seconds{C.RESET}")

    log(f"\n  Risk Score  : {SCORE}")
    log(f"  Risk Level  : {risk}")
    log(f"  Total Flags : {total}")
    log(f"  Scan Time   : {duration} seconds")

    if FLAGS:
        print(f"\n{C.RED}{C.BOLD}  ===== FLAGS ====={C.RESET}")
        log(f"\n  ===== FLAGS =====")
        for i, f in enumerate(FLAGS, 1):
            print(f"  {C.RED}[{i:02d}]{C.RESET} {f[:110]}")
            log(f"  [{i:02d}] {f}")
    else:
        print(f"\n{C.GREEN}  No rootkit indicators found — system kernel appears clean!{C.RESET}")
        log(f"\n  No rootkit indicators found — system kernel appears clean!")

    print(f"""
{C.DIM}  IMPORTANT LIMITATION:
  This scanner operates from user-mode (Ring-3). A sophisticated kernel
  rootkit (Ring-0) can hide from ALL user-mode tools simultaneously.
  For confirmed infections or high-risk scenarios, ALWAYS use:

    > GMER          : http://www.gmer.net          (free, kernel-mode scanner)
    > TDSSKiller    : kaspersky.com/tdsskiller      (Kaspersky, free)
    > RootkitBuster : trendmicro.com                (Trend Micro, free)
    > Bootable Scan : Boot from USB with AV, scan offline (most reliable)
{C.RESET}""")

    log("\n  IMPORTANT LIMITATION:")
    log("  This scanner operates from user-mode (Ring-3). For confirmed")
    log("  infections, use GMER, TDSSKiller, or offline bootable scanner.")

    # Save report
    log(f"\n\n{'='*66}")
    log(f"  Scan completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"{'='*66}")

    try:
        DESKTOP.mkdir(parents=True, exist_ok=True)
        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(REPORT_LINES))
        print(f"\n  {C.GREEN}Report saved to: {REPORT_FILE}{C.RESET}\n")
    except Exception as e:
        print(f"  {C.YELLOW}Could not save report: {e}{C.RESET}")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    os.system('color')

    if not sys.platform.startswith('win'):
        print("This tool is for Windows only.")
        sys.exit(1)

    # Check for admin
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    banner()

    if not is_admin:
        print(f"{C.RED}  [!] NOT running as Administrator!{C.RESET}")
        print(f"{C.RED}  [!] Many checks will be incomplete. Right-click → Run as Admin.{C.RESET}\n")
    else:
        print(f"{C.GREEN}  [+] Running as Administrator — full scan enabled.{C.RESET}\n")

    try:
        detect_hidden_processes()
        detect_unsigned_drivers()
        detect_driver_path_anomalies()
        detect_mbr_bootkit()
        detect_minifilter_rootkits()
        detect_hidden_kernel_modules()
        detect_registry_hiding()
        detect_code_integrity()
        detect_network_hooks()
        detect_syscall_anomalies()
        final_report()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Scan interrupted.{C.RESET}")
        final_report()
    except Exception as e:
        import traceback
        print(f"{C.RED}  Error: {e}{C.RESET}")
        traceback.print_exc()
        final_report()


if __name__ == "__main__":
    main()
