# Windows DFIR Audit Suite

A lightweight, automated Digital Forensics and Incident Response (DFIR) toolkit for Windows. 
This suite contains custom Python scripts designed to hunt down evasive user-mode malware (like process-hollowing crypto-miners) and Ring-0 kernel rootkits.

## 🧰 What's Included

* **`ThreatHunter.py`**: A user-mode 7-phase scanner that audits processes, network connections, persistence mechanisms (Registry, Scheduled Tasks, Startup), file drops in suspicious locations, and basic crypto-miner indicators.
* **`KernelRootkitScanner.py`**: A Ring-0 focused scanner that uses `ctypes` to interact with the Windows API. It detects DKOM (Direct Kernel Object Manipulation) hidden processes, unsigned kernel drivers, minifilter I/O interception, and MBR bootkits.
* **`Run_Security_Audit.bat`**: A master wrapper script that runs both Python tools sequentially and merges their outputs into a single, clean report file on your Desktop.

## 🚀 How to Use

1. **Requirements:** You must have Python 3 installed on the target machine.
2. **Download:** Clone or download this repository so that all three files are in the same folder.
3. **Execute:** Right-click **`Run_Security_Audit.bat`** and select **"Run as Administrator"**.
   *(Note: Administrator privileges are strictly required. If you run it as a standard user, the kernel checks and system-level file inspections will fail and return false positives).*
4. **Review:** Once the script finishes, a `MASTER_SECURITY_AUDIT` text file will be generated containing the complete combined results of both scans.

## ⚠️ Limitations
The Kernel Scanner operates from user-mode (Ring-3). A highly sophisticated kernel rootkit (Ring-0) can theoretically manipulate the APIs this script uses to remain hidden. For confirmed, deep kernel infections, always supplement this toolkit with dedicated kernel-mode scanners like Kaspersky TDSSKiller or GMER.

---
*Developed during an active incident response engagement to eradicate a deeply entrenched crypto-miner.*
