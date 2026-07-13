# From Anomalies to Automation: Hunting a Stealthy Crypto-Miner and Building Custom IR Tooling in Python

*A deep dive into discovering, dissecting, and destroying a stubborn crypto-miner, and how it led to the creation of custom Windows threat-hunting tools.*

As a VAPT (Vulnerability Assessment and Penetration Testing) analyst, you get used to looking for the invisible. But sometimes, the invisible makes itself known through a symptom as mundane as a sluggish laptop. 

What started as a routine investigation into unexpected system latency recently spiraled into a full-scale digital forensics and incident response (DFIR) engagement. The culprit? A highly evasive crypto-miner deeply entrenched in the Windows operating system. 

Here is a breakdown of how the threat was discovered, the clever persistence mechanisms it employed, the manual remediation process, and how this incident inspired the creation of a custom, automated Python threat-hunting suite.

---

## 1. The Initial Compromise & Discovery

The first indicator of compromise (IoC) was classic: inexplicable CPU and GPU spikes when the system was idle, which vanished the moment Task Manager was opened. This is a common evasion technique used by modern miners to avoid casual detection.

### The Disguise: Process Hollowing
A deeper look using advanced process enumeration revealed the truth. The malware wasn't running as `miner.exe`; it was masquerading as legitimate Adobe background services. By utilizing **Process Hollowing**—a technique where legitimate executables are launched in a suspended state, hollowed out, and injected with malicious payloads—the miner managed to blend into the background noise of everyday computing.

---

## 2. Dissecting the Persistence Mechanisms

Removing the hollowed process in memory was easy; keeping it gone was the challenge. The malware utilized a multi-tiered persistence strategy designed to survive reboots and frustrate removal attempts.

### Strategy A: The Unkillable Shell Extension
The most stubborn persistence mechanism was a malicious DLL (`CoreSync_x64.dll`) registered as a Windows Shell Extension. Because shell extensions are loaded directly into `explorer.exe` (the Windows UI shell), the file is constantly locked by the operating system. You can't delete it because it's "in use."

**The Fix:**
To rip out the DLL, we had to forcefully break the lock:
1. Terminated the `explorer.exe` process entirely via command line.
2. Used `takeown` and `icacls` to strip the malicious file of its protected SYSTEM ownership and grant full access to the local admin.
3. Deleted the DLL before the shell could respawn and lock it again.

### Strategy B: DNS Hijacking via the `hosts` File
To prevent the system from downloading antivirus updates or communicating with security telemetry servers, the malware hijacked the `C:\Windows\System32\drivers\etc\hosts` file, redirecting critical security domains to `localhost` (`127.0.0.1`). 

Like the shell extension, the `hosts` file was locked—this time by the `dnscache` service. Because `dnscache` is a protected service that cannot be easily stopped in modern Windows, we used a file-swapping bypass: copying the file to the Desktop, cleaning the malicious entries, and forcefully overwriting the original file using an elevated command prompt.

### Strategy C: Registry Autoruns and Scheduled Tasks
Finally, standard persistence hooks were found in the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry keys, ensuring the initial loader executed every time the user logged in. These were purged manually.

---

## 3. From Manual Cleanup to Automation

While manual DFIR is satisfying, it’s not scalable. To ensure the system was truly clean and to prepare for future engagements, I decided to codify the methodologies used during the cleanup into automated tooling. 

I developed two robust Python-based tools, designed to run natively on Windows without requiring heavy third-party agent installations:

### Tool 1: The User-Mode Threat Hunter
A 7-phase Python scanner that audits the system from the ground up:
1. **Process Analysis:** Identifies hollowed processes, spoofed system names, and executables running from suspicious locations (like `AppData` or `Temp`).
2. **Network Analysis:** Scans for active backdoor ports and audits the `hosts` file and DNS cache for DGA (Domain Generation Algorithm) domains.
3. **Persistence Mechanisms:** Audits Registry Run keys, Startup folders, and Scheduled Tasks.
4. **File System Forensics:** Hunts for recently dropped executables (`.exe`, `.dll`, `.sys`) in temporary directories.
5. **Miner Detection:** Actively samples CPU delta timing to catch "burst" miners and polls GPU utilization.
6. **Security Logs & Obfuscation:** Checks for encoded PowerShell commands often used in fileless malware.

### Tool 2: The Kernel Rootkit Scanner (Ring-0)
Because advanced malware can operate in kernel space (Ring-0) to hide its user-mode (Ring-3) activities, I built a secondary scanner utilizing `ctypes` to interact directly with the Windows API:
* **DKOM Detection:** Uses Cross-View Process Enumeration (comparing `CreateToolhelp32Snapshot`, `EnumProcesses`, WMI, and PowerShell) to find discrepancies. If an API returns 252 processes but another returns 250, a rootkit is hiding something.
* **Driver Auditing:** Checks all loaded `.sys` kernel modules for valid digital signatures to catch PatchGuard/DSE bypasses.
* **Minifilter Analysis:** Audits registered I/O minifilters to detect rootkits intercepting file reads.

### The Wrapper
To make the tools operationally viable, I wrapped them in a simple Windows Batch script (`.bat`) that enforces Administrator privileges, runs both scanners sequentially, and merges their outputs into a single, time-stamped `MASTER_SECURITY_AUDIT` text file. 

---

## Key Takeaways for VAPT Analysts

1. **Trust Your Instincts (And Your CPU Fan):** If a system feels sluggish or runs hot, don't dismiss it as poor optimization.
2. **Understand Windows Internals:** Knowing how `explorer.exe` handles shell extensions or how `dnscache` locks network files is critical when traditional "delete" commands fail.
3. **Automate Your Knowledge:** Every time you manually dissect a threat, you are writing a behavioral signature in your head. Translate that signature into code. Building custom Python tools not only deepens your understanding of OS APIs but provides you with a portable, bespoke toolkit for your next engagement.

*The system is now running faster than ever, and the custom Python suite has been added to my permanent DFIR toolkit. On to the next hunt.*

---

## Get the Tools

To help other security researchers and VAPT analysts, I have open-sourced the automated Python tools we built during this engagement. 

You can download **ThreatHunter.py** and **KernelRootkitScanner.py** on my GitHub:

🔗 **[GitHub Repository: Windows-DFIR-Audit-Suite](https://github.com/sxyjvs10/Windows-DFIR-Audit-Suite)**

*Feel free to fork it, contribute, or use it to speed up your next Windows malware investigation!*
