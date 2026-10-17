# IR-003 — Brute Force Authentication Attack

**Date:** 2026-10-17
**Analyst:** Naim Hariri
**Severity:** Medium (Level 5)
**MITRE Technique:** T1110 — Brute Force
**Status:** Resolved

---

## 1. Executive Summary

Ten consecutive failed authentication attempts were detected against the local Administrator account on endpoint DESKTOP-UHNGR5H using `net use` over SMB (IPC$). The attempts originated from the endpoint itself via PowerShell, indicating a potential lateral movement simulation or credential spraying activity. Wazuh rule 60122 detected the repeated logon failures via Windows Security Event ID 4625.

---

## 2. Detection

| Field | Value |
|-------|-------|
| Wazuh Rule | 60122 |
| Rule Description | Logon Failure - Unknown user or bad password |
| Windows Event ID | 4625 |
| Alert Level | 5 |
| Timestamp | 2026-10-17 19:49:50 – 19:50:25 UTC |
| Endpoint | DESKTOP-UHNGR5H (10.0.2.15) |
| Target Account | Administrator |
| Failure Count | 10 |

---

## 3. Timeline

| Time (UTC) | Event |
|------------|-------|
| 19:49:50 | First logon failure — Administrator / wrongpassword via SMB |
| 19:49:50–19:50:25 | 10 consecutive failures over 35 seconds |
| 19:50:25 | Wazuh rule 60122 triggered on each failure |
| 19:50:31 | Rule 92037 triggered — net.exe remote connection spawned via PowerShell |

---

## 4. Analysis

The attacker used `net use \\target\IPC$` to authenticate over SMB — a common reconnaissance and lateral movement technique. The IPC$ share is used for inter-process communication and is frequently targeted in brute force and Pass-the-Hash attacks.

**Indicators of Compromise:**
- Repeated Event ID 4625 (failed logon) in short time window
- `net.exe` spawned by `powershell.exe` (parent-child anomaly)
- Target: built-in Administrator account

**If attack succeeded:**
- Attacker gains SMB session as Administrator
- Enables lateral movement, file access, and remote command execution

---

## 5. Containment & Response

- No successful authentication occurred
- Account lockout policy would block this in a hardened environment
- Simulation stopped after 10 attempts

---

## 6. Lessons Learned

- Windows Security log (Event ID 4625) is critical for brute force detection — already captured by Wazuh's default config
- Account lockout policies (e.g., lock after 5 failures) are the most effective prevention control
- Alerting on rapid successive 4625 events from the same source should trigger automated blocking via Wazuh active response
