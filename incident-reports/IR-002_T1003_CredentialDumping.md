# IR-002 — Credential Dumping via SAM Hive Export

**Date:** 2026-10-17
**Analyst:** Naim Hariri
**Severity:** Critical (Level 14)
**MITRE Technique:** T1003 — OS Credential Dumping
**Status:** Resolved

---

## 1. Executive Summary

An attacker used `reg.exe` to export the SAM and SYSTEM registry hives to disk on endpoint DESKTOP-UHNGR5H. This technique enables offline extraction of local account password hashes using tools such as Mimikatz or impacket's `secretsdump`. Wazuh rule 92026 triggered with a specific signature for SAM hive dumping, generating a level 14 critical alert.

---

## 2. Detection

| Field | Value |
|-------|-------|
| Wazuh Rule | 92026 |
| Rule Description | Reg.exe used to dump SAM hive |
| Alert Level | 14 |
| Timestamp | 2026-10-17 19:51:54 UTC |
| Endpoint | DESKTOP-UHNGR5H (10.0.2.15) |

**Commands Detected:**
```
reg save HKLM\SAM C:\Windows\Temp\sam.bak
reg save HKLM\SYSTEM C:\Windows\Temp\system.bak
```

---

## 3. Timeline

| Time (UTC) | Event |
|------------|-------|
| 19:51:54 | reg.exe invoked to save SAM hive to C:\Windows\Temp\sam.bak |
| 19:51:54 | Wazuh rule 92026 triggered — level 14 alert |
| 19:52:01 | Rule 92213 triggered — executable dropped in suspicious location |
| 19:52:xx | SAM and SYSTEM hive files deleted (cleanup) |

---

## 4. Analysis

Exporting the SAM hive is a standard credential theft technique. The SAM (Security Account Manager) hive contains hashed credentials for all local accounts. Combined with the SYSTEM hive (which contains the boot key needed to decrypt SAM), an attacker can perform offline hash extraction without ever touching LSASS memory.

**Attack chain if successful:**
1. `reg save HKLM\SAM` → exports local account hashes
2. `reg save HKLM\SYSTEM` → exports boot key
3. Exfiltrate both files
4. Run `secretsdump.py -sam sam.bak -system system.bak LOCAL` → plaintext hashes
5. Use hashes for Pass-the-Hash or offline cracking

---

## 5. Containment & Response

- Hive files deleted immediately after detection (simulation cleanup)
- No evidence of exfiltration
- No accounts compromised
- Wazuh rule 92026 confirmed effective detection

---

## 6. Lessons Learned

- Wazuh ships with a built-in rule (92026) specifically for SAM hive dumping — no custom rule needed
- Monitoring `C:\Windows\Temp\` for unexpected `.bak` or `.hiv` files is an effective secondary detection layer
- Restricting `reg save` for non-admin users via AppLocker or Group Policy would prevent this technique
