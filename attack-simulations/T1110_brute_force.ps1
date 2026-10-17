# T1110 - Brute Force
# Simulates repeated failed authentication attempts against localhost
# Expected detection: Wazuh rule 60122

1..10 | ForEach-Object { net use \\localhost\IPC$ /user:Administrator wrongpassword 2>$null }
