# T1136.001 - Create Account: Local Account
# Simulates attacker creating a backdoor local user account
# Expected detection: Wazuh rule 60109

net user hacker Password123! /add
Start-Sleep -Seconds 5
net user hacker /delete
