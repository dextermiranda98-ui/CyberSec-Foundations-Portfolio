# Incident Report: Privilege Escalation & Domain Dominance

**Incident ID:** INC-2025-089  
**Status:** Closed / Remediated  
**Severity:** Critical  

## 1. Executive Summary
An alert was triggered indicating a suspicious Kerberos Ticket Granting Ticket (TGT) request with an unusually long lifetime (10 years), indicating a **Golden Ticket Attack** targeting the `projectx.local` Domain Controller. 

## 2. Detection & SIEM Telemetry
* **Detection Tool:** Wazuh SIEM
* **Triggered Rule:** Rule ID `60100` (Windows Event ID 4624 - Successful Logon using an explicitly specified explicit credential).
* **Source IP:** 10.0.0.50 (Kali Attacker Box)
* **Target Host:** CORP-DC-01 (10.0.0.10)

## 3. Containment & Eradication Steps
1. **Isolated Target Host:** The compromised host was network-isolated using internal VMware host-only adapter controls to halt data exfiltration.
2. **Reset KRBTGT Password:** Executed the built-in Microsoft script to reset the `krbtgt` account password twice, rendering all forged tickets invalid.
3. **Log Cleansing & Analysis:** Validated using Sysmon logs that malicious lateral persistence hooks were purged.
