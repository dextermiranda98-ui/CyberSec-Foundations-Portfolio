ProjectX Enterprise E101: Cyber Attack Simulation and Incident Report
1. Executive Summary

A simulated Red Team engagement was conducted against the ProjectX virtual enterprise environment to test the efficacy of deployed security controls (Wazuh SIEM/XDR). The objective was to achieve Domain Administrator privileges and exfiltrate simulated sensitive data. The Red Team successfully achieved all objectives, leveraging a phishing-based Initial Access vector and lateral movement techniques. The Blue Team, however, was able to detect and triage the activity through the deployed Wazuh SIEM, demonstrating visibility and log ingestion success, though specific hardening measures are required to prevent recurrence.

2. Environment and Scope

Target Environment: ProjectX Virtual Network (Simulated Enterprise)

Hypervisor: VirtualBox

Key Systems: Windows Server 2025 (Domain Controller), Windows 11 Workstation, Ubuntu Workstation, Kali Linux (Attacker), Ubuntu Server (Wazuh SIEM), Security Onion (Network Monitoring).

Scope: The engagement covered the full cyber kill chain, from initial reconnaissance to achieving persistence on the Domain Controller.

3. Attack Methodology (Red Team)

The attack followed a structured approach based on the MITRE ATT&CK framework. The primary goal was credential compromise and administrative control over the domain.

| ATT&CK Phase | Technique (T-Code) | Attack Details | Outcome | 
| ----- | ----- | ----- | ----- | 
| **Reconnaissance** | T1589 (Gather Victim Identity Information) | Enumerated internal domain users and names using open-source methods (simulated). | Identified target users for phishing. | 
| **Initial Access** | T1566 (Phishing: Malicious File) | Delivered a payload (simulated malicious document/script) to the Windows 11 Workstation (PROJECTX-W11). | Achieved user-level execution on the endpoint. | 
| **Execution** | T1059 (PowerShell) | Executed a **reverse shell payload** to establish a Command and Control (C2) channel back to the Kali Linux attacker machine. | Persistent remote access established. | 
| **Lateral Movement** | T1021 (Remote Services) | Utilized captured credentials and **PsExec** to move from the PROJECTX-W11 workstation to the Domain Controller (PROJECTX-AD). | Gained SYSTEM privileges on the Domain Controller. | 
| **Exfiltration** | T1041 (Exfiltration Over C2) | Copied simulated "sensitive data" (placeholder files) and transferred them over the established C2 channel. | **Objective Achieved.** | 
| **Persistence** | T1547 (Run Keys) | Modified a registry key to ensure the shell re-established upon system reboot. | **Objective Achieved.** | 

4. Detection and Analysis (Blue Team)

The defensive posture was primarily centered on endpoint telemetry gathered by the Wazuh agents.

| Security Tool | Observation / Findings | Analysis | 
| ----- | ----- | ----- | 
| **Wazuh SIEM/XDR** | Multiple high-severity alerts detected: `Suspicious PowerShell Execution` (ID 60002), `New Remote Login from Unusual Source` (ID 5400), and `Unusual Process Execution` on PROJECTX-AD. | Logs from the Windows 11 Sysmon and Security event logs provided a clear timeline of the execution and privilege escalation steps. | 
| **Security Onion** | Detected spikes in outbound traffic matching C2 beaconing patterns. Identified the initial HTTP connection used for payload retrieval. | Network analysis confirmed the IP address of the Kali Attacker VM and the ports used for C2 communication. | 
| **Custom Rule:** | A custom rule targeting the specific registry modification (T1547) successfully triggered on PROJECTX-AD. | **Demonstrates effective pro-active security rule engineering.** | 

5. Remediation and Recommendations

Based on the findings of this simulation, the following actions are recommended for the ProjectX environment:

Endpoint Hardening: Implement a Group Policy Object (GPO) to enforce PowerShell script block logging and restrict PowerShell execution policies on all user workstations (PROJECTX-W11, PROJECTX-LINUX).

Access Control: Enforce least-privilege principles. Conduct a review of Domain Controller access and ensure no standard user accounts have local administrative rights on any sensitive servers.

Authentication: Implement Multi-Factor Authentication (MFA) for all domain administrator and critical service accounts to mitigate the risk of credential compromise.

Security Monitoring Improvement: Refine Wazuh rule sets to include automated response actions (e.g., firewall blocking) upon confirmed detection of high-risk lateral movement activity.
