🛡️ Enterprise Cyber Range: Offense & Defense Lab

Project Overview

This project is a full-scale simulation of a corporate enterprise environment. It was designed to practice the CIA Triad (Confidentiality, Integrity, and Availability) by deploying a vulnerable network and defending it using industry-standard SIEM and XDR tools.

💻 The Hardware Environment

Device: Dell XPS 13

Optimization: Leveraged hardware virtualization (VT-x) and aggressive resource capping to maintain a stable 8-10 VM environment on a mobile workstation.

Hypervisor: Oracle VirtualBox

Note: Managed strict RAM and CPU thread allocation to ensure high-fidelity telemetry collection from the SIEM without system bottlenecks.

🛠️ The Tech Stack

Identity: Windows Server 2022 (Active Directory, DNS, GPO)

Defensive: Wazuh (SIEM/XDR), Security Onion, Sysmon

Offensive: Kali Linux, Metasploit, PowerShell Empire

Endpoints: Windows 10/11 (Target machines), Ubuntu Mail Server (MailHog)

🚀 Key Security Milestones

Infrastructure Hardening: Deployed Active Directory and configured Group Policy Objects (GPOs) to enforce security baselines.

Telemetry & Monitoring: Installed Wazuh agents on all endpoints. Configured custom rules to detect LSASS dumping and Unauthorized RDP attempts.

Attack Simulation: * Performed Brute Force attacks on the Mail Server.

Executed Mimikatz to test credential harvesting detection.

Successfully alerted on and mitigated a Golden Ticket attack within the AD environment.

Incident Response: Documented "False Positives" vs "True Positives" to refine the SIEM alert-to-noise ratio.

📂 Repository Contents

* [Documentation/](Documentation/) - This folder contains detailed write-ups and reports, including the **[Cyber Attack Simulation Report](Documentation/Attack_Simulation_Report.md)**, which details the full Red and Blue Team analysis.

* [Configuration-Scripts/](Configuration-Scripts/) - All custom configuration files, including Wazuh rule definitions, Active Directory Group Policy scripts, and hardening baselines.

* [Attack-Artifacts/](Attack-Artifacts/) - The non-malicious code/payloads (e.g., Python scripts, HTML templates) used for the simulation. (Disclaimer: For educational use only.)

* [Evidence-Screenshots/](Attack-Artifacts/) - Visual proof of key deployment and attack steps (e.g., Wazuh Alerts Dashboard, successful whoami commands on the Domain Controller).

🚀 Future Enhancements (NA101 Integration)

This project serves as the foundation for future work. The immediate next steps include building off this topology for the Networks & Attacks 101 (NA101) course:

Integrating a dedicated firewall solution (e.g., pfSense) to implement network segmentation rules.

Deploying an Intrusion Prevention System (IPS) like Suricata to actively block network attacks.

Practicing advanced network-layer attacks (MiTM, DNS Spoofing).
