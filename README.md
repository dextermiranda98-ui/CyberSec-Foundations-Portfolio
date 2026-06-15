🛡️ Enterprise Cyber Range: Offense & Defense Lab

📌 Project Overview

This project is a full-scale simulation of a corporate enterprise environment designed to operationalize the CIA Triad (Confidentiality, Integrity, and Availability). The lab consists of deploying a multi-tier vulnerable corporate network, executing sophisticated attack vectors, and engineering detection/defense mechanisms using industry-standard SIEM and XDR ecosystems.

💻 Hardware & Virtualization Architecture

Host Device: Dell XPS 13

Optimization: Optimized hardware virtualization (VT-x) and engineered aggressive resource/vCPU capping to maintain a stable, high-fidelity 8–10 Virtual Machine topology on a single mobile workstation without telemetry loss or bottlenecking.

Hypervisor Platform: VMware Workstation

🛠️ The Enterprise Tech Stack

Identity & Access Management (IAM): Windows Server 2022 (Active Directory, DNS, GPO)

Defensive Architecture (SIEM/XDR): Wazuh (SIEM/XDR), Security Onion, System Monitor (Sysmon)

Offensive Frameworks: Kali Linux, Metasploit Framework, PowerShell Empire

Target Endpoints & Infrastructure: Windows 10/11 Enterprise, Ubuntu Mail Server (MailHog)

🚀 Infrastructure, Support & Security Milestones

🏗️ 1. Enterprise IT Administration & Support

Network Infrastructure: Configured core DNS zones and DHCP scopes to ensure stable network lease assignments across all Windows 10/11 endpoints.

Identity Management Lifecycle: Simulated full onboarding, role changes, and offboarding workflows within Active Directory for a mock "ProjectX" workforce.

Desktop Support Engineering: Replicated common Windows 10 "Blue Screen of Death" (BSOD) errors and connectivity drops to develop rapid troubleshooting and root-cause analysis playbooks.

🔒 2. Infrastructure Hardening & Defensive Engineering

Identity Hardening: Deployed Windows Server 2022 Active Directory and established custom Group Policy Objects (GPOs) to enforce strict enterprise security baselines.

Telemetry & Monitoring Egress: Deployed Wazuh agents across all windows and Linux endpoints. Engineered custom detection rules targeting advanced post-exploitation techniques, including LSASS memory dumping and unauthorized RDP connection attempts.

SIEM Tuning & Tuning: Analyzed and documented "False Positives" vs. "True Positives" to actively suppress benign alert noise and optimize analyst triage efficiency.

⚔️ 3. Threat Simulation & Incident Response

Credential Theft Mitigated: Alerted on, triaged, and successfully mitigated a high-severity Golden Ticket (Kerberos) attack within the Active Directory domain controller.

Network Layer Attacks: Executed automated Brute Force attacks against the Ubuntu Mail Server to validate log ingestion and security control alerts.

📂 Repository Architecture

* [Documentation/](Documentation/) - This folder contains detailed write-ups and reports, including the **[Cyber Attack Simulation Report](Documentation/Attack_Simulation_Report.md)**, which details the full Red and Blue Team analysis.

* [Configuration-Scripts/](Configuration-Scripts/) - All custom configuration files, including Wazuh rule definitions, Active Directory Group Policy scripts, and hardening baselines.

* [Attack-Artifacts/](Attack-Artifacts/) - The non-malicious code/payloads (e.g., Python scripts, HTML templates) used for the simulation. (Disclaimer: For educational use only.)

* [Evidence-Screenshots/](Attack-Artifacts/) - Visual proof of key deployment and attack steps (e.g., Wazuh Alerts Dashboard, successful whoami commands on the Domain Controller).

🚀 Future Enhancements (NA101 Integration)

This project serves as the foundation for future work. The immediate next steps include building off this topology for the Networks & Attacks 101 (NA101) course:

Integrating a dedicated firewall solution (e.g., pfSense) to implement network segmentation rules.

Deploying an Intrusion Prevention System (IPS) like Suricata to actively block network attacks.

Practicing advanced network-layer attacks (MiTM, DNS Spoofing).
