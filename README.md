🛡️ Project Overview
This repository documents the Enterprise 101 (E101) core section from ProjectSecurity.io, where I designed, built, attacked, and defended a small, virtualized enterprise network known as "ProjectX."

The primary goal of this project was to gain hands-on, end-to-end experience in both offensive (Red Team) and defensive (Blue Team) security within a realistic Active Directory environment.

Key Outcomes:

Successfully deployed and managed a multi-OS virtual network using a defined enterprise topology.

Implemented a Security Information and Event Management (SIEM) solution for continuous monitoring.

Executed a multi-stage cyber attack, from initial access to data exfiltration.

Developed custom detection rules and performed incident response to identify and contain the simulated threat.

🏛️ Lab Topology and Technologies
The ProjectX network was segmented and managed using VirtualBox (or VMware) to simulate a modern corporate infrastructure.

Network Components
Virtual Machine (VM)

Role

Operating System/Tool

Purpose

PROJECTX-AD

Domain Controller (DC)

Windows Server 2025

Centralized identity management (Active Directory) and DNS resolution.

PROJECTX-W11

Windows Workstation

Windows 11 Enterprise

Simulates a primary user endpoint. Used for phishing and vulnerability exploitation.

PROJECTX-LINUX

Corporate Workstation

Ubuntu Desktop 22.04

Simulates a secondary user endpoint.

PROJECTX-SEC

Security Server (SIEM)

Ubuntu Server 22.04 + Wazuh

Security Information and Event Management, collecting logs from all endpoints via agents.

PROJECTX-NETMON

Network Monitoring

Security Onion

Intrusion Detection System (IDS) and network log analysis.

ATTACKER-VM

Offensive Machine

Kali Linux

Used to execute the simulated cyber attack chain.

Corporate Services

Email/Web Sandbox

MailHog

Simulates an internal email server for intercepting phishing attempts.

Core Skills Demonstrated
System Administration: Active Directory setup, Group Policy Object (GPO) configuration, DNS management.

Virtualization: Configuration of NAT and Internal/Host-Only networks for isolation and segmentation.

Log Management: Deployment and configuration of Wazuh agents and centralized log ingestion.

Incident Detection: Writing custom detection rules for specific attack techniques.

Offensive Security: Phishing, payload delivery, privilege escalation, and lateral movement.

💥 Cyber Attack Simulation (Red Team)
A full, end-to-end attack was conducted against the ProjectX environment, leveraging misconfigurations and vulnerable user interaction to compromise the domain. The phases mapped directly to the MITRE ATT&CK framework:

ATT&CK Phase

Technique (T-Code)

Summary of Action

Initial Access

T1566 (Phishing)

Delivered a malicious file or link to the target user on the Windows 11 endpoint, resulting in initial execution.

Execution

T1059 (Command and Scripting Interpreter)

Executed a reverse shell payload using PowerShell to establish C2 communication.

Lateral Movement

T1021 (Remote Services)

Used tools like PsExec or compromised credentials to move from the initial workstation to the Domain Controller (PROJECTX-AD).

Privilege Escalation

T1068 (Exploitation for Privilege Escalation)

Elevated user privileges on the DC to a Domain Administrator level.

Exfiltration

T1041 (Exfiltration Over C2 Channel)

Stole simulated "sensitive data" files from a corporate share, proving the breach objective was met.

Persistence

T1547 (Boot or Logon Autostart Execution)

Established a mechanism to maintain access in case of a system reboot or session termination.

🔎 Incident Response and Detection (Blue Team)
The primary goal of the Blue Team component was to ensure the security stack could detect every phase of the Red Team simulation.

Wazuh Alert Triage: Monitored the Wazuh dashboard for high-severity alerts related to unauthorized process execution (PowerShell), new user creation, and suspicious remote logins.

Custom Rule Writing: Developed a custom rule to specifically detect the unique characteristics of the malicious payload used during the initial access phase, lowering the time-to-detection.

Log Investigation: Used Security Onion (Elastic Stack, Wireshark, Suricata) to analyze network traffic and system logs (Sysmon) from the endpoints to confirm the source, method, and scope of the compromise.

Remediation: Document\
