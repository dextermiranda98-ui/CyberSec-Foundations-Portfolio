 Configuration Scripts Overview

1. Executive Summary

This folder contains the reusable configuration files, scripts, and templates used to build, secure, and monitor the ProjectX enterprise lab environment. The files demonstrate skills in repeatable deployment, host hardening, and centralized security management across Windows and Linux platforms.

2. Windows Automation Scripts (PowerShell)

These scripts are designed to run on the Windows Server (PROJECTX-AD) or the Windows 11 workstation (PROJECTX-W11) for automated configuration.


| Filename | Platform | Purpose | Skills Demonstrated |
| ----- | ----- | ----- | ----- |
| `Deploy-Sysmon.ps1` | Windows | Automates the installation and configuration of the Sysmon service using a pre-configured XML manifest file. | Infrastructure as Code, Advanced Logging, PowerShell. |
| `Install-WazuhAgent.ps1` | Windows | Installs the Wazuh agent on endpoints and configures it to report to the Wazuh Manager (PROJECTX-SEC). | Endpoint Security Deployment, Remote Management. |
| `AD-ServiceAccountSetup.ps1` | Windows Server | Script to quickly create standardized service accounts and assign necessary permissions in Active Directory. | AD Management, Identity and Access Management (IAM). |

3. Linux Configuration and Automation (Bash)

These scripts handle system updates, security hardening, and essential service deployment on the Ubuntu servers (PROJECTX-SEC, PROJECTX-NETMON).


| Filename | Platform | Purpose | Skills Demonstrated |
| ----- | ----- | ----- | ----- |
| `Harden-UFW.sh` | Ubuntu Server | Configures the Uncomplicated Firewall (UFW) to only allow necessary inbound traffic (SSH, Wazuh, etc.) and deny all others. | Linux Security, Network Segmentation. |
| `Setup-MailHog.sh` | Ubuntu Server | Installs and configures the MailHog container on the corporate server for email sandbox testing. | Docker/Containerization, Service Deployment. |
| `WazuhAgent-Enroll.sh` | Ubuntu Clients | Automated script for downloading, installing, and enrolling the Wazuh agent on Linux clients. | Automated Client Provisioning. |

4. Security Tool Configuration Files (XML/YML)

These are the non-executable configuration files that define the logic and rules for the security tools.


| Filename | Tool | Purpose | Skills Demonstrated |
| ----- | ----- | ----- | ----- |
| `sysmon-config.xml` | Sysmon | The XML file containing the rules for which events (process creation, network activity, etc.) Sysmon should log. | Telemetry Customization, XML Configuration. |
| `custom_rules.xml` | Wazuh Manager | Custom alert rules written to detect specific activities, such as lateral movement or known malicious PowerShell commands. | Detection Engineering, Threat Hunting, SIEM Tuning. |
