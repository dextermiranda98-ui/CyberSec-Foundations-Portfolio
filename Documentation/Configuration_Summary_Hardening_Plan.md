ProjectX Enterprise E101: Configuration Summary and Hardening Plan

1. Executive Summary

This document summarizes the core defensive configurations implemented in the ProjectX environment during the Blue Team setup phase. The focus was on establishing foundational security controls, including centralized logging, policy enforcement via Active Directory, and host-based firewall hardening, to prepare the network for the attack-and-defend scenario.

2. Windows Hardening (PROJECTX-AD, PROJECTX-W11)

Windows security was enforced primarily through centralized Group Policy Objects (GPO) applied to the relevant Organizational Units (OU) and host-based configuration.

| Area | Configuration Tool / Policy | Implementation Detail | Purpose |
| ----- | ----- | ----- | ----- |
| **Logging** | GPO / Sysmon | Deployed Sysmon via GPO to collect enhanced event logs (process creation, network connections, registry changes). | Provides critical telemetry for Wazuh SIEM to detect advanced threats. |
| **Authentication** | GPO (Password Policy) | Enforced strong password requirements (length, complexity, history) and account lockout policies. | Mitigates brute-force and credential stuffing attacks. |
| **Firewall** | Windows Defender Firewall GPO | Enabled Windows Firewall on all hosts. Restricted inbound connections to only essential services (e.g., RDP, SMB for administration). | Reduces the attack surface area of the endpoints. |
| **Script Control** | GPO / AppLocker (Simulated) | Configured PowerShell execution policy to `Restricted` (simulated via GPO for demonstration). | Prevents unauthorized script execution, a common Initial Access vector. |
| **Auditing** | GPO (Advanced Audit Policy) | Enabled detailed auditing for successful/failed logons, privileged use, and object access on the Domain Controller. | Ensures full visibility into administrative actions and lateral movement. |

3. Security Tool Deployment (PROJECTX-SEC, PROJECTX-NETMON)

The core defensive tools were deployed on their dedicated server VMs to ensure comprehensive coverage.

| Tool / Component | VM Host | Configuration Detail | Goal |
| ----- | ----- | ----- | ----- |
| **Wazuh Manager** | PROJECTX-SEC (10.0.0.10) | Installed Manager and Elasticsearch stack. Configured default FIM and rootkit detection modules. | Centralized log ingestion, correlation, and initial alert generation. |
| **Wazuh Agents** | PROJECTX-AD, PROJECTX-W11, PROJECTX-LINUX | Agents deployed and successfully connected to the Manager. | Endpoint detection and response (EDR) capability, including real-time log forwarding. |
| **Security Onion** | PROJECTX-NETMON (10.0.0.103) | Configured the network interface to monitor all traffic on the Corporate LAN segment. | Network Intrusion Detection System (NIDS) using Suricata and deep packet inspection. |
| **Email Sandbox** | PROJECTX-AD (via MailHog container) | Configured an internal, non-internet-facing SMTP server (MailHog) for safe phishing simulation. | Provides a safe environment to test email-based attacks without compromising external systems. |

4. Linux Hardening (PROJECTX-LINUX, PROJECTX-SEC, PROJECTX-NETMON)

Basic hardening was applied to all Ubuntu-based systems to ensure a secure baseline before deploying services.

Firewall: Configured UFW (Uncomplicated Firewall) to deny all inbound connections by default, only allowing SSH access from authorized administrative IPs.

SSH: Disabled root login and enforced key-based authentication (where applicable) to prevent password brute-forcing.

Updates: Ensured all systems were updated (apt update && apt upgrade) immediately after provisioning to address known vulnerabilities.

5. Ongoing Monitoring and Maintenance

This foundational configuration requires continuous effort. Key Blue Team maintenance tasks include:

Regularly reviewing the health of all Wazuh agents and ensuring they are active.

Tuning Wazuh rules to reduce false positives and enhance detection fidelity.

Reviewing Windows Event Logs and Security Onion alerts daily for anomalous activity.
