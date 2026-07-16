# 🖥️ Enterprise Infrastructure, Support Operations & Threat Simulation Lab

Welcome to my Enterprise Support & Systems Security portfolio. This repository hosts the documentation, configurations, standard operating procedures (SOPs), and simulation reports developed within my simulated corporate environment: **`corp.project-x-dc.com`**.

This lab was engineered using **VMware Workstation** to mirror a real-world enterprise network, focusing on system administration, user lifecycle management, desktop support, endpoint telemetry, and active threat detection.

---

## 🗺️ Lab Topology & Environment Specs
*   **Domain Controller:** Windows Server 2022 (`corp.project-x-dc.com` | IP: `10.0.0.5`)
*   **Services Hosted:** Active Directory Domain Services (AD DS), DNS, DHCP, Group Policy (GPMC)
*   **Endpoints:** Windows 10/11 Enterprise & Ubuntu Linux Client Workstations
*   **Ticketing & Queue System:** osTicket (Simulated Help Desk Portal)
*   **Telemetry & SIEM:** Wazuh Manager & Endpoint Security Agents
*   **Attack Platform:** Kali Linux (External threat simulation host)

---

## 📁 Repository Navigation & Documentation
I have structured this repository to reflect standard corporate IT and security operations. Click the links below to view the detailed work, scripts, and simulation reports:

### 👤 [1. Active Directory & Identity Management (IAM)](./1_Active_Directory_IAM/User-Provisioning-SOP.md)
*   **What's Inside:** Active Directory OU architecture, role-based access control (RBAC), and standard operating procedures (SOPs) for secure user onboarding/offboarding.
*   **GPOs Implemented:** Account lockout policies, password complexity requirements, and software restriction policies to block malicious execution.
*   **Configurations:** View our custom [GPO Hardening Scripts & Baselines](./Configuration-Scripts/).

### 🛠️ [2. Desktop Support & Troubleshooting Playbook](./2_Endpoint_Troubleshooting/Desktop-Support-Playbook.md)
*   **What's Inside:** Step-by-step technical resolution steps for common enterprise support scenarios.
*   **Scenarios Covered:** Diagnosing and recovering from Windows BSODs, resolving local network/DNS drops (APIPA recovery), and managing support tickets using an **osTicket** SLA structure.

### 🛡️ [3. Endpoint Security & Telemetry (Wazuh SIEM)](./3_Security_Telemetry/Endpoint-Monitoring-Wazuh.md)
*   **What's Inside:** Deployment and configuration of Wazuh SIEM monitoring agents across the domain controller and endpoints.
*   **Configurations:** Check out the [Custom Wazuh Rules & Configurations](./Configuration-Scripts/) utilized to alert on credential attacks and privilege escalations.

### 🎯 [4. Incident Response & Threat Simulation (Red vs. Blue)](./Documentation/)
*   **What's Inside:** Comprehensive cyber attack simulation reports analyzing system exploits, credential access, and host defense mitigation.
*   **Artifacts Used:** View the educational [Python Attack Scripts & Templates](./Attack-Artifacts/) used during the simulations.
*   **Visual Proof:** Step-by-step verification and logs via our [Evidence Screenshots](./Evidence-Screenshots/) gallery (featuring Wazuh alerts and Domain Controller telemetry).

---

## ⚙️ Core Competencies Demonstrated
*   **Systems Administration:** Windows Server 2022, Active Directory administration, Group Policy management, and virtualization (VMware).
*   **Desktop Support:** Operating system troubleshooting (Windows/macOS/Linux), hardware diagnostic testing, and local network diagnostics (TCP/IP, DHCP, DNS).
*   **Security & Telemetry:** SIEM deployment (Wazuh), endpoint monitoring, log analysis, and incident triage.
*   **IT Operations:** Help Desk queue triage, SLA adherence, change management, and tech
