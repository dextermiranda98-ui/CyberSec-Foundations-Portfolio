ProjectX Enterprise Network Topology and Configuration

1. Overview

This document provides the blueprint for the virtual network infrastructure used in the ProjectX E101 lab. The topology is designed to emulate a standard small business environment, featuring segregated segments for corporate user access and administrative/security functions.

2. Network Diagram (Conceptual)
(Note: Replace the line above with your actual network diagram image, e.g., created with tools like draw.io or Visio.)

3. Network Segmentation

The lab utilizes a single internal network configured as a VirtualBox NAT Network. This isolates the ProjectX environment from the host machine's physical network while allowing all internal VMs outbound internet access (essential for updates and tool downloads).

| Network Segment | Subnet (Example) | VM Roles Included | Purpose | 
| ----- | ----- | ----- | ----- | 
| **Corporate LAN** | 192.168.10.0/24 | PROJECTX-AD, PROJECTX-W11, PROJECTX-LINUX, PROJECTX-SEC | Primary internal network for client-server communication. | 
| **Security/Monitoring** | 192.168.10.0/24 | PROJECTX-NETMON (Security Onion), PROJECTX-SEC (Wazuh) | Hosts the core security infrastructure. | 
| **Offensive Access** | (Isolated) | ATTACKER-VM (Kali Linux) | Used to launch attacks and establish C2 communication into the Corporate LAN. | 

4. Virtual Machine IP and Role Mapping

| VM Name | Operating System | Assigned IP (Static) | Primary Role |
| ----- | ----- | ----- | ----- |
| PROJECTX-AD | Windows Server 2025 | 10.0.0.5 | Domain Controller, DNS Server |
| PROJECTX-W11 | Windows 11 Enterprise | 10.0.0.100 | Standard User Workstation |
| PROJECTX-LINUX | Ubuntu Desktop 22.04 | 10.0.0.101 | Standard User Workstation |
| PROJECTX-SEC | Ubuntu Server 22.04 | 10.0.0.10 | Wazuh Manager/Server |
| PROJECTX-NETMON | Security Onion | 10.0.0.103  | Network IDS, Log Aggregation |
| ATTACKER-VM | Kali Linux | dynamic | Red Team Attack Host |

5. Key Configuration Details
Active Directory: Configured the projectx.local domain. All workstations and servers (except Kali) are domain-joined.

DNS: All internal hosts point to PROJECTX-AD (192.168.10.10) for primary DNS resolution.

Log Management: Wazuh agents are deployed on PROJECTX-AD, PROJECTX-W11, and PROJECTX-LINUX and report to the Wazuh Manager on PROJECTX-SEC.

Security Onion: Configured to monitor network traffic flowing through the Corporate LAN, capturing logs via its network interface.
