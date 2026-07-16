# Help Desk & Desktop Support Troubleshooting Playbook
**Scope:** Windows 10/11 Enterprise Workstations & Local Network Infrastructure

---

## 📌 1. Objective
This playbook documents standard troubleshooting workflows and resolution steps for common desktop support issues simulated and resolved within the Project-X enterprise environment.

---

## 🛠️ 2. Scenario A: Windows "Blue Screen of Death" (BSOD) Recovery
**Symptom:** A user's domain-joined Windows 10 workstation is experiencing intermittent BSOD crashes (Stop Code: `DRIVER_IRQL_NOT_LESS_OR_EQUAL`).

### 🔍 Diagnostic & Resolution Steps:
1.  **Boot into Safe Mode:** Restarted the workstation and booted into Safe Mode with Networking to isolate third-party software interference.
2.  **Analyze Event Viewer:** Checked the **Windows Event Viewer** under `System` logs to locate the exact driver or process causing the crash (identified as a corrupted network adapter driver).
3.  **Driver Rollback/Reinstall:** Uninstalled the corrupted driver via Device Manager, rebooted, and installed the manufacturer’s stable, verified driver version.
4.  **System File Verification:** Ran `sfc /scannow` and `DISM /Online /Cleanup-Image /RestoreHealth` via elevated Command Prompt to repair compromised system files.
5.  **Validation:** Workstation monitored for 48 hours with zero crash recurrence.

---

## 🌐 3. Scenario B: Local Network & DNS Connectivity Drops
**Symptom:** A user in the Finance department reports they cannot access local network shared drives or load external websites.

### 🔍 Diagnostic & Resolution Steps:
1.  **Physical/Layer 1 Check:** Verified the ethernet interface was active and link lights were showing on the virtual switch.
2.  **IP Configuration Audit:** Ran `ipconfig /all` via Command Prompt. Identified the workstation was holding a self-assigned APIPA address (`169.254.x.x`), indicating it could not reach the DHCP server.
3.  **DHCP Renewal:** Executed `ipconfig /release` followed by `ipconfig /renew`. 
4.  **DNS Verification:** Tested local name resolution by querying the Domain Controller DNS server using `nslookup corp.project-x-dc.com` to ensure Active Directory records were reachable.
5.  **Local Cache Flush:** Flushed DNS resolver cache using `ipconfig /flushdns` to clear outdated records.
6.  **Resolution:** Assigned valid lease from the DHCP scope, restored connection to the file server, and verified shared drive mapping.

---

## 🎫 4. Ticketing & SLA Workflow (osTicket Simulation)
To maintain organized operations, all incoming issues were logged, triaged, and closed using a simulated **osTicket** portal:

*   **Triage Rules:** Incoming requests were categorized by **Impact** (Single User vs. Department-wide) and **Urgency**.
*   **Documentation Standard:** All tickets were closed with a mandatory **Root Cause
