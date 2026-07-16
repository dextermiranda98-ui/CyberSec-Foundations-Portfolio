# Endpoint Security Telemetry & SIEM Monitoring (Wazuh)
**Scope:** Active Directory Domain Controller & Windows Enterprise Endpoints

---

## 📌 1. Objective
To configure, deploy, and utilize Wazuh SIEM/XDR agents to gain real-time visibility into endpoint system events, monitor local user authentication, and detect unauthorized changes on domain workstations.

---

## 🛠️ 2. Deployment & Agent Configuration
To establish centralized monitoring across the Project-X domain, the following architecture was implemented:

1.  **Manager Setup:** Maintained a centralized Wazuh manager instance acting as the syslog and telemetry aggregator.
2.  **Agent Installation:** Deployed the Wazuh MSI agent on the Windows Server Domain Controller (`corp.project-x-dc.com`) and Windows 10/11 endpoints.
3.  **Communication Security:** Enforced secure, encrypted communication between the endpoint agents and the manager using TLS authentication.

---

## 🔍 3. Key Monitored Security Events
With agents deployed, custom alerting rules and event filters were implemented to focus on typical Help Desk and Desktop security concerns:

### A. Local Administrator & Account Creation
*   **Wazuh Event ID / Rule:** Triggered alerts when changes were made to local privilege groups (e.g., adding a user to the local `Administrators` group on a laptop).
*   **Support Application:** Helps Desktop Support audit and ensure users are not bypassing corporate policy by installing unauthorized software or modifying system files.

### B. Brute-Force & Account Lockouts
*   **Wazuh Event ID / Rule:** Set up rule triggers for multiple consecutive failed login attempts followed by a successful login, or immediate account lockout alerts.
*   **Support Application:** Allows Desktop Support to proactively identify if an employee is locked out of their system before they even call the Help Desk, decreasing response times.

### C. File Integrity Monitoring (FIM)
*   **Wazuh Configuration:** Monitored sensitive system folders (such as `C:\Windows\System32`) for unauthorized file modifications or deletions.
