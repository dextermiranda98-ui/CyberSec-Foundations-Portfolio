# Standard Operating Procedure: Identity Lifecycle & Group Policy Hardening
**Target Environment:** corp.project-x-dc.com (Domain Controller: 10.0.0.5)

---

## 📌 1. Objective
To establish a secure, repeatable, and audited workflow for user provisioning, group membership assignment, and security baselining within the Project-X enterprise domain.

---

## 🏗️ 2. Active Directory Organizational Unit (OU) Architecture
To prevent administrative privilege creep and ensure clean GPO application, the following OU structure was established:

*   **Project-X-Enterprise/** (Root OU)
    *   `Users/` (Houses all standard employees and department groups)
    *   `Computers/` (Houses all domain-joined Windows 10/11 client machines)
    *   `Service-Accounts/` (Dedicated, non-interactive accounts for automated services)

---

## 🚀 3. User Onboarding Workflow (Step-by-Step)
When a new employee joins the Project-X workforce, the following provisioning checklist is executed:

1.  **Account Creation:** Create the user object in the `Users` OU matching the naming convention (`firstinitiallastname` e.g., `jdoe`).
2.  **Password Security:** Assign a temporary, complex 12-character password. Enforce **"User must change password at next logon"** to maintain absolute credential privacy.
3.  **Role-Based Access Control (RBAC):** Assign the user to their designated security department groups (e.g., `Finance-Dept`, `HR-Dept`) to grant access only to necessary network drives.
4.  **Logon Hours & Restrictions:** Configure standard business hours logon restrictions to minimize the active threat surface during non-business hours.

---

## 🔒 4. Group Policy Objects (GPOs) Enforced
The following GPOs were created, linked to the root OU, and enforced to protect domain-joined workstations:

| GPO Name | Setting Configured | Business / Security Reason |
| :--- | :--- | :--- |
| **GPO-Account-Lockout** | Lock account after 5 failed attempts for 30 minutes | Prevents automated password-spraying and brute-force attacks. |
| **GPO-Password-Complexity** | Minimum 12 characters, uppercase, numbers, and symbols | Ensures standard users cannot utilize easily guessable passwords. |
| **GPO-Software-Restriction** | Disallowed execution of `.exe` from User AppData fol
