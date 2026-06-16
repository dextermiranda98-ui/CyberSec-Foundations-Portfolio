# ProjectX Identity Lifecycle Management SOP

## Purpose
This document establishes the standard workflow for onboarding and offboarding personnel within the ProjectX corporate domain environment to ensure role-based access control (RBAC).

## 1. Onboarding Workflow
1. Access the Windows Server 2022 Active Directory Administrative Center (ADAC).
2. Navigate to the appropriate **Organizational Unit (OU)** (e.g., `ProjectX/Departments/Operations`).
3. Select **New User** and fill out the standardized naming convention: `FirstInitialLastName` (e.g., dmiranda).
4. Assign the user to the corresponding security groups to grant baseline share permissions.

## 2. Security Configuration Baseline
* **Password Complexity:** Minimum 12 characters, requiring uppercase, lowercase, numbers, and symbols (Enforced via Default Domain Policy GPO).
* **Account Lockout:** Account locks out for 30 minutes after 5 consecutive failed authentication attempts to mitigate brute-force vectors.
