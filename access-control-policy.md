# Access Control Policy

**Organization:** Ridgeline Relay Communications (fictional)
**Policy owner:** CISO · **Operational owner:** IAM Administrator
**Version:** 1.0 · **Review:** annually
**Aligned to:** NIST CSF 2.0 (PR.AA), CIS Controls (5 and 6), CIS Microsoft Windows Benchmark, NIST SP 800-63B (passwords)
**Closes gaps:** PR.AA, GV.PO (see the [gap analysis](../docs/02-nist-csf-gap-analysis.md))

---

## 1. Purpose

Make sure only authorized people and systems can reach Ridgeline's systems and data, with the least access they need, and that this access is verified, reviewed and removed on time. Most of all, this policy aims to stop the common attack path from **one compromised account → admin rights → domain controllers**.

## 2. Scope

This policy covers all employees, contractors, vendors and service accounts with access to Ridgeline systems: Active Directory and Entra ID, Microsoft 365, AWS, VPN, endpoints, servers, network devices, and any system that stores subscriber data or CPNI.

## 3. Policy statements

### 3.1 Account management (PR.AA-01)
- Every user has a **unique, named account**. Shared accounts are not allowed. The only exception is a documented system need, approved by the CISO, with a named owner.
- Accounts are created only after a manager's approval through the HR or IT ticketing system.
- **Leavers:** accounts are disabled **on the last working day**, or **within 1 hour** of a termination for cause.
- **Movers:** access from the old role is removed within **5 business days** of a role change.
- Accounts with no logon for **45 days** are disabled automatically and reviewed.
- The built-in Windows **Guest** and **Administrator** accounts stay disabled (audit checks ACCT-02, ACCT-06).

### 3.2 Least privilege and role-based access (PR.AA-05)
- Access is granted through **roles (groups)** tied to job function, not to individuals directly.
- Users get only the access their role needs. Access to subscriber data and CPNI is limited to roles with a documented business need (e.g. customer care, billing, fraud).
- **Standard users do not have local administrator rights** on laptops or desktops. Exceptions need a business reason, CISO approval, and are reviewed every 90 days (audit checks ACCT-05, SYS-04).
- Separation of duties: the same person cannot both request and approve their own access, or both change and approve billing records.

### 3.3 Privileged access (PR.AA-05)
- Admins use a **separate admin account** (e.g. `adm-jdoe`) for admin work, and their normal account for email and browsing. Admin accounts are never used to read email or browse the web.
- Privileged access is split into tiers. **Tier 0** covers domain controllers, Entra ID global admins, ESXi and backup systems. Tier 0 accounts are used only from hardened admin workstations, never from everyday laptops.
- Local administrator passwords are unique per device and rotated automatically (**Windows LAPS**).
- Membership in Domain Admins and other Tier 0 groups is limited to the minimum (target: ≤ 3 named people) and is alerted on in the SIEM.

### 3.4 Authentication (PR.AA-03)
- **MFA is required** for: VPN and all remote access, Microsoft 365 and other cloud apps, all privileged accounts, and all vendor and contractor access. Phishing-resistant MFA (FIDO2 or Windows Hello for Business) is required for Tier 0 admins.
- **Passwords and passphrases:**
  - At least **14 characters** (ACCT-01). Long passphrases are encouraged.
  - Checked against a list of known-compromised passwords when set.
  - **No forced periodic changes.** Passwords are changed when compromise is suspected, following NIST SP 800-63B.
  - The Windows "complexity requirements" setting stays **enabled** to meet the CIS baseline (ACCT-04) until a compromised-password filter is deployed. *(NIST SP 800-63B discourages composition rules; this is a documented, temporary trade-off.)*
- **Account lockout:** after **5** failed attempts, for 15 minutes (ACCT-03).
- **Session lock:** screens lock after 15 minutes of inactivity.

### 3.5 Remote access (PR.AA-03, PR.IR-01)
- Remote access is only through the company VPN with MFA.
- **Remote Desktop (RDP) is never exposed to the internet.** Where RDP is needed, it goes through a jump host and requires Network Level Authentication (NET-04).
- Remote access sessions are logged and kept for at least 90 days.

### 3.6 Service accounts
- Use group Managed Service Accounts (gMSA) where possible. Otherwise store passwords in the approved password vault and rotate them at least yearly.
- Service accounts cannot log on interactively and are given only the permissions their service needs.
- Each service account has a named owner and is listed in the asset inventory.

### 3.7 Third-party and contractor access (GV.SC, PR.AA-05)
- Vendor access needs a Ridgeline sponsor, a signed agreement with security requirements, and MFA.
- Access is **time-limited** (90 days at most, renewable) and restricted to the systems in the agreement.
- Contractor accounts are reviewed **monthly**.

### 3.8 Access reviews (PR.AA-05, GV.OV)
| What | How often | Reviewer |
|---|---|---|
| Tier 0 and privileged accounts | Quarterly | CISO + system owner |
| Access to subscriber data / CPNI systems | Quarterly | Data owner |
| Contractor and vendor accounts | Monthly | Sponsor |
| All other user access | Every 6 months | Manager |

Access that a reviewer can't justify is removed within **5 business days**. Review results are kept for audit.

### 3.9 Logging and monitoring (PR.PS-04, DE.CM)
- All authentication events, privileged group changes and admin logons are logged and sent to the SIEM. That includes audited logons (LOG-02), PowerShell logging (LOG-01) and security log sizes (LOG-03).
- The SOC alerts on: brute-force attempts, logons from unusual locations, new members in privileged groups, and use of disabled or expired accounts.

## 4. Exceptions

Exceptions must be requested in writing, include the business reason and compensating controls, be approved by the CISO, and expire after **no more than 12 months**. The GRC analyst keeps an exceptions register.

## 5. Enforcement

Violations may lead to removal of access and disciplinary action, up to and including termination of employment or contract.

## 6. Control mapping

| Policy section | NIST CSF 2.0 | CIS reference | Verified by audit check |
|---|---|---|---|
| 3.1 Account management | PR.AA-01 | Controls 5.1, 5.3 | ACCT-02, ACCT-06 |
| 3.2 Least privilege | PR.AA-05 | Control 5.4 | ACCT-05, SYS-04 |
| 3.3 Privileged access | PR.AA-05 | Controls 5.4, 6.5 | ACCT-05 |
| 3.4 Authentication | PR.AA-01, PR.AA-03 | Benchmark §1.1, §1.2; Control 6.3–6.5 | ACCT-01, ACCT-03, ACCT-04 |
| 3.5 Remote access | PR.AA-03, PR.IR-01 | Control 6.4 | NET-04, NET-01 |
| 3.9 Logging | PR.PS-04, DE.CM | Control 8 | LOG-01, LOG-02, LOG-03 |
