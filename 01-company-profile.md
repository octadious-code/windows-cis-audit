# Company Profile: Ridgeline Relay Communications (fictional)

> **Ridgeline Relay Communications is a fictional company** made up for this portfolio project. Any resemblance to a real business is coincidental. The technical evidence comes from a real lab endpoint, scanned with `scripts/Invoke-CisAudit.ps1`.

## Business overview

| | |
|---|---|
| **Industry** | Telecommunications: prepaid wireless and satellite broadband |
| **Headquarters** | Denver, Colorado |
| **Employees** | ~1,400 (HQ, two call centers, one network operations center) |
| **Customers** | ~600,000 subscribers, mostly in the Mountain West |
| **Services** | Prepaid mobile plans (an MVNO running on a national carrier's network), satellite internet for rural homes, connectivity for small businesses |

## What we're protecting ("crown jewels")

1. **Subscriber data:** names, addresses, account PINs and call/usage records. Usage records count as *Customer Proprietary Network Information* (CPNI), which the FCC regulates.
2. **Billing and payments:** the billing platform runs in AWS. Card payments are tokenized by a third-party processor.
3. **Network operations:** the NOC tools that provision SIMs and satellite terminals and monitor service.
4. **Identity infrastructure:** on-prem Active Directory, synced to Microsoft Entra ID. If AD is compromised, everything is.

## Technology environment

- **Endpoints:** ~1,600 Windows 11 laptops and desktops
- **Servers:** ~120 Windows Server VMs on a VMware ESXi cluster in the HQ data center
- **Cloud:** Microsoft 365, AWS for billing and the customer portal
- **Backups:** nightly backups to an on-prem NAS that is **joined to the Active Directory domain**
- **Remote access:** VPN for employees; third-party contractors reach the customer portal admin console over the VPN

## Security organization

- CISO (reports to the CIO), 2 SOC analysts, 1 security engineer, 1 GRC analyst, 1 identity (IAM) admin
- A managed security service provider (MSSP) monitors firewall and VPN logs after hours

## Current state (assessment interviews, Q4)

These are the conditions the gap analysis starts from:

- **Policies:** the only written security policy is an Acceptable Use Policy from 2019.
- **Incident response:** no written plan. Incidents are handled ad hoc by IT. Roles, escalation paths and regulator notification steps aren't documented, and no tabletop exercise has ever been run.
- **Privileged access:** about 40% of employees have local admin rights on their laptops. IT admins use their everyday accounts for admin work. MFA is on for Microsoft 365, but not for the VPN or admin accounts.
- **Configuration:** there is no enforced secure baseline for Windows. Laptops ship with mostly default settings (see the scan results in the gap analysis).
- **Logging:** the SIEM ingests firewall and VPN logs only. Endpoint security logs stay on each device at default sizes, and PowerShell logging is off.
- **Asset inventory:** kept in spreadsheets. An estimated 10–15% of laptops aren't in the inventory.
- **Encryption:** BitLocker is on about 60% of laptops.
- **Backups:** the backup NAS is domain-joined, so an attacker with domain admin could encrypt it too. Restores have never been tested.
- **Third parties:** no security review of the network host carrier, the payment processor, the MSSP or portal contractors.
- **Training:** an annual awareness video, with no phishing simulations.

## Why this matters: the threat that drives priorities

Ransomware groups targeting telecom and media companies commonly follow this pattern:

1. Get in through a weaker entry point, such as a subsidiary, a contractor or a VPN account without MFA.
2. Take over Windows domain controllers.
3. Encrypt the VMware ESXi hosts **and the backups**.
4. Threaten to leak stolen data.

Ridgeline's flat admin rights, domain-joined backups and missing IR plan line up with every step of that chain. That's why the gap analysis puts identity, configuration, logging and incident response first.
