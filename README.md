# Windows CIS Compliance Audit + NIST CSF 2.0 Gap Analysis

An end-to-end GRC project for **Ridgeline Relay Communications**, a fictional Colorado telecom (prepaid wireless and satellite broadband, ~1,400 employees). It has three parts:

1. **Measure.** A PowerShell tool audits Windows against **17 CIS checks**, maps each one to **NIST CSF 2.0**, and exports pass/fail reports (CSV + HTML).
2. **Analyze.** A **NIST CSF 2.0 gap analysis** scores all 22 Categories (Current vs. Target), using the scan results as technical evidence.
3. **Fix.** Two policies close the top gaps: an **Incident Response Plan** aligned to NIST SP 800-61 Rev. 3, and an **Access Control Policy**. A 30/60/90-day action plan covers the rest.

## Results

| | Compliance score |
|---|---|
| Baseline (`reports/before.csv`) | ⏳ __% |
| After remediation (`reports/after.csv`) | ⏳ __% |

<!-- Add a screenshot of reports/before.html here:  ![Audit report](reports/screenshot.png) -->

## Quick start

The script is **read-only**: it reads settings and changes nothing.

```powershell
# Open Windows PowerShell with "Run as administrator", then:
cd path\to\windows-cis-audit
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Invoke-CisAudit.ps1 -OutputPath .\reports\before.csv
```

This produces `reports/before.csv`, `reports/before.html`, and a console summary with a compliance score. Without admin rights, the checks that need elevation show `ERROR` instead of PASS/FAIL.

## What the audit checks

| Area | Checks | NIST CSF 2.0 |
|---|---|---|
| Accounts | Password length and complexity, lockout threshold, Guest and built-in Administrator disabled, local admin count | PR.AA-01, PR.AA-03, PR.AA-05 |
| Network | Firewall on all profiles, SMBv1 off, LLMNR off, RDP off or NLA required | PR.IR-01, PR.PS-01, PR.AA-03 |
| System | Defender real-time protection, BitLocker, recent updates, UAC | DE.CM-09, PR.DS-01, PR.PS-02, PR.AA-05 |
| Logging | PowerShell script block logging, logon auditing, Security log size | PR.PS-04 |

Each result includes the expected value, the actual value, the CIS reference, and the remediation step.

## Repository layout

```
scripts/Invoke-CisAudit.ps1            the audit tool
reports/                               scan output (before/after)
docs/01-company-profile.md             the fictional company, its environment and current state
docs/02-nist-csf-gap-analysis.md       Current vs. Target profile, top gaps, action plan
policies/incident-response-plan.md     IR plan with notification timelines, ransomware playbook, tabletop exercise
policies/access-control-policy.md      least privilege, MFA, privileged access, access reviews
```

## Design notes

- **Mapped to frameworks.** Every technical check traces to a CIS recommendation and a CSF 2.0 subcategory, so a failed check becomes evidence for a specific gap.
- **Fault-tolerant.** A check that can't run (no admin rights, or a feature missing on Windows Home) reports `ERROR` instead of crashing the scan, and errors aren't counted in the score.
- **Language-independent where possible.** Built-in accounts and groups are found by well-known SIDs (`-500`, `-501`, `S-1-5-32-544`), and audit policy by GUID, so renamed accounts are still caught.
- **Industry-specific.** The IR plan covers telecom obligations (FCC CPNI breach reporting) and Colorado's 30-day breach notification law. The tabletop exercise follows a ransomware pattern seen against telecom and media companies.

---
*Ridgeline Relay Communications is fictional. Technical results come from a personal lab machine. Regulatory timelines are summarized for learning purposes and are not legal advice.*
