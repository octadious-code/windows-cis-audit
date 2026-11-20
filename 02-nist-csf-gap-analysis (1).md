# NIST CSF 2.0 Gap Analysis: Ridgeline Relay Communications (fictional)

**Framework:** NIST Cybersecurity Framework 2.0. The method follows NIST SP 1301, *Quick-Start Guide for Creating and Using Organizational Profiles*.
**Scope:** corporate IT for Ridgeline Relay Communications (see [Company Profile](01-company-profile.md)): identity, endpoints, servers, backups, logging, and incident response. Network-core and satellite ground systems are out of scope.
**Evidence:** current-state interviews (described in the company profile), plus a technical scan of a lab endpoint that stands in for Ridgeline's standard Windows 11 laptop build. The scan used `scripts/Invoke-CisAudit.ps1`.

---

## 1. Scoring method

Each of the 22 CSF 2.0 Categories gets a **Current** and a **Target** score on this scale:

| Score | Meaning |
|---|---|
| 0 | Not implemented |
| 1 | Initial: ad hoc, depends on individuals, undocumented |
| 2 | Partial: some controls exist but are inconsistent or not enforced |
| 3 | Implemented: documented, enforced, and owned |
| 4 | Measured: monitored with metrics and improving |

**Target = 3 for all Categories.** For a company of Ridgeline's size and regulatory exposure, 3 is a realistic 12-month goal. Priority comes from the size of the gap and how directly the Category breaks the ransomware attack chain described in the company profile.

## 2. Results by Function

| Function | Current (avg) | Target | Gap |
|---|---|---|---|
| Govern (GV) | 1.2 | 3.0 | 1.8 |
| Identify (ID) | 1.0 | 3.0 | 2.0 |
| Protect (PR) | 1.4 | 3.0 | 1.6 |
| Detect (DE) | 1.0 | 3.0 | 2.0 |
| **Respond (RS)** | **0.5** | 3.0 | **2.5** |
| Recover (RC) | 1.0 | 3.0 | 2.0 |
| **Overall** | **1.0** | **3.0** | **2.0** |

**Bottom line:** Respond is the weakest Function. Ridgeline has no incident response plan and no documented regulator notification process, and it holds regulated subscriber data (CPNI). A ransomware attack today would be run on improvisation.

## 3. Current vs. Target Profile (all 22 Categories)

| ID | Category | Cur | Tgt | Gap | Priority | Current state / evidence |
|---|---|---|---|---|---|---|
| GV.OC | Organizational Context | 2 | 3 | 1 | Med | Mission understood; legal and regulatory duties (FCC CPNI rules, Colorado breach law) not documented |
| GV.RM | Risk Management Strategy | 1 | 3 | 2 | Med | No risk appetite statement or risk register |
| GV.RR | Roles, Responsibilities, and Authorities | 2 | 3 | 1 | Med | CISO role exists; incident roles and decision rights undefined |
| GV.PO | Policy | 1 | 3 | 2 | **High** | Only a 2019 Acceptable Use Policy. *This project adds IR and Access Control policies* |
| GV.OV | Oversight | 1 | 3 | 2 | Low | No security metrics reported to leadership |
| GV.SC | Cybersecurity Supply Chain Risk Management | 0 | 3 | 3 | **High** | No vendor security reviews; contractors have VPN access with no MFA |
| ID.AM | Asset Management | 1 | 3 | 2 | Med | Spreadsheet inventory; 10–15% of laptops unknown |
| ID.RA | Risk Assessment | 1 | 3 | 2 | Med | No recurring assessment; this is the first |
| ID.IM | Improvement | 1 | 3 | 2 | Low | No lessons-learned process after incidents |
| PR.AA | Identity Management, Authentication, and Access Control | 1 | 3 | 2 | **High** | ~40% of users have local admin; admins use everyday accounts; no MFA on VPN or admin accounts. Scan: ACCT-01 to ACCT-06, NET-04, SYS-04 |
| PR.AT | Awareness and Training | 1 | 3 | 2 | Med | Annual video only; no phishing simulation |
| PR.DS | Data Security | 2 | 3 | 1 | **High** | BitLocker on ~60% of laptops; card data tokenized; backups untested and reachable from the domain. Scan: SYS-02 |
| PR.PS | Platform Security | 1 | 3 | 2 | **High** | No enforced Windows baseline; endpoint logging at defaults. Scan: NET-02, SYS-01, SYS-03, LOG-01 to LOG-03 |
| PR.IR | Technology Infrastructure Resilience | 2 | 3 | 1 | Med | Perimeter firewalls in place; host firewall and name-resolution hardening inconsistent. Scan: NET-01, NET-03 |
| DE.CM | Continuous Monitoring | 1 | 3 | 2 | **High** | SIEM sees firewall and VPN only; no endpoint telemetry. Scan: SYS-01 |
| DE.AE | Adverse Event Analysis | 1 | 3 | 2 | Med | No correlation rules or triage runbooks |
| RS.MA | Incident Management | 0 | 3 | 3 | **High** | No IR plan, roles or severity levels. *Closed by the IR Plan* |
| RS.AN | Incident Analysis | 1 | 3 | 2 | Med | No evidence-handling procedure. *Addressed by the IR Plan* |
| RS.CO | Incident Response Reporting and Communication | 0 | 3 | 3 | **High** | FCC, law enforcement and state notification steps undocumented. *Closed by the IR Plan* |
| RS.MI | Incident Mitigation | 1 | 3 | 2 | Med | Containment is ad hoc. *Addressed by the IR Plan's ransomware playbook* |
| RC.RP | Incident Recovery Plan Execution | 1 | 3 | 2 | **High** | Restores never tested; backup NAS is domain-joined |
| RC.CO | Incident Recovery Communication | 1 | 3 | 2 | Med | No customer or status communication templates. *Addressed by the IR Plan* |

## 4. Technical evidence: Windows baseline scan

The lab endpoint was scanned against 17 checks drawn from the CIS Microsoft Windows Benchmark and CIS Controls. Each check maps to a CSF 2.0 subcategory. It was scanned once at baseline and again after remediation. The full output is in `reports/before.*` and `reports/after.*`.

**Compliance score: 59% (10 of 17) at baseline → 88% (15 of 17) after remediation. Zero checks errored.**

| Check | What it verifies | CSF 2.0 | Before | After |
|---|---|---|---|---|
| ACCT-01 | Minimum password length ≥ 14 | PR.AA-01 | ❌ FAIL (0) | ✅ PASS (14) |
| ACCT-02 | Guest account disabled | PR.AA-05 | ✅ PASS | ✅ PASS |
| ACCT-03 | Account lockout after 1–5 failed attempts | PR.AA-03 | ❌ FAIL (10) | ✅ PASS (5) |
| ACCT-04 | Password complexity enabled | PR.AA-01 | ❌ FAIL | ❌ FAIL *(exception, see below)* |
| ACCT-05 | ≤ 2 members in local Administrators | PR.AA-05 | ❌ FAIL (3) | ❌ FAIL *(open finding, see below)* |
| ACCT-06 | Built-in Administrator disabled | PR.AA-05 | ✅ PASS | ✅ PASS |
| NET-01 | Firewall on for all profiles | PR.IR-01 | ✅ PASS | ✅ PASS |
| NET-02 | SMBv1 disabled | PR.PS-01 | ✅ PASS | ✅ PASS |
| NET-03 | LLMNR disabled | PR.IR-01 | ❌ FAIL (not configured) | ✅ PASS |
| NET-04 | RDP off, or requires NLA | PR.AA-03 | ✅ PASS (RDP off) | ✅ PASS |
| SYS-01 | Defender real-time protection on | DE.CM-09 | ✅ PASS | ✅ PASS |
| SYS-02 | BitLocker on system drive | PR.DS-01 | ✅ PASS | ✅ PASS |
| SYS-03 | Update installed in last 30 days | PR.PS-02 | ✅ PASS (27 days) | ✅ PASS |
| SYS-04 | UAC Admin Approval Mode on | PR.AA-05 | ✅ PASS | ✅ PASS |
| LOG-01 | PowerShell script block logging on | PR.PS-04 | ❌ FAIL (not configured) | ✅ PASS |
| LOG-02 | Logon success and failure audited | PR.PS-04 | ✅ PASS | ✅ PASS |
| LOG-03 | Security log ≥ 196,608 KB | PR.PS-04 | ❌ FAIL (20,480 KB) | ✅ PASS (196,608 KB) |

**Key observations**

1. **Windows defaults handled the "big" controls.** Firewall, Defender, BitLocker, UAC, SMBv1 removal and disabled RDP all passed at baseline. Modern Windows 11 is reasonably secure out of the box.
2. **Every baseline failure fell in two areas that defaults leave open: account policy (PR.AA) and logging (PR.PS-04).** This confirms the interview findings and the "High" priorities in Section 3.
   - **Account policy.** A minimum password length of 0 and a lockout threshold of 10 make password guessing much easier. That's the first step in the ransomware chain described in the company profile.
   - **Logging.** A 20 MB Security log can roll over within hours on a busy machine, erasing evidence. PowerShell logging was off, even though PowerShell is a favorite tool of ransomware operators. During an incident, responders would be blind (this ties to the IR Plan, §6.1).
   - **LLMNR on.** This lets an attacker on the local network trick Windows into handing over password hashes (LLMNR poisoning).
3. **All 5 remediated settings are cheap, low-risk Group Policy changes.** Pushing them fleet-wide is action plan item #5.

**Remediation log (lab endpoint)**

| Check | Change made |
|---|---|
| ACCT-01 | `net accounts /minpwlen:14` |
| ACCT-03 | `net accounts /lockoutthreshold:5` |
| LOG-03 | `wevtutil sl Security /ms:201326592` (196,608 KB) |
| LOG-01 | Registry policy `EnableScriptBlockLogging = 1` |
| NET-03 | Registry policy `EnableMulticast = 0` |

**Open findings (accepted for now)**

- **ACCT-04, password complexity: documented exception.** NIST SP 800-63B advises against composition rules and favors length plus checks against known-compromised passwords. The 14-character minimum is now enforced as a compensating control. Complexity stays a documented exception (see Access Control Policy §3.4) until a compromised-password filter is in place.
- **ACCT-05, 3 local administrators: open finding.** The group holds the disabled built-in Administrator plus two user accounts. Removing admin rights from an account that's actively used needs planning so nobody gets locked out. The target state is one named admin account plus a standard everyday account (Access Control Policy §3.2–3.3; action plan item #6).

## 5. Top 5 priority gaps

1. **No incident response capability (RS.MA, RS.CO, RC.CO).** Ridgeline must notify federal agencies within 7 business days of determining a CPNI breach, and Colorado residents within 30 days of determining a breach. Neither process is written down.
   → **Closed by:** [Incident Response Plan](../policies/incident-response-plan.md)
2. **Excessive privilege and weak admin authentication (PR.AA).** Widespread local admin rights and admins working from everyday accounts give an attacker a short path to domain controllers.
   → **Closed by:** [Access Control Policy](../policies/access-control-policy.md)
3. **No enforced secure configuration baseline (PR.PS-01).** Laptops run near-default settings.
   → **Addressed by:** the CIS audit script (measures it), plus a CIS-based Group Policy baseline (action plan, below).
4. **Endpoint activity is invisible (PR.PS-04, DE.CM).** Without endpoint logs in the SIEM, the early steps of an intrusion (failed logons, PowerShell abuse) can't be detected.
5. **Backups can be destroyed with the rest of the environment (PR.DS-11, RC.RP).** A domain-joined, untested backup is not a recovery plan.

## 6. Action plan (30 / 60 / 90 days)

| # | Action | CSF 2.0 | Owner | Due | Done when |
|---|---|---|---|---|---|
| 1 | Approve and publish the IR Plan; run the first tabletop exercise | RS.MA, RS.CO, GV.PO | CISO | 30 days | Plan approved; tabletop held; lessons-learned report filed |
| 2 | Approve and publish the Access Control Policy | PR.AA, GV.PO | CISO / IAM admin | 30 days | Policy approved and acknowledged by IT staff |
| 3 | Enforce MFA on VPN and all admin accounts | PR.AA-03 | IAM admin | 30 days | 100% of VPN and admin logons use MFA |
| 4 | Take backups off the domain, make one copy immutable or offline, and test a restore | PR.DS-11, RC.RP | IT Ops | 60 days | Successful restore test documented |
| 5 | Deploy a CIS-based Windows Group Policy baseline; re-run the audit script | PR.PS-01 | Security engineer | 60 days | Baseline score ≥ 90% across a sample of laptops |
| 6 | Remove local admin rights; deploy Windows LAPS for local admin passwords | PR.AA-05 | IT Ops | 60 days | ≤ 2% of users with local admin (approved exceptions only) |
| 7 | Forward endpoint security and PowerShell logs to the SIEM; build alerts for brute force and suspicious PowerShell | PR.PS-04, DE.CM | SOC | 90 days | Alerts tested with simulated events |
| 8 | Security review of the top 5 vendors (host carrier, payment processor, MSSP, portal contractors) | GV.SC | GRC analyst | 90 days | Reviews completed; contract security clauses updated |
| 9 | Replace the asset spreadsheet with automated inventory | ID.AM | IT Ops | 90 days | ≥ 98% of laptops inventoried |

**12-month goal:** overall Current score from **1.0 → 2.5+**, with Respond and Protect at 3.

---
*Regulatory timelines are summarized for a portfolio exercise and are not legal advice. A real program would confirm them with legal counsel.*
