# Incident Response Plan

**Organization:** Ridgeline Relay Communications (fictional)
**Policy owner:** Chief Information Security Officer (CISO)
**Version:** 1.0 · **Review:** at least once a year, and after every SEV-1 or SEV-2 incident
**Aligned to:** NIST SP 800-61 Rev. 3 (*Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*) and NIST CSF 2.0
**Closes gaps:** RS.MA, RS.AN, RS.CO, RS.MI, RC.CO, GV.RR (see the [gap analysis](../docs/02-nist-csf-gap-analysis.md))

---

## 1. Purpose

This plan defines how Ridgeline detects, responds to and recovers from cybersecurity incidents. The goals are to limit harm to customers and the business, meet legal notification deadlines, and learn from every incident. Following NIST SP 800-61 Rev. 3, incident response is treated as part of risk management across all six CSF Functions, not just an IT task.

## 2. Scope

The plan covers all Ridgeline systems, data, employees, contractors and vendors with access to Ridgeline systems. That includes corporate IT, cloud services (Microsoft 365, AWS), the customer portal, and systems that store subscriber data or CPNI.

## 3. Definitions

| Term | Meaning |
|---|---|
| **Event** | Any observable occurrence, such as an alert, a failed logon or a user report |
| **Incident** | An event that actually or likely jeopardizes the confidentiality, integrity or availability of systems or data, or violates security policy |
| **Breach** | An incident where personal information or CPNI was, or is reasonably believed to have been, accessed or taken without authorization |
| **CPNI** | Customer Proprietary Network Information: data about a customer's use of telecom services (call records, plan details) protected under FCC rules |

## 4. Roles and responsibilities

| Role | Who | Responsibilities |
|---|---|---|
| **Incident Commander (IC)** | CISO (backup: Security Engineer) | Declares incidents and sets severity; makes containment decisions; owns the timeline and final report |
| **SOC Lead** | Senior SOC Analyst | Triage, investigation, evidence collection, coordination with the MSSP |
| **IT Operations Lead** | IT Infrastructure Manager | Carries out containment and recovery (isolation, resets, restores) |
| **Identity Lead** | IAM Administrator | Disables accounts, resets credentials, revokes sessions and tokens |
| **Legal & Privacy** | General Counsel | Decides whether a breach occurred; runs regulator, law enforcement and customer notifications |
| **Communications** | VP Communications | Internal updates, customer messaging, media statements (all reviewed by Legal) |
| **Executive Sponsor** | CIO | Approves business-impacting decisions (e.g. taking services offline); briefs the CEO and board |
| **External support** | MSSP; IR retainer firm; cyber insurer | After-hours monitoring; forensic surge support; claim and approved-vendor requirements |

Contact details are kept in **Appendix B**, with a printed copy stored offline. During a ransomware event, email and chat may be down.

## 5. Severity levels

| Severity | Definition | Examples | IC engaged within | Exec update |
|---|---|---|---|---|
| **SEV-1 Critical** | Widespread outage, confirmed breach of subscriber data or CPNI, or active ransomware | Domain controllers compromised; data exfiltration confirmed | 15 min | Every 2 hrs |
| **SEV-2 High** | Confirmed compromise contained to a few systems or accounts | Admin account takeover; malware on a server | 1 hr | Every 4 hrs |
| **SEV-3 Medium** | Suspicious activity, no confirmed compromise | Brute-force attempts; malware blocked on one laptop | 4 hrs | Daily summary |
| **SEV-4 Low** | Minor policy violation or nuisance event | Phishing email reported and deleted | Next business day | Monthly metrics |

Severity can go up or down as facts emerge. **When in doubt, rate it higher.**

## 6. Response lifecycle

### 6.1 Prepare (GV, ID, PR)
- Keep this plan, the contact list and the playbooks current. Store copies offline.
- Make sure the logs needed for investigation are being collected and kept for at least 90 days: endpoint security logs, PowerShell logs, VPN, Entra ID and firewall. The CIS audit script verifies the endpoint logging settings.
- Keep tested, offline or immutable backups of critical systems (Active Directory, billing, the customer portal).
- Keep an IR retainer and cyber insurance in place, and know the insurer's notification requirements.
- Run a tabletop exercise at least **twice a year** (see Appendix A).

### 6.2 Detect and analyze (DE.CM, DE.AE, RS.AN)
1. Events come in from SIEM alerts, the MSSP, endpoint protection, the help desk or employee reports (security@ridgeline.example).
2. The SOC analyst triages: is it real? What's affected? Is it still happening?
3. If it's an incident, open an incident ticket, notify the IC, and set the initial severity.
4. **Preserve evidence before changing anything:** memory and disk images of key systems, relevant logs, screenshots, ransom notes. Record who collected what, when and how (chain of custody).
5. Determine scope: which accounts, hosts and data are involved. Note when the attacker first got in, and how.

### 6.3 Contain (RS.MI)
- **Short term:** isolate affected hosts (EDR network isolation or unplugging); disable compromised accounts; block attacker IPs and domains; cut VPN or contractor access if it was the entry point.
- **Credentials:** if domain admin compromise is suspected, plan a coordinated reset of privileged accounts and the KRBTGT account (twice, with replication time in between).
- **Business decisions:** the IC recommends and the Executive Sponsor approves any action that takes customer-facing services offline.

### 6.4 Eradicate and recover (RS.MI, RC.RP)
1. Remove malware, attacker accounts, persistence mechanisms and unauthorized remote tools.
2. Rebuild compromised systems from known-good images rather than "cleaning" them where possible.
3. Restore data from backups, after confirming the backups are clean and dated before the compromise.
4. Restore in priority order: **identity (AD/Entra) → core infrastructure → billing and customer portal → everything else.**
5. Watch restored systems closely for at least 30 days.

### 6.5 Communicate and notify (RS.CO, RC.CO)
Legal & Privacy decides whether notification is required. **The clocks below start at "reasonable determination" of a breach, so start documenting from hour one.**

| Who | When | Trigger |
|---|---|---|
| FBI, U.S. Secret Service, and FCC (through the FCC's central reporting facility) | As soon as practicable, **no later than 7 business days** after reasonable determination of a breach | Breach of CPNI (FCC rule, 47 CFR § 64.2011) |
| Affected customers (CPNI) | As required by the current FCC rule, timed and coordinated with law enforcement | Breach of CPNI |
| Affected Colorado residents | As quickly as possible, **no later than 30 days** after determining a breach occurred | Breach of personal information (C.R.S. § 6-1-716) |
| Colorado Attorney General | **No later than 30 days** | 500 or more Colorado residents affected |
| Credit reporting agencies | Per state law | More than 1,000 Colorado residents notified |
| Other states' residents and regulators | Per each state's law | Residents of other states affected |
| Cyber insurer | Per policy terms (usually "immediately" or within days) | Any SEV-1 or SEV-2 |
| Payment processor | Per contract | Any suspected exposure of payment systems |

- All outside communications go through Legal and Communications. **Employees must not discuss an incident publicly or with customers** unless authorized.
- Use out-of-band channels (phone bridge, personal devices) if corporate email or chat may be compromised.
- Do not contact or negotiate with the attacker without Legal, the Executive Sponsor and outside counsel involved.

### 6.6 Learn and improve (ID.IM)
- Hold a blameless lessons-learned review within **10 business days** of closing any SEV-1 or SEV-2 incident.
- Record the root cause, what went well, what didn't, and action items with owners and due dates.
- Update this plan, the playbooks and the gap analysis.
- Track metrics: time to detect, time to contain, time to recover, number of incidents by severity.

## 7. Ransomware playbook (quick reference)

| Step | Action | Owner |
|---|---|---|
| 1 | Declare SEV-1, start the incident log, open the phone bridge | IC |
| 2 | Isolate infected hosts. **Do not power them off** (memory holds evidence) | IT Ops |
| 3 | Disable the suspected entry account(s); force MFA re-registration for admins | Identity Lead |
| 4 | Take backups offline right away to protect them; confirm whether the backup system was touched | IT Ops |
| 5 | Check for data theft (large outbound transfers, archive tools such as 7-Zip or rclone) | SOC Lead |
| 6 | Engage the IR retainer and notify the cyber insurer | IC |
| 7 | Brief Legal: is subscriber data or CPNI involved? Start the notification clocks | Legal |
| 8 | Rebuild identity first (domain controllers), then ESXi hosts, then apps | IT Ops |
| 9 | Restore from clean backups; reset all privileged credentials, including KRBTGT (twice) | IT Ops / Identity |
| 10 | Monitor closely; hold the lessons-learned review | SOC / IC |

## 8. Documentation

Every incident ticket records: a timeline of events and actions (UTC), systems and accounts affected, evidence collected (with chain of custody), decisions and who made them, notifications sent (to whom, when, what), and the final root cause. Records are kept for at least 3 years.

## 9. Testing and maintenance

- Tabletop exercises twice a year, rotating scenarios (ransomware, account takeover, insider data theft, third-party breach).
- One technical exercise a year (e.g. restore AD from backup in an isolated lab).
- Plan reviewed annually, and after any SEV-1 or SEV-2, any major organizational change, or any change in regulations.

---

## Appendix A: Tabletop exercise, "Contractor to Core"

*The scenario follows a common real-world ransomware pattern against telecom and media companies.*

| Time | Inject | Discussion questions |
|---|---|---|
| Fri 4:40 PM | The help desk gets 3 tickets: "files won't open," "VPN is slow." | Who triages on a Friday evening? When does this become an incident? |
| Fri 6:15 PM | The MSSP reports VPN logons from an overseas IP using a portal contractor's account. That account has no MFA. | What do we disable first? Who has authority to cut contractor VPN access? |
| Fri 9:30 PM | Endpoint alerts show PowerShell running on two domain controllers. | What severity is this now? Who gets woken up? What evidence do we grab? |
| Sat 2:00 AM | ESXi datastores are encrypted and the billing VMs are down. A ransom note threatens to leak "subscriber records." | Are the backups safe? (The NAS is domain-joined.) What do we tell customers about service status? |
| Sat 10:00 AM | A leak-site post shows sample data that includes call records. | Is this a CPNI breach? When did the 7-business-day clock start? Who files with the FCC/FBI/USSS? Colorado AG? |
| Mon 8:00 AM | A reporter calls asking about an outage "caused by hackers." | Who speaks? What can we say? |

**After the exercise, document:** gaps found, decisions that were unclear, and action items. Each one feeds back into the gap analysis (ID.IM).

## Appendix B: Contact list template

| Role | Name | Mobile | Backup | Backup mobile |
|---|---|---|---|---|
| Incident Commander | | | | |
| SOC Lead | | | | |
| IT Operations Lead | | | | |
| Identity Lead | | | | |
| Legal & Privacy | | | | |
| Communications | | | | |
| Executive Sponsor | | | | |
| MSSP 24/7 line | | | | |
| IR retainer hotline | | | | |
| Cyber insurer claims | | | | |

## Appendix C: Incident log template

| Time (UTC) | Who | Action / observation | Evidence ref |
|---|---|---|---|
| | | | |

---
*Regulatory timelines are summarized for a portfolio exercise and are not legal advice. A real plan would be confirmed by legal counsel, and requirements can change.*
