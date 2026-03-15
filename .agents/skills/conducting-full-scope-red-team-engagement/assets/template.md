# Red Team Engagement Report Template

## Document Control

| Field | Value |
|---|---|
| Engagement ID | RT-2025-XXX |
| Client Name | [Organization Name] |
| Report Date | YYYY-MM-DD |
| Classification | CONFIDENTIAL |
| Report Version | 1.0 |
| Lead Operator | [Name] |
| Reviewed By | [Name] |

---

## 1. Executive Summary

### 1.1 Engagement Overview

[Organization Name] engaged [Red Team Company] to conduct a full-scope red team assessment from [start date] to [end date]. The engagement simulated the tactics, techniques, and procedures (TTPs) of [Threat Actor], targeting [objectives].

### 1.2 Key Findings Summary

| # | Finding | Severity | Detected |
|---|---|---|---|
| 1 | [Finding Title] | Critical | No |
| 2 | [Finding Title] | High | Yes |
| 3 | [Finding Title] | High | No |
| 4 | [Finding Title] | Medium | Yes |

### 1.3 Overall Risk Rating

**[CRITICAL / HIGH / MEDIUM / LOW]**

The red team achieved [X of Y] defined objectives, with [Z]% of activities detected by the security operations center. Critical gaps were identified in [area 1], [area 2], and [area 3].

### 1.4 Metrics at a Glance

| Metric | Value |
|---|---|
| Total TTPs Executed | XX |
| Detection Rate | XX% |
| Mean Time to Detect | XX hours |
| Objectives Achieved | X/Y |
| Dwell Time (Undetected) | XX days |
| Unique Hosts Compromised | XX |
| Credentials Harvested | XX |

---

## 2. Scope and Rules of Engagement

### 2.1 Engagement Scope

**In-Scope:**
- Network ranges: [CIDR ranges]
- Domains: [domains]
- Physical locations: [if applicable]
- Personnel: [if social engineering in scope]

**Out-of-Scope:**
- [Systems/networks excluded]
- [Actions prohibited]

### 2.2 Rules of Engagement

- Authorization document reference: [RoE document ID]
- Approved hours of operation: [hours]
- Emergency contact: [name, phone]
- Deconfliction process: [description]

### 2.3 Threat Profile

**Emulated Adversary:** [Threat Actor Name]
- MITRE ATT&CK Group: [Group ID]
- Known Targets: [industries/regions]
- Typical TTPs: [summary of techniques]

---

## 3. Attack Narrative

### 3.1 Engagement Timeline

```
Day 1-5:   Reconnaissance and OSINT
Day 6-8:   Infrastructure setup and payload development
Day 9-12:  Initial access attempts
Day 13-20: Post-exploitation, lateral movement, persistence
Day 21-25: Objective pursuit and data exfiltration
Day 26-28: Cleanup and evidence collection
```

### 3.2 Phase 1: Reconnaissance

**Objective:** Identify attack surface and high-value targets

| Action | Technique | Result |
|---|---|---|
| Subdomain enumeration | T1593 | Found XX subdomains |
| Employee enumeration | T1589.002 | Identified XX employees |
| Credential search | T1589.001 | Found XX breached credentials |

**Key Discoveries:**
- [Discovery 1 with evidence]
- [Discovery 2 with evidence]

### 3.3 Phase 2: Initial Access

**Objective:** Establish initial foothold on target network

**Vector Used:** [T1566.001 Spearphishing / T1190 Exploit / etc.]

**Detailed Walkthrough:**
1. [Step 1 with screenshot reference]
2. [Step 2 with screenshot reference]
3. [Step 3 with screenshot reference]

**Detection Status:** [Detected/Undetected] by [source] at [time]

### 3.4 Phase 3: Post-Exploitation

**Objective:** Escalate privileges and establish persistence

| Action | Technique | Host | Result | Detected |
|---|---|---|---|---|
| Credential dump | T1003.001 | WS-XXX | Obtained X creds | Yes/No |
| Kerberoasting | T1558.003 | DC01 | Cracked X SPNs | Yes/No |
| Scheduled task | T1053.005 | WS-XXX | Persistence set | Yes/No |

### 3.5 Phase 4: Lateral Movement

**Objective:** Move toward crown jewel systems

**Attack Path:**
```
Initial Foothold (WS-042)
    └── Credential Reuse (T1078)
        └── File Server (FS01) via PsExec (T1021.002)
            └── Database Server (DB01) via RDP (T1021.001)
                └── Domain Controller (DC01) via DCSync (T1003.006)
```

### 3.6 Phase 5: Objective Achievement

| Objective | Status | Evidence |
|---|---|---|
| Domain Admin Access | Achieved | DCSync of krbtgt hash |
| PII Data Exfiltration | Achieved | 50MB exfiled over C2 |
| SCADA Network Access | Not Achieved | Network segmentation prevented access |

---

## 4. MITRE ATT&CK Mapping

### 4.1 Technique Heat Map

[Insert ATT&CK Navigator layer screenshot]

Navigator JSON file: `engagement_navigator.json`

### 4.2 Techniques Used

| Technique ID | Technique Name | Tactic | Used | Detected |
|---|---|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access | Yes | Yes |
| T1059.001 | PowerShell | Execution | Yes | No |
| T1003.001 | LSASS Memory | Credential Access | Yes | Yes |
| T1558.003 | Kerberoasting | Credential Access | Yes | No |
| T1021.002 | SMB Admin Shares | Lateral Movement | Yes | No |
| T1003.006 | DCSync | Credential Access | Yes | Yes |
| T1041 | Exfil Over C2 Channel | Exfiltration | Yes | No |

---

## 5. Findings

### Finding 1: [Title]

| Field | Value |
|---|---|
| Severity | Critical |
| CVSS Score | 9.8 |
| Affected Systems | [list] |
| MITRE ATT&CK | [technique ID] |

**Description:** [Detailed description of the vulnerability or gap]

**Evidence:** [Screenshots, logs, proof of exploitation]

**Impact:** [Business impact assessment]

**Recommendation:** [Specific remediation steps]

---

## 6. Detection Gap Analysis

### 6.1 Summary

| Category | Count | Percentage |
|---|---|---|
| Actions Detected | X | XX% |
| Actions Undetected | X | XX% |
| Techniques with Zero Coverage | X | - |

### 6.2 Gaps by Tactic

| Tactic | Actions | Detected | Gap |
|---|---|---|---|
| Initial Access | X | X | XX% |
| Execution | X | X | XX% |
| Persistence | X | X | XX% |
| Credential Access | X | X | XX% |
| Lateral Movement | X | X | XX% |
| Exfiltration | X | X | XX% |

### 6.3 Priority Detection Rules Needed

1. **[Detection Rule Name]** - Detect [technique] via [data source]
2. **[Detection Rule Name]** - Detect [technique] via [data source]
3. **[Detection Rule Name]** - Detect [technique] via [data source]

---

## 7. Recommendations

### 7.1 Immediate (0-30 days)
1. [Critical remediation action]
2. [Critical remediation action]

### 7.2 Short-Term (30-90 days)
1. [High-priority improvement]
2. [High-priority improvement]

### 7.3 Long-Term (90-180 days)
1. [Strategic improvement]
2. [Strategic improvement]

---

## 8. Appendices

### Appendix A: Tools Used
| Tool | Purpose | Version |
|---|---|---|
| Havoc | C2 Framework | 0.7 |
| Impacket | AD Attacks | 0.11.0 |
| Rubeus | Kerberos Attacks | 2.3.0 |
| BloodHound | AD Reconnaissance | 4.3 |

### Appendix B: IOCs for Deconfliction
| Type | Value | Context |
|---|---|---|
| IP | X.X.X.X | C2 Server |
| Domain | c2.example.com | C2 Domain |
| Hash | [SHA256] | Payload |
| User-Agent | [string] | C2 Callback |

### Appendix C: Cleanup Confirmation
- [ ] All implants removed
- [ ] All persistence mechanisms removed
- [ ] All created accounts deleted
- [ ] All modified configurations restored
- [ ] Infrastructure decommissioned
