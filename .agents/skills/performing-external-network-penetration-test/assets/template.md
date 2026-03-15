# External Network Penetration Test — Report Template

## Document Control

| Field | Value |
|-------|-------|
| Client | [Client Name] |
| Assessment Type | External Network Penetration Test |
| Test Period | [Start Date] — [End Date] |
| Report Version | 1.0 |
| Classification | CONFIDENTIAL |
| Prepared By | [Tester Name], [Certification] |
| Reviewed By | [QA Reviewer] |
| Authorization ID | [PENTEST-YYYY-EXT-NNN] |

---

## 1. Executive Summary

### 1.1 Engagement Overview
[Organization Name] engaged [Testing Company] to perform an external network penetration test against its internet-facing infrastructure. The assessment was conducted between [dates] following the PTES methodology.

### 1.2 Scope
- **IP Ranges:** [CIDR ranges]
- **Domains:** [domain list]
- **Exclusions:** [excluded assets]

### 1.3 Key Findings Summary

| Severity | Count |
|----------|-------|
| Critical | [N] |
| High | [N] |
| Medium | [N] |
| Low | [N] |
| Informational | [N] |

### 1.4 Overall Risk Rating
**[CRITICAL / HIGH / MEDIUM / LOW]**

[Brief narrative of overall security posture]

### 1.5 Top Strategic Recommendations
1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

---

## 2. Technical Findings

### Finding [N]: [Title]

| Attribute | Detail |
|-----------|--------|
| Severity | [Critical/High/Medium/Low] |
| CVSS v3.1 | [Score] — [Vector String] |
| CVE | [CVE-YYYY-NNNNN] |
| CWE | [CWE-NNN] |
| Affected Asset | [IP/hostname:port] |
| Status | [Exploited / Validated / Potential] |

**Description:**
[Detailed description of the vulnerability]

**Impact:**
[Business and technical impact]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Evidence:**
![Screenshot](./evidence/finding_N_screenshot.png)

```
[Terminal output / HTTP request-response]
```

**Remediation:**
- [Primary fix]
- [Alternative mitigation]
- [Detection recommendation]

**References:**
- [URL to CVE/advisory]
- [Vendor documentation]

---

## 3. Methodology

### 3.1 Framework
- PTES (Penetration Testing Execution Standard)
- OWASP Testing Guide v4.2
- MITRE ATT&CK Framework

### 3.2 Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Nmap | [ver] | Port scanning, service enumeration |
| Metasploit | [ver] | Exploitation framework |
| Burp Suite Pro | [ver] | Web application testing |
| Nuclei | [ver] | Vulnerability scanning |
| SQLMap | [ver] | SQL injection testing |
| Hashcat | [ver] | Password cracking |

### 3.3 Testing Timeline

| Date | Phase | Activities |
|------|-------|-----------|
| [Date] | Reconnaissance | OSINT, subdomain enum, port scanning |
| [Date] | Vulnerability Analysis | Automated and manual scanning |
| [Date] | Exploitation | Service and web application exploitation |
| [Date] | Post-Exploitation | Privilege escalation, evidence collection |
| [Date] | Reporting | Findings documentation and QA |

---

## 4. Appendices

### A. Full Scan Results
[Attached as separate files]

### B. Network Topology Discovered
[Network diagram]

### C. Credentials Obtained
| Source | Account Type | Method |
|--------|-------------|--------|
| [Service] | [Role] | [Attack method] |

### D. Glossary

| Term | Definition |
|------|-----------|
| CVSS | Common Vulnerability Scoring System |
| CVE | Common Vulnerabilities and Exposures |
| RCE | Remote Code Execution |
| PTES | Penetration Testing Execution Standard |

---

*This document is classified CONFIDENTIAL and intended solely for [Client Name].*
