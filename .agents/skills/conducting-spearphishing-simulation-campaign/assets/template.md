# Spearphishing Campaign Report Template

## Document Control

| Field | Value |
|-------|-------|
| Campaign ID | [ID] |
| Engagement ID | [ENGAGEMENT_ID] |
| Target Organization | [NAME] |
| Campaign Date | [START] - [END] |
| Red Team Lead | [NAME] |
| Classification | CONFIDENTIAL |

---

## 1. Executive Summary

[Overview of campaign objectives, methodology, and key findings]

**Bottom Line:** [X]% of targeted users clicked the phishing link, and [Y]% submitted credentials, demonstrating [assessment of organizational risk].

---

## 2. Campaign Details

### 2.1 Pretext
- **Theme:** [Password expiry / Shared document / HR benefits / etc.]
- **Authority Figure:** [IT Security / HR / Executive / Vendor]
- **Urgency Level:** [High / Medium / Low]
- **Personalization Level:** [Name, role, department, etc.]

### 2.2 Infrastructure
| Component | Details |
|-----------|---------|
| Sending Domain | [DOMAIN] |
| Domain Age | [DAYS] days |
| SPF/DKIM/DMARC | [Configured / Partial / None] |
| Landing Page URL | [URL] |
| SSL Certificate | [Let's Encrypt / Self-signed] |

### 2.3 Payload
- **Type:** [Link / Attachment / QR Code]
- **Payload:** [Credential harvester / HTML smuggling / Macro document]
- **C2 Callback:** [C2 DOMAIN/IP]

---

## 3. Target Summary

| Department | Targets | Clicked | Submitted | Reported |
|-----------|---------|---------|-----------|----------|
| | | | | |
| **Total** | | | | |

---

## 4. Campaign Metrics

| Metric | Value | Industry Benchmark |
|--------|-------|--------------------|
| Delivery Rate | % | 95%+ |
| Open Rate | % | 30-40% |
| Click-Through Rate | % | 10-15% |
| Credential Capture Rate | % | 5-10% |
| Phishing Report Rate | % | 20-30% |
| Time to First Click | min | <5 min typical |
| Time to First Report | min | <30 min ideal |

---

## 5. Timeline of Events

| Time (UTC) | Event | User | Details |
|-----------|-------|------|---------|
| | Campaign launched | N/A | Wave 1 sent |
| | First email opened | [USER] | Tracking pixel loaded |
| | First link click | [USER] | Landing page accessed |
| | First credential submission | [USER] | Credentials captured |
| | First SOC report | [USER] | Phishing reported |
| | Campaign concluded | N/A | All waves completed |

---

## 6. Security Control Assessment

### 6.1 Email Security Gateway
| Control | Status | Notes |
|---------|--------|-------|
| SPF Validation | Passed/Blocked | |
| DKIM Validation | Passed/Blocked | |
| DMARC Enforcement | Passed/Blocked | |
| URL Rewriting | Active/Bypassed | |
| Attachment Scanning | Active/Bypassed | |
| Sandboxing | Active/Bypassed | |

### 6.2 Endpoint Protection
| Control | Status | Notes |
|---------|--------|-------|
| Browser URL Filtering | Blocked/Bypassed | |
| EDR Detection | Detected/Missed | |
| Credential Guard | Active/Bypassed | |

### 6.3 User Awareness
| Indicator | Assessment |
|-----------|-----------|
| Recognition of phishing indicators | Low/Medium/High |
| Use of phishing report button | Low/Medium/High |
| Resistance to urgency pressure | Low/Medium/High |
| Verification of sender identity | Low/Medium/High |

---

## 7. Risk Assessment

### 7.1 Impact Analysis
If this were a real attack:
- **[X] credentials** would provide initial access to corporate systems
- **[Y] users** would have unknowingly executed malicious payloads
- **Estimated dwell time** before detection: [Z hours/days]

### 7.2 Risk Rating
**Overall Risk: [CRITICAL/HIGH/MEDIUM/LOW]**

---

## 8. Recommendations

### Immediate (0-30 days)
1. [Recommendation]
2. [Recommendation]

### Short-Term (30-90 days)
1. [Recommendation]
2. [Recommendation]

### Long-Term (90+ days)
1. [Recommendation]
2. [Recommendation]

---

## 9. MITRE ATT&CK Mapping

| Technique ID | Name | Status |
|-------------|------|--------|
| T1566.002 | Spearphishing Link | Successful/Blocked |
| T1204.001 | User Execution: Malicious Link | Successful/Blocked |
| T1078 | Valid Accounts | Credentials Captured/None |

---

## Appendix A: Email Template Used

[Include screenshot or text of phishing email]

## Appendix B: Landing Page Screenshot

[Include screenshot of credential harvesting page]

## Appendix C: Users Who Clicked (Redacted)

| # | Department | Role Level | Action Taken |
|---|-----------|------------|-------------|
| 1 | | | Clicked/Submitted/Both |

## Appendix D: IOCs for Blue Team

| Type | Value | Description |
|------|-------|-------------|
| Domain | | Phishing domain |
| IP | | Infrastructure IP |
| URL | | Landing page URL |
| Email | | Sender address |
