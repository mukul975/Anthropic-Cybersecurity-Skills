# OSINT Collection Report Template

## Document Control

| Field | Value |
|-------|-------|
| Target Organization | [NAME] |
| Target Domain(s) | [DOMAINS] |
| Engagement ID | [ID] |
| Collector | [NAME] |
| Date | [DATE] |
| Classification | CONFIDENTIAL |

---

## 1. Executive Summary

[Brief overview of OSINT findings and their impact on attack planning]

**Key Findings:**
- [Finding 1]
- [Finding 2]
- [Finding 3]

**Recommended Attack Vectors:**
1. [Vector 1 based on OSINT]
2. [Vector 2 based on OSINT]

---

## 2. External Attack Surface

### 2.1 Domain Inventory

| Domain | Registrar | Nameservers | Expiry Date |
|--------|-----------|-------------|-------------|
| | | | |

### 2.2 Subdomain Enumeration

| Subdomain | IP Address | Service | Status |
|-----------|-----------|---------|--------|
| | | | Active/Inactive |

### 2.3 IP Range and ASN

| ASN | Organization | IP Range | Country |
|-----|-------------|----------|---------|
| | | | |

### 2.4 Cloud Assets

| Provider | Asset Type | Identifier | Public Access |
|----------|-----------|------------|---------------|
| AWS | S3 Bucket | | Yes/No |
| Azure | Blob Storage | | Yes/No |
| GCP | Storage | | Yes/No |

---

## 3. Personnel Intelligence

### 3.1 Key Personnel

| Name | Title | Department | LinkedIn | Email |
|------|-------|------------|----------|-------|
| | | | | |

### 3.2 Email Format
- **Confirmed Format:** [first.last@domain.com]
- **Validation Method:** [How confirmed]

### 3.3 Social Engineering Targets

| Target | Role | Justification | Risk Level |
|--------|------|---------------|------------|
| | | | High/Medium/Low |

---

## 4. Technology Stack

### 4.1 Web Technologies

| Component | Technology | Version | Notes |
|-----------|-----------|---------|-------|
| Web Server | | | |
| Framework | | | |
| CMS | | | |
| CDN | | | |
| WAF | | | |

### 4.2 Security Posture

| Security Header | Status | Rating |
|----------------|--------|--------|
| HSTS | Present/Missing | |
| CSP | Present/Missing | |
| X-Frame-Options | Present/Missing | |
| X-Content-Type-Options | Present/Missing | |

### 4.3 Infrastructure

| Service | Product | Version | Port |
|---------|---------|---------|------|
| VPN | | | |
| Email | | | |
| Remote Access | | | |

---

## 5. Credential Exposure

### 5.1 Breach Database Results

| Source | Date | Records | Type |
|--------|------|---------|------|
| | | | Passwords/Hashes/Emails |

### 5.2 Code Repository Leaks

| Repository | File | Type of Secret | Status |
|-----------|------|----------------|--------|
| | | API Key/Password/Token | Active/Rotated |

### 5.3 Paste Site Findings

| Site | Date | Content Type | Relevance |
|------|------|-------------|-----------|
| | | | High/Medium/Low |

---

## 6. Physical Intelligence

### 6.1 Office Locations

| Address | Type | Access Controls | Notes |
|---------|------|-----------------|-------|
| | HQ/Branch/DC | | |

### 6.2 Physical Security Observations

| Observation | Location | Photo Reference |
|-------------|----------|-----------------|
| | | |

---

## 7. Attack Surface Summary

### 7.1 Priority Targets

| # | Target | Type | Rationale | Risk |
|---|--------|------|-----------|------|
| 1 | | Technical/Human/Physical | | Critical/High/Medium |

### 7.2 Recommended Initial Access Methods

| Method | MITRE ATT&CK | Likelihood | Required Resources |
|--------|-------------|------------|-------------------|
| Spearphishing | T1566.001 | | |
| Credential Stuffing | T1078 | | |
| External Exploit | T1190 | | |

---

## Appendix A: Raw Data Files

| File | Description | Location |
|------|-------------|----------|
| subdomains.txt | Full subdomain list | |
| emails.txt | Discovered email addresses | |
| dorks.txt | Google dorking queries | |
| tech_fingerprint.json | Technology details | |

## Appendix B: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| | | |

## Appendix C: MITRE ATT&CK Techniques Used

| Technique ID | Name | Result |
|-------------|------|--------|
| T1593.002 | Search Engines | |
| T1596.005 | Scan Databases | |
| T1589.002 | Email Addresses | |
