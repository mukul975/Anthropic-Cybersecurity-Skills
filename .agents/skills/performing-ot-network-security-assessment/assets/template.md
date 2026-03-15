# OT Network Security Assessment Report Template

## Document Information

| Field | Value |
|-------|-------|
| Facility | [Facility Name and Location] |
| Assessment Date | YYYY-MM-DD to YYYY-MM-DD |
| Lead Assessor | [Name, Certification] |
| Standard | IEC 62443-3-3 / NIST SP 800-82r3 |
| Classification | [Confidential / Internal Use Only] |
| Report Version | 1.0 |

## Executive Summary

[2-3 paragraphs summarizing the assessment scope, methodology, key findings, and overall risk rating. Written for C-level and operations management audience.]

**Overall Risk Rating**: [Critical / High / Moderate / Low]

**Key Statistics**:
- Total OT assets discovered: [N]
- Critical findings: [N]
- High findings: [N]
- Unauthenticated protocol exposures: [N]
- Cross-zone violations: [N]

## 1. Scope and Methodology

### 1.1 Assessment Scope

| Purdue Level | In Scope | Activity Type |
|-------------|----------|---------------|
| Level 0-1 (Field) | Yes/No | Passive Only |
| Level 2 (Control) | Yes/No | Passive + Limited Active |
| Level 3 (Operations) | Yes/No | Active Permitted |
| Level 3.5 (DMZ) | Yes/No | Active Permitted |
| Level 4 (Enterprise) | Yes/No | Active Permitted |

### 1.2 Exclusions
- [List safety-critical systems excluded from assessment]
- [List maintenance windows utilized for active testing]

### 1.3 Methodology
- Passive network monitoring via SPAN ports ([duration])
- Industrial protocol deep packet inspection
- Firewall rule analysis
- [Other assessment activities performed]

### 1.4 Tools Used
- [Tool 1]: [Purpose]
- [Tool 2]: [Purpose]

## 2. Asset Inventory

### 2.1 Asset Summary by Purdue Level

| Level | Device Type | Count | Key Vendors |
|-------|------------|-------|-------------|
| Level 0-1 | PLCs, RTUs, I/O | [N] | [Vendors] |
| Level 2 | HMI, EWS | [N] | [Vendors] |
| Level 3 | Historian, OPC | [N] | [Vendors] |
| Level 3.5 | DMZ systems | [N] | [Vendors] |
| Level 4 | Enterprise | [N] | [Vendors] |

### 2.2 Industrial Protocol Distribution

| Protocol | Port | Packet Count | Device Count | Auth Support |
|----------|------|-------------|-------------|-------------|
| Modbus/TCP | 502 | [N] | [N] | No |
| EtherNet/IP | 44818 | [N] | [N] | No |
| OPC UA | 4840 | [N] | [N] | Yes |
| S7comm | 102 | [N] | [N] | No |
| DNP3 | 20000 | [N] | [N] | Optional |

## 3. Network Architecture Assessment

### 3.1 Zone Architecture Evaluation
[Assessment of current zone/conduit architecture against IEC 62443-3-2]

### 3.2 Cross-Zone Communication Analysis
[Summary of authorized and unauthorized cross-zone communication flows]

### 3.3 Firewall Rule Analysis
[Summary of firewall rule review findings]

## 4. Findings

### 4.1 Finding Template

```
Finding ID: OT-[NNN]
Severity: [Critical / High / Medium / Low]
Title: [Finding Title]
Affected Assets: [Asset list]
IEC 62443 Reference: [Section reference]
NIST 800-82r3 Reference: [Section reference]

Description:
[Detailed technical description of the finding]

Evidence:
[Screenshots, packet captures, or tool output demonstrating the finding]

Operational Impact:
[Impact on process safety, availability, and operations]

Remediation:
[Specific technical steps to remediate the finding]

Compensating Controls:
[Interim measures if immediate remediation is not feasible]
```

### 4.2 Critical Findings
[List all critical findings using template above]

### 4.3 High Findings
[List all high findings]

### 4.4 Medium Findings
[List all medium findings]

### 4.5 Low Findings
[List all low findings]

## 5. Risk Matrix

| Finding ID | Likelihood | Safety Impact | Operational Impact | Overall Risk |
|-----------|-----------|---------------|-------------------|-------------|
| OT-001 | [H/M/L] | [H/M/L] | [H/M/L] | [Critical/High/Medium/Low] |

## 6. Remediation Roadmap

### Phase 1: Immediate (0-30 days)
- [Critical finding remediation items]

### Phase 2: Short-term (30-90 days)
- [High finding remediation items]

### Phase 3: Medium-term (90-180 days)
- [Medium finding remediation items]

### Phase 4: Long-term (6-12 months)
- [Architecture improvements and low findings]

## 7. Compliance Gap Analysis

### IEC 62443-3-3 Compliance

| Requirement | Status | Gap Description |
|------------|--------|----------------|
| SR 1.1 Human User IAC | [Met/Partial/Not Met] | [Gap detail] |
| SR 2.1 Authorization Enforcement | [Met/Partial/Not Met] | [Gap detail] |
| SR 3.1 Communication Integrity | [Met/Partial/Not Met] | [Gap detail] |
| SR 5.1 Network Segmentation | [Met/Partial/Not Met] | [Gap detail] |

## Appendices

### Appendix A: Complete Asset Inventory
[Detailed asset list with IPs, MACs, firmware versions, protocols]

### Appendix B: Network Diagrams
[Updated network topology diagrams showing discovered assets and flows]

### Appendix C: Firewall Rule Analysis Detail
[Complete firewall rule review with per-rule assessment]

### Appendix D: Tool Output
[Relevant tool output and packet captures]
