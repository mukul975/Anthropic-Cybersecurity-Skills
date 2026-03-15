# Vulnerability Exception Request Template

## Exception Request Form

### Vulnerability Information
- **CVE ID**: CVE-YYYY-NNNNN
- **Finding ID**: [Scanner reference number]
- **Affected Asset(s)**: [hostname/IP]
- **Severity**: [Critical/High/Medium/Low]
- **CVSS Score**: [0.0 - 10.0]
- **Discovery Date**: [YYYY-MM-DD]
- **Original SLA Deadline**: [YYYY-MM-DD]

### Exception Details
- **Category**: [ ] Remediation Delay [ ] No Fix Available [ ] Business Critical [ ] False Positive [ ] Compensating Control
- **Requested Expiration Date**: [YYYY-MM-DD]
- **Justification**: [Detailed explanation of why remediation cannot be completed within SLA]

### Compensating Controls
1. **Detection Control**: [How will exploitation attempts be detected?]
2. **Prevention Control**: [What barriers reduce exploitation likelihood?]
3. **Response Procedure**: [What IR procedures are in place for this vulnerability?]
4. **Monitoring**: [What ongoing monitoring ensures controls remain effective?]

### Risk Assessment
- **Residual Risk Rating**: [High/Medium/Low]
- **Business Impact if Exploited**: [Description]
- **Likelihood of Exploitation**: [High/Medium/Low]

### Requestor
- **Name**: [Full name]
- **Email**: [email@company.com]
- **Department**: [Team/Department]
- **Date**: [YYYY-MM-DD]

---

## Approval Section (For Approver Use)

### Decision
- [ ] **Approved** - Exception granted with conditions below
- [ ] **Rejected** - See rejection reason below
- [ ] **More Information Required** - See notes below

### Conditions (if approved)
- [List any additional conditions]

### Reviewer Notes
- [Notes from security review]

### Approver
- **Name**: [Full name]
- **Title**: [Job title]
- **Date**: [YYYY-MM-DD]
- **Signature**: [Digital signature or email confirmation reference]
