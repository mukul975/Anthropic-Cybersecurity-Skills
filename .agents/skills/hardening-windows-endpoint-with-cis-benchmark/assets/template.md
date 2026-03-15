# CIS Benchmark Hardening Assessment Template

## Endpoint Information

| Field | Value |
|-------|-------|
| Hostname | |
| OS Version | Windows 11 Enterprise 23H2 |
| Domain/Workgroup | |
| CIS Benchmark Version | v3.0.0 |
| Profile Applied | Level 1 / Level 2 |
| Assessment Date | |
| Assessor | |

## Pre-Hardening Checklist

- [ ] Verified current OS patch level
- [ ] Documented installed applications and services
- [ ] Created system restore point / VM snapshot
- [ ] Identified business-critical applications for compatibility testing
- [ ] Obtained CIS Build Kit GPO for target OS version
- [ ] Confirmed Active Directory OU structure for GPO deployment

## CIS-CAT Assessment Results

| Metric | Value |
|--------|-------|
| Total Rules Assessed | |
| Passed | |
| Failed | |
| Not Applicable | |
| Compliance Score | % |
| Target Score | 95% (L1) / 90% (L2) |

## Failed Controls Summary

| CIS ID | Recommendation | Severity | Remediation Plan | Exception? |
|--------|---------------|----------|-----------------|------------|
| | | | | |

## Exception Register

| CIS ID | Recommendation | Business Justification | Compensating Control | Review Date | Approved By |
|--------|---------------|----------------------|---------------------|-------------|-------------|
| | | | | | |

## Post-Hardening Validation

- [ ] Re-ran CIS-CAT assessment after GPO application
- [ ] Verified all business applications function correctly
- [ ] Confirmed remote management tools (RDP, WinRM) still accessible
- [ ] Validated endpoint joins domain and receives policies
- [ ] Tested user login and MFA functionality
- [ ] Verified antivirus/EDR agent status

## Compliance Tracking

| Scan Date | Score | Delta | New Failures | Resolved | Notes |
|-----------|-------|-------|-------------|----------|-------|
| | | | | | Initial baseline |

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| System Administrator | | | |
| Security Analyst | | | |
| CISO / Security Manager | | | |
