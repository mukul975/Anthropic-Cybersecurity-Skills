# Access Recertification with Saviynt - Standards Reference

## Compliance Requirements for Access Reviews

### SOX Section 404 (Sarbanes-Oxley)
- Quarterly access reviews for financially significant applications
- Evidence of review decisions with justification
- Remediation of revoked access within defined SLA
- Separation of duties validation during certification

### SOC 2 Type II
- CC6.1: Logical access controls
- CC6.2: User registration and authorization
- CC6.3: Access modification and removal
- Semi-annual certification campaigns required for trust service criteria

### PCI DSS v4.0
- 7.2.4: User accounts and access reviewed at least every 6 months
- 7.2.5: Application and system accounts reviewed every 6 months
- Evidence of review decisions required

### HIPAA Security Rule
- 164.312(a)(1): Access control standard
- 164.308(a)(3)(ii)(A): Workforce clearance procedure
- 164.308(a)(4): Information access management
- Annual access reviews for PHI-accessing systems

### GDPR Article 5(1)(f)
- Appropriate security of personal data
- Regular access reviews ensure only authorized personnel access PII
- Documentation of access review decisions

## Saviynt Campaign Configuration Standards

### Campaign Frequency by Compliance

| Framework | Minimum Frequency | Scope |
|-----------|------------------|-------|
| SOX | Quarterly | Financial applications |
| SOC 2 | Semi-annually | All in-scope systems |
| PCI DSS | Semi-annually | Cardholder data systems |
| HIPAA | Annually | PHI-accessing systems |
| ISO 27001 | Annually | All systems |
| NIST CSF | Per risk assessment | Risk-based |

### Risk-Based Certification

| Risk Level | Review Frequency | Certifier | Auto-Revoke |
|-----------|-----------------|-----------|-------------|
| Critical | Monthly | CISO + App Owner | 7 days |
| High | Quarterly | Manager + App Owner | 14 days |
| Medium | Semi-annually | Manager | 21 days |
| Low | Annually | Manager | 30 days |
