# Zero Standing Privilege with CyberArk - Standards Reference

## Zero Trust Frameworks

### NIST SP 800-207 - Zero Trust Architecture
- Never trust, always verify
- Least privilege access to resources
- Microsegmentation and policy enforcement points
- Dynamic, risk-based access policies

### CISA Zero Trust Maturity Model
- Identity pillar: JIT/JEA access for all identities
- Advanced maturity: Automated privilege provisioning/deprovisioning
- Optimal maturity: Continuous verification with ephemeral access

## TEA Framework Components

### Time
- Session duration: minimum required for task completion
- CyberArk default: 1 hour, configurable 15 min to 8 hours
- Business hours enforcement optional
- Auto-termination on session inactivity

### Entitlements
- Principle of least privilege
- Dynamic role creation scoped to specific resources
- Permission boundaries to prevent escalation
- Entitlement analytics for right-sizing

### Approvals
- Risk-based approval routing
- Multi-level approval for critical access
- Auto-approval for previously approved, low-risk requests
- ITSM integration (ServiceNow, Jira) for audit trail

## Compliance Requirements

### SOC 2 - CC6
- CC6.1: Logical access security restricted
- CC6.3: Access authorized, modified, removed timely
- ZSP provides evidence of no standing privileges

### PCI DSS v4.0
- 7.2.1: Access limited to least privilege
- 7.2.4: Access reviewed at least every 6 months
- ZSP eliminates the review burden by removing standing access

### SOX Section 404
- Separation of duties enforcement
- Access to financial systems must be controlled
- JIT access provides clear audit trail of who accessed what, when
