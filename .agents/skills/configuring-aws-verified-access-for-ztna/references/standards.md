# Standards Reference: AWS Verified Access ZTNA

## AWS Verified Access Standards

### Cedar Policy Language
- Developed by AWS for fine-grained access control
- Supports permit and forbid policies with conditions
- Evaluates context attributes (identity, device posture, request metadata)
- Open-source specification at cedarpolicy.com

### AWS Well-Architected Framework - Security Pillar
- SEC03-BP01: Define access requirements
- SEC03-BP02: Grant least privilege access
- SEC03-BP05: Define permission guardrails for organization
- SEC05-BP03: Automate network protection

## Zero Trust Standards

### NIST SP 800-207
- Verified Access implements enhanced identity governance (Section 3.1)
- Per-request policy evaluation aligns with continuous verification
- Device posture assessment satisfies device trust requirements
- Integration with identity providers meets identity pillar requirements

### CISA Zero Trust Maturity Model
- Identity Pillar: OIDC integration with MFA-enabled providers
- Device Pillar: CrowdStrike/Jamf device posture assessment
- Network Pillar: VPN-less access eliminates implicit network trust
- Application Pillar: Per-application access policies

## Compliance Mappings

### SOC 2
- CC6.1: Logical access security through Cedar policies
- CC6.2: Identity verification via trust providers
- CC6.3: Role-based access through group policies
- CC7.2: System monitoring through access logging

### FedRAMP
- AC-2: Account Management via identity provider integration
- AC-3: Access Enforcement through Cedar policies
- AC-6: Least Privilege via per-application policies
- AU-2: Auditable Events through CloudWatch logging
- SC-7: Boundary Protection via Verified Access endpoints
