# OWASP Top 10 (2021) Mapping

This directory maps the cybersecurity skills in this repository to the [OWASP Top 10](https://owasp.org/www-project-top-ten/) categories for web application security risks.

## Overview

The OWASP Top 10 represents the most critical security risks to web applications. This mapping connects hands-on skills to each risk category, enabling teams to build targeted training programs for secure development and application security testing.

## OWASP Top 10 2021 Skill Mapping

### A01:2021 -- Broken Access Control

Restrictions on what authenticated users are allowed to do are not properly enforced.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| web-application-security | 41 | IDOR, privilege escalation, path traversal, CORS misconfiguration |
| identity-access-management | 33 | RBAC, ABAC, session management, OAuth/OIDC flaws |
| api-security | 28 | Broken object level authorization (BOLA), function level authorization |
| zero-trust-architecture | 13 | Least privilege enforcement, microsegmentation |

**Example skills:** Implementing RBAC, testing for IDOR vulnerabilities, configuring OAuth 2.0 securely, enforcing API authorization policies.

### A02:2021 -- Cryptographic Failures

Failures related to cryptography that lead to exposure of sensitive data.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| cryptography | 13 | TLS configuration, key management, hashing, encryption at rest |
| web-application-security | 41 | HTTPS enforcement, cookie security flags, certificate validation |
| cloud-security | 48 | KMS configuration, secrets management, encryption in transit |
| api-security | 28 | API transport security, token encryption |

**Example skills:** Configuring TLS 1.3, implementing envelope encryption with KMS, securing JWT tokens, certificate pinning.

### A03:2021 -- Injection

User-supplied data is sent to an interpreter as part of a command or query without proper validation.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| web-application-security | 41 | SQL injection, XSS, command injection, LDAP injection |
| api-security | 28 | GraphQL injection, NoSQL injection, header injection |
| devsecops | 16 | SAST/DAST scanning, input validation, parameterized queries |
| penetration-testing | 23 | Injection testing, payload crafting, WAF bypass |

**Example skills:** Exploiting and remediating SQL injection, testing for stored/reflected XSS, configuring parameterized queries, SAST pipeline integration.

### A04:2021 -- Insecure Design

Risks related to design and architectural flaws, calling for more use of threat modeling and secure design patterns.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| devsecops | 16 | Threat modeling, secure SDLC, security requirements |
| zero-trust-architecture | 13 | Zero trust design principles, defense in depth |
| compliance-governance | 5 | Security architecture review, risk assessment frameworks |
| web-application-security | 41 | Business logic flaws, trust boundary definition |

**Example skills:** Conducting threat modeling with STRIDE, implementing secure design patterns, defining trust boundaries, security architecture review.

### A05:2021 -- Security Misconfiguration

Missing or incorrect security hardening across the application stack.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| cloud-security | 48 | Cloud service misconfiguration, IAM policy errors, S3 bucket exposure |
| container-security | 26 | Container hardening, Kubernetes RBAC, pod security policies |
| network-security | 33 | Firewall rules, segmentation errors, default credentials |
| endpoint-security | 16 | OS hardening, unnecessary services, default configurations |

**Example skills:** Auditing AWS S3 bucket permissions, hardening Kubernetes clusters, configuring security headers, CIS benchmark compliance.

### A06:2021 -- Vulnerable and Outdated Components

Using components with known vulnerabilities or that are no longer maintained.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| vulnerability-management | 24 | CVE tracking, vulnerability scanning, patch management |
| devsecops | 16 | SCA scanning, dependency management, SBOM generation |
| container-security | 26 | Image scanning, base image updates, registry security |
| web-application-security | 41 | Third-party library vulnerabilities, framework updates |

**Example skills:** Running Trivy container scans, implementing SCA in CI/CD, generating and analyzing SBOMs, CVE prioritization with CVSS/EPSS.

### A07:2021 -- Identification and Authentication Failures

Weaknesses in authentication and session management.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| identity-access-management | 33 | MFA implementation, password policies, session fixation |
| web-application-security | 41 | Credential stuffing defense, brute force protection |
| api-security | 28 | API key management, OAuth token handling, JWT validation |
| phishing-defense | 16 | Credential phishing prevention, anti-phishing controls |

**Example skills:** Implementing FIDO2/WebAuthn, configuring adaptive MFA, securing API authentication, detecting credential stuffing attacks.

### A08:2021 -- Software and Data Integrity Failures

Failures related to code and infrastructure that do not protect against integrity violations.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| devsecops | 16 | CI/CD pipeline security, code signing, artifact integrity |
| container-security | 26 | Image signing, admission control, supply chain verification |
| cryptography | 13 | Digital signatures, integrity hashing, code signing certificates |
| vulnerability-management | 24 | Supply chain risk, dependency integrity verification |

**Example skills:** Implementing Sigstore for container signing, securing CI/CD pipelines, verifying software supply chain integrity, content trust enforcement.

### A09:2021 -- Security Logging and Monitoring Failures

Insufficient logging, detection, monitoring, and active response.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| soc-operations | 33 | SIEM configuration, log aggregation, alert tuning |
| threat-hunting | 35 | Log analysis, detection engineering, hypothesis-driven hunting |
| incident-response | 24 | Incident detection, log-based investigation, response automation |
| network-security | 33 | Network monitoring, flow analysis, IDS/IPS tuning |

**Example skills:** Analyzing security logs with Splunk, writing Sigma detection rules, configuring SIEM correlation rules, implementing centralized logging.

### A10:2021 -- Server-Side Request Forgery (SSRF)

Fetching a remote resource without validating the user-supplied URL.

| Relevant Subdomains | Skills | Key Topics |
|---------------------|--------|------------|
| web-application-security | 41 | SSRF exploitation, URL validation, allowlisting |
| cloud-security | 48 | IMDS exploitation, cloud metadata access, VPC endpoint security |
| api-security | 28 | API-to-API SSRF, webhook validation |
| penetration-testing | 23 | SSRF detection and exploitation techniques |

**Example skills:** Testing for SSRF vulnerabilities, securing cloud metadata endpoints (IMDSv2), implementing URL validation and allowlisting, detecting SSRF in API integrations.

## Cross-Reference: OWASP to ATT&CK

| OWASP Category | Related ATT&CK Techniques |
|---------------|--------------------------|
| A01: Broken Access Control | T1078 (Valid Accounts), T1548 (Abuse Elevation Control) |
| A02: Cryptographic Failures | T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing) |
| A03: Injection | T1190 (Exploit Public-Facing App), T1059 (Command and Scripting) |
| A04: Insecure Design | T1195 (Supply Chain Compromise), cross-cutting |
| A05: Security Misconfiguration | T1574 (Hijack Execution Flow), T1190 |
| A06: Vulnerable Components | T1190 (Exploit Public-Facing App), T1195 |
| A07: Authentication Failures | T1110 (Brute Force), T1539 (Steal Web Session Cookie) |
| A08: Integrity Failures | T1195 (Supply Chain Compromise), T1554 (Compromise Client Software) |
| A09: Logging Failures | T1070 (Indicator Removal), T1562 (Impair Defenses) |
| A10: SSRF | T1190 (Exploit Public-Facing App) |

## Cross-Reference: OWASP to NIST CSF 2.0

| OWASP Category | NIST CSF Functions | CSF Categories |
|---------------|-------------------|----------------|
| A01: Broken Access Control | Protect | PR.AA |
| A02: Cryptographic Failures | Protect | PR.DS |
| A03: Injection | Protect, Detect | PR.DS, DE.AE |
| A04: Insecure Design | Govern, Protect | GV.RM, PR.PS |
| A05: Security Misconfiguration | Protect | PR.PS, PR.IR |
| A06: Vulnerable Components | Identify, Govern | ID.RA, GV.SC |
| A07: Authentication Failures | Protect | PR.AA |
| A08: Integrity Failures | Protect, Govern | PR.DS, GV.SC |
| A09: Logging Failures | Detect | DE.CM, DE.AE |
| A10: SSRF | Protect, Detect | PR.DS, DE.AE |

## References

- [OWASP Top 10 Project](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/) -- relevant for api-security subdomain
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) -- relevant for mobile-security subdomain
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) -- Application Security Verification Standard
