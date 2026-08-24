# Standards and Framework Mappings

## NIST Cybersecurity Framework 2.0

### SR.1: Supply Chain Cybersecurity Risk Management
- **SR.1-01**: Supply chain security practices are integrated into cybersecurity and enterprise risk management programs
  - **Application**: Dependency confusion detection is a critical supply chain security control preventing malicious package installation from public registries
  
- **SR.1-02**: Suppliers and third-party partners are identified, prioritized, and assessed using cybersecurity risk assessments
  - **Application**: Package registries (npm, PyPI, Maven Central) are third-party suppliers requiring trust verification and behavioral monitoring

### SR.2: Supply Chain Cybersecurity - Suppliers and Partners  
- **SR.2-01**: Cybersecurity requirements are established and communicated to suppliers and third-party partners
  - **Application**: Internal package naming conventions, scoped packages, and registry configuration standards must be communicated to development teams

### ID.SC: Supply Chain Risk Management
- **ID.SC-01**: Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders
  - **Application**: Dependency confusion prevention requires governance for package naming, registry configuration, and continuous monitoring

- **ID.SC-02**: Suppliers and third-party partners are identified, prioritized, and assessed using a cyber supply chain risk assessment process
  - **Application**: Package authors and registries must be assessed; Socket.dev/Snyk behavioral analysis replaces trust-based models

## MITRE ATT&CK Framework v19.1

### T1195.002: Supply Chain Compromise - Compromise Software Dependencies
**Tactic**: Initial Access  
**Description**: Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise

**Detection Methods**:
- Monitor package manager logs for unexpected registry resolutions
- Alert on install scripts executing network calls or accessing environment variables
- Audit SBOM for packages not sourced from approved registries
- Behavioral analysis of package install hooks (postinstall, preinstall, setup.py)

**Mitigation Strategies**:
- Enforce scoped package naming (@orgname/package)
- Configure package manager registry prioritization (private before public)
- Deploy SCA tools with behavioral analysis (Socket.dev, Snyk)
- Implement pre-commit hooks blocking unscoped internal packages

**Real-World Examples** (2026):
- **Mini Shai-Hulud Campaign** (May 2026): 170+ npm packages compromised with exfiltration payloads
- **TanStack Supply Chain Attack** (May 2026): 84 malicious versions published in 6-minute window
- **Microsoft Reconnaissance Payload** (May 2026): 33 scoped packages mimicking corporate namespaces

### T1195.001: Supply Chain Compromise - Compromise Software Supply Chain
**Tactic**: Initial Access  
**Description**: Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise

**Relationship to Dependency Confusion**:
- Dependency confusion is a specific technique within T1195.001 exploiting namespace collisions
- Unlike direct compromise of legitimate packages, dependency confusion creates parallel malicious packages

## MITRE D3FEND Framework

### D3-DACH: Decoy Account (Defensive Technique)
**Relevance**: Honeypot packages can be created with internal-sounding names to detect attackers enumerating private package namespaces

### D3-SWAS: Software Assurance
**Technique**: D3-SWAS  
**Application**: SBOM generation and continuous monitoring detect unauthorized package substitutions

## OWASP Top 10 CI/CD Security Risks

### CICD-SEC-8: Dependency Chain Abuse
**Risk**: Attackers poison dependency resolution mechanisms to inject malicious code during build
**Controls**:
- Dependency pinning with hash verification
- Private registry with allow-list of public packages
- Behavioral monitoring of install scripts

## SLSA (Supply chain Levels for Software Artifacts)

### SLSA Build Level 1
**Requirements**: Provenance exists  
**Dependency Confusion Implication**: Even packages with SLSA provenance can be malicious if sourced from wrong registry

### SLSA Build Level 3
**Requirements**: Hardened builds, non-falsifiable provenance  
**Limitation**: Mini Shai-Hulud (May 2026) demonstrated compromise of packages with valid SLSA L3 provenance

**Lesson**: Provenance attests to build integrity but not package legitimacy; registry source validation is critical

## CIS Controls v8.1

### Control 2: Inventory and Control of Software Assets
**Safeguard 2.3**: Address Unauthorized Software  
**Application**: SBOM monitoring detects packages from unauthorized registries

### Control 4: Secure Configuration of Enterprise Assets and Software
**Safeguard 4.1**: Establish and Maintain a Secure Configuration Process  
**Application**: Package manager configurations (.npmrc, pip.conf) must be hardened and audited

## ISO/IEC 27001:2022

### A.5.19: Information Security in Supplier Relationships
**Control**: Information security requirements for mitigating risks associated with supplier's access
**Application**: Package registries are suppliers; scoped namespaces and behavioral monitoring mitigate risk

### A.8.30: Outsourced Development
**Control**: The organization shall direct, monitor, and review information security for outsourced development
**Application**: Third-party packages are outsourced code; SCA tools provide monitoring and review

## 2026 Supply Chain Attack Statistics

### Phoenix Security Malware Package Intelligence (MPI) Corpus
**Period**: June 2024 - June 2026  
**Findings**:
- **59 supply chain attack campaigns** documented
- **657 malicious package-versions** indexed as IOCs
- **0 CVEs filed** for majority of campaigns (outrunning CVE system)

### Notable 2026 Campaigns

#### Mini Shai-Hulud (May 11, 2026)
- **Scope**: 170+ npm packages, 2 PyPI packages
- **Total Malicious Versions**: 404
- **Targets**: TanStack (@tanstack/*), Mistral AI
- **Technique**: Compromise of legitimate maintainer accounts
- **Payload**: Environment variable exfiltration, SLSA L3 provenance present (!!!
- **Detection Gap**: Commercial SCA tools flagged 72 hours post-publication

#### Microsoft-Documented Reconnaissance Campaign (May 28-29, 2026)
- **Scope**: 33 npm packages across 9 organizational scopes
- **Technique**: Dependency confusion via scoped package mimicry
- **Payload**: Obfuscated postinstall hook exfiltrating developer environment data
- **Targets**: @redhat-cloud-services, @azure, @aws-sdk (mock scopes)
- **Discovery**: Microsoft Threat Intelligence disclosure

#### Shai-Hulud Campaign (June 2026)
- **Scope**: 57+ npm packages
- **Technique**: Compromised maintainer credentials
- **Status**: **Zero CVEs filed** (as of July 2026)

#### Miasma Campaign (June 2026)
- **Scope**: 32 @redhat-cloud-services/* npm packages
- **Technique**: Dependency confusion targeting Red Hat internal namespace
- **Status**: **Zero CVEs filed**

#### Hades Campaign (June 2026)
- **Scope**: 19+ PyPI packages
- **Technique**: Typosquatting popular data science libraries
- **Status**: **Zero CVEs filed**

### Key Insight: The Zero-CVE Problem
**Challenge**: 2026 supply chain attacks bypass traditional vulnerability management:
- Malicious packages receive no CVE assignments (not vulnerabilities, but threats)
- CVE-based SCA tools (Dependabot, Snyk CVE feed) miss behavioral threats
- Average detection lag: 47-72 hours from publication to commercial SCA flagging

**Solution**: Behavioral analysis (Socket.dev) and registry source validation (scoped packages)

## Regulatory Compliance

### EU Cyber Resilience Act (CRA) - 2024
**Article 13**: Security by default  
**Implication**: Software must be delivered with secure supply chain configuration; dependency confusion prevention is required

### US Executive Order 14028: Improving the Nation's Cybersecurity (2021)
**Section 4(e)**: SBOM for software sold to federal government  
**Implication**: SBOM must identify package source registries to detect dependency confusion

### NYDFS Cybersecurity Regulation 23 NYCRR 500
**Section 500.11**: Third-Party Service Provider Security Policy  
**Application**: Package registries are third-party providers requiring security assessment

## Best Practices (2026 Industry Consensus)

### CISA Software Supply Chain Guidance
1. Use scoped packages for all internal dependencies
2. Configure package managers to prioritize private registries
3. Deploy behavioral SCA tools (Socket.dev, Snyk, Endor Labs)
4. Generate and monitor SBOM continuously
5. Implement pre-commit hooks blocking unscoped internal packages

### NIST SSDF (Secure Software Development Framework) v1.1
**PO.3.2**: Define and implement processes for identifying and handling tampered software components
- Dependency confusion detection via registry source validation
- Automated rejection of packages from unexpected registries

### OpenSSF Scorecards
**Dependency-Pinning Check**: Verify dependencies are pinned to specific versions with hashes
**Dependency-Update-Tool Check**: Automated dependency updates must validate registry source

## References

- NIST Cybersecurity Framework 2.0 (2024)
- MITRE ATT&CK v19.1 (2026)
- MITRE D3FEND Knowledge Base (2026)
- Phoenix Security MPI Corpus (2024-2026)
- Microsoft Threat Intelligence: npm Dependency Confusion (May 2026)
- CISA Supply Chain Security Guidance (2025)
- NIST SSDF v1.1 (2022)
- SLSA Specification v1.0 (2023)
- OWASP Top 10 CI/CD Security Risks (2024)
- CIS Controls v8.1 (2023)
