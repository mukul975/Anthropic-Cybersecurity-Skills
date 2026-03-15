# Standards and References - Supply Chain Security with in-toto

## Industry Standards

### SLSA (Supply chain Levels for Software Artifacts)
- in-toto provides the attestation framework that SLSA builds upon
- SLSA provenance attestations use in-toto attestation format
- Graduated to v1.0 specification with clear level requirements

### NIST SSDF (Secure Software Development Framework) SP 800-218
- PO.1.1: Define and document security requirements for software
- PS.1.1: Verify third-party software components
- PW.4.1: Review and analyze source code for security vulnerabilities

### NIST SP 800-204D: Strategies for Securing the Software Supply Chain
- Section 4: Build system integrity verification
- Section 5: Attestation-based supply chain verification
- Recommends cryptographic provenance tracking

### Executive Order 14028 (Improving the Nation's Cybersecurity)
- Requires SBOM generation for software sold to federal government
- Mandates supply chain security for critical software
- in-toto attestations satisfy provenance requirements

## Compliance Mapping

| Requirement | Framework | in-toto Capability |
|-------------|-----------|-------------------|
| Build provenance | SLSA L2+ | Signed link metadata per build step |
| Artifact integrity | NIST 800-204D | SHA-256 hash chaining between steps |
| Authorized builders | SLSA L3+ | Functionary key verification |
| SBOM generation | EO 14028 | Inspection step for SBOM validation |
| Code review | SLSA L4 | Threshold signing with multiple reviewers |
| Tamper detection | PCI DSS 6.5 | End-to-end verification before deployment |

## Ecosystem Integration

### Sigstore
- Keyless signing via Fulcio certificate authority
- Transparency log via Rekor for attestation persistence
- Cosign for container image signing and verification

### Witness / Archivista
- Witness: in-toto implementation focused on cloud-native CI/CD
- Archivista: Attestation storage and retrieval service
- Both used by SolarWinds for supply chain integrity post-breach

### OpenVEX
- Vulnerability Exploitability eXchange format
- Complements in-toto attestations with vulnerability status
- Allows marking CVEs as "not affected" for specific builds
