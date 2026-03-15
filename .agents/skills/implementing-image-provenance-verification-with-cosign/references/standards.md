# Standards and References - Image Provenance with Cosign

## SLSA Framework (Supply-chain Levels for Software Artifacts)
- Level 1: Documentation of build process
- Level 2: Source version controlled + signed provenance
- Level 3: Hardened build platform, non-falsifiable provenance
- Level 4: Two-party review, hermetic reproducible builds

## NIST SP 800-190
- Section 4.1: Image vulnerabilities - Verify image integrity before deployment
- Section 5.1: Image security - Cryptographic signing and verification

## Executive Order 14028 (Improving the Nation's Cybersecurity)
- Section 4(e): SBOM requirements for software supply chain
- Section 4(g): Software supply chain security guidelines

## Sigstore Components

| Component | Purpose | URL |
|-----------|---------|-----|
| Cosign | Container signing/verification | https://github.com/sigstore/cosign |
| Fulcio | Free code signing CA | https://fulcio.sigstore.dev |
| Rekor | Transparency log | https://rekor.sigstore.dev |
| policy-controller | K8s admission enforcement | https://github.com/sigstore/policy-controller |

## Compliance Mappings

### PCI DSS v4.0
- Req 6.3.2: Develop software securely with integrity verification

### SOC 2
- CC8.1: Change management with cryptographic verification

### FedRAMP
- SA-12: Supply chain protection
- SI-7: Software, firmware, and information integrity
