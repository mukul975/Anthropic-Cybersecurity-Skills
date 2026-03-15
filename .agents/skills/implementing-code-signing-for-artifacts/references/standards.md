# Standards Reference: Code Signing for Artifacts

## SLSA Framework

### Level 1: Build Provenance
- Document the build process (source, builder, dependencies)
- Provenance metadata available for all artifacts

### Level 2: Signed Provenance
- Build provenance is signed by the build platform
- Signatures tied to authenticated builder identity

### Level 3: Hardened Build Platform
- Build process runs on a hardened, isolated platform
- Provenance is non-falsifiable by the build service

## NIST SSDF (SP 800-218)

### PS.2: Provide Mechanism for Verifying Software Release Integrity
- PS.2.1: Make integrity verification information available to consumers
- Code signing provides cryptographic proof of artifact integrity
- Transparency logs provide public auditability of signing events

### PW.4: Reuse Existing, Well-Secured Software
- Verify signatures of third-party dependencies before integration
- Establish trust anchors for acceptable signing identities

## CIS Software Supply Chain Security

### Artifacts (AR) Controls
- AR-1: Sign all build artifacts using cryptographic signatures
- AR-2: Verify artifact signatures before deployment
- AR-3: Use transparency logs for signing event auditability
- AR-4: Rotate signing keys on a defined schedule

## Executive Order 14028

- Section 4(e): Agencies shall employ tools and processes to maintain trusted source code supply chains
- SBOM and artifact signing required for federal software suppliers
- Sigstore adoption recommended by CISA for open-source supply chain security
