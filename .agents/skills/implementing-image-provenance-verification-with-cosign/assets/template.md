# Image Signing Policy Template

## Signing Requirements

| Environment | Signing Required | Attestations Required | Enforcement |
|-------------|-----------------|----------------------|-------------|
| Production | Yes (keyless) | SBOM + vuln scan | Deny unsigned |
| Staging | Yes (keyless) | SBOM | Warn unsigned |
| Development | Optional | None | Audit only |

## Trusted Identities

| Identity | OIDC Issuer | Registries |
|----------|-------------|------------|
| GitHub Actions CI | https://token.actions.githubusercontent.com | ghcr.io/myorg/* |
| Google Cloud Build | https://accounts.google.com | gcr.io/project/* |

## Image Inventory for Signing Audit

| Image | Registry | Signed | SBOM | Vuln Scan | Last Verified |
|-------|----------|--------|------|-----------|---------------|
| | | | | | |

## Key Management

| Key Type | Location | Rotation | Owner |
|----------|----------|----------|-------|
| Keyless (OIDC) | Fulcio CA | Ephemeral | CI/CD |
| Backup key pair | AWS KMS | Annual | Security |

## Verification Commands Reference

```bash
# Verify keyless signature
cosign verify \
  --certificate-identity=IDENTITY \
  --certificate-oidc-issuer=ISSUER \
  IMAGE@DIGEST

# Verify SBOM attestation
cosign verify-attestation --type cyclonedx \
  --certificate-identity=IDENTITY \
  --certificate-oidc-issuer=ISSUER \
  IMAGE@DIGEST
```
