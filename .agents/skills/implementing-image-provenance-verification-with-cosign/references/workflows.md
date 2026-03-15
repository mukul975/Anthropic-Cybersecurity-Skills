# Workflow - Image Provenance with Cosign

## Phase 1: Setup
1. Install cosign CLI
2. Choose signing method: keyless (recommended) or key-based
3. If key-based: generate keys, store private key in KMS
4. Configure CI/CD OIDC token for keyless signing

## Phase 2: Build Pipeline Integration
1. Build container image
2. Push to registry (by digest)
3. Sign image with cosign (keyless or key-based)
4. Generate SBOM with syft
5. Attach SBOM as attestation
6. Attach vulnerability scan as attestation

## Phase 3: Admission Enforcement
1. Deploy policy-controller or Kyverno
2. Create ClusterImagePolicy requiring signatures
3. Test with signed image (should pass)
4. Test with unsigned image (should be denied)
5. Enable enforcement in production namespaces

## Phase 4: Verification
```bash
# Manual verification
cosign verify --certificate-identity=CI_IDENTITY \
  --certificate-oidc-issuer=ISSUER \
  IMAGE@DIGEST

# Verify SBOM attestation
cosign verify-attestation --type cyclonedx \
  --certificate-identity=CI_IDENTITY \
  --certificate-oidc-issuer=ISSUER \
  IMAGE@DIGEST
```

## Phase 5: Monitoring
1. Check Rekor transparency log for audit trail
2. Monitor admission controller deny events
3. Alert on unsigned image deployment attempts
