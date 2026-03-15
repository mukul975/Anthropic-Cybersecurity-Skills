# API Reference: Implementing Image Provenance Verification with Cosign

## Cosign CLI Commands

```bash
# Sign image (keyless with OIDC)
cosign sign --yes IMAGE_REF

# Sign with key
cosign sign --key cosign.key IMAGE_REF

# Verify (keyless)
cosign verify --certificate-identity USER --certificate-oidc-issuer ISSUER IMAGE_REF

# Verify with key
cosign verify --key cosign.pub IMAGE_REF

# Attach attestation
cosign attest --predicate sbom.json --type spdxjson IMAGE_REF

# Verify attestation
cosign verify-attestation --type spdxjson IMAGE_REF

# Get signature location
cosign triangulate IMAGE_REF
```

## Sigstore Components

| Component | Purpose |
|-----------|---------|
| Cosign | Sign and verify images |
| Fulcio | Short-lived certificate authority |
| Rekor | Transparency log |
| policy-controller | Kubernetes admission |

## Attestation Types

| Type | Predicate | Use Case |
|------|-----------|----------|
| `custom` | Custom JSON | General |
| `spdxjson` | SPDX SBOM | Software bill of materials |
| `cyclonedxjson` | CycloneDX SBOM | Alt SBOM format |
| `slsaprovenance` | SLSA Provenance | Build provenance |
| `vuln` | Vulnerability scan | Scan results |

## Kyverno Policy (Kubernetes Admission)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-cosign
      match:
        any:
          - resources: { kinds: [Pod] }
      verifyImages:
        - imageReferences: ["ghcr.io/org/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "*@org.com"
                    issuer: "https://token.actions.githubusercontent.com"
```

### References

- Sigstore: https://sigstore.dev/
- Cosign Docs: https://docs.sigstore.dev/cosign/signing/overview/
- SLSA Framework: https://slsa.dev/
- Kyverno Image Verification: https://kyverno.io/docs/writing-policies/verify-images/
