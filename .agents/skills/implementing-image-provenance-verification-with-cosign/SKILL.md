---
name: implementing-image-provenance-verification-with-cosign
description: Sign and verify container image provenance using Sigstore Cosign with keyless OIDC-based signing, attestations, and Kubernetes admission enforcement.
domain: cybersecurity
subdomain: container-security
tags: [cosign, sigstore, image-signing, supply-chain, provenance, keyless, slsa]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Image Provenance Verification with Cosign

## Overview

Cosign is a Sigstore tool for signing, verifying, and attaching metadata to container images and OCI artifacts. It supports both key-based and keyless (OIDC) signing, integrates with Fulcio (certificate authority) and Rekor (transparency log), and enables supply chain security for container images.

## Prerequisites

- Cosign CLI installed
- Docker or Podman for building images
- OCI-compliant container registry (Docker Hub, GHCR, GCR, ECR)
- OIDC provider account (GitHub, Google, Microsoft) for keyless signing

## Installing Cosign

```bash
# Install via Go
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Install via Homebrew
brew install cosign

# Install via script
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

# Verify installation
cosign version
```

## Key-Based Signing

### Generate Key Pair

```bash
# Generate cosign key pair (creates cosign.key and cosign.pub)
cosign generate-key-pair

# Generate key pair stored in KMS
cosign generate-key-pair --kms awskms:///alias/cosign-key
cosign generate-key-pair --kms gcpkms://projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY
cosign generate-key-pair --kms hashivault://transit/keys/cosign
```

### Sign Image with Key

```bash
# Sign an image
cosign sign --key cosign.key ghcr.io/myorg/myapp:v1.0.0

# Sign with annotations
cosign sign --key cosign.key \
  -a "build-id=12345" \
  -a "git-sha=$(git rev-parse HEAD)" \
  ghcr.io/myorg/myapp:v1.0.0
```

### Verify Image with Key

```bash
# Verify signature
cosign verify --key cosign.pub ghcr.io/myorg/myapp:v1.0.0

# Verify with annotation check
cosign verify --key cosign.pub \
  -a "build-id=12345" \
  ghcr.io/myorg/myapp:v1.0.0
```

## Keyless Signing (OIDC)

### Sign with Keyless (Interactive)

```bash
# Keyless sign - opens browser for OIDC auth
cosign sign ghcr.io/myorg/myapp:v1.0.0

# The signature, certificate, and Rekor entry are created automatically
```

### Sign with Keyless (CI/CD - Non-Interactive)

```bash
# GitHub Actions (uses OIDC token automatically)
cosign sign ghcr.io/myorg/myapp:v1.0.0 \
  --yes

# With explicit identity token
cosign sign ghcr.io/myorg/myapp:v1.0.0 \
  --identity-token=$(cat /var/run/sigstore/cosign/oidc-token) \
  --yes
```

### Verify Keyless Signature

```bash
# Verify by email identity
cosign verify ghcr.io/myorg/myapp:v1.0.0 \
  --certificate-identity=builder@example.com \
  --certificate-oidc-issuer=https://accounts.google.com

# Verify by GitHub Actions workflow
cosign verify ghcr.io/myorg/myapp:v1.0.0 \
  --certificate-identity=https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com

# Verify with regex matching
cosign verify ghcr.io/myorg/myapp:v1.0.0 \
  --certificate-identity-regexp=".*@example.com" \
  --certificate-oidc-issuer=https://accounts.google.com
```

## Attestations (SLSA Provenance)

### Attach SBOM Attestation

```bash
# Generate SBOM
syft ghcr.io/myorg/myapp:v1.0.0 -o cyclonedx-json > sbom.cdx.json

# Attach SBOM as attestation
cosign attest --key cosign.key \
  --type cyclonedx \
  --predicate sbom.cdx.json \
  ghcr.io/myorg/myapp:v1.0.0

# Verify attestation
cosign verify-attestation --key cosign.pub \
  --type cyclonedx \
  ghcr.io/myorg/myapp:v1.0.0
```

### Attach Vulnerability Scan Attestation

```bash
# Run scan and save results
grype ghcr.io/myorg/myapp:v1.0.0 -o json > vuln-scan.json

# Attach scan results as attestation
cosign attest --key cosign.key \
  --type vuln \
  --predicate vuln-scan.json \
  ghcr.io/myorg/myapp:v1.0.0
```

### SLSA Provenance Attestation

```bash
# Attach SLSA provenance
cosign attest --key cosign.key \
  --type slsaprovenance \
  --predicate provenance.json \
  ghcr.io/myorg/myapp:v1.0.0

# Verify SLSA provenance
cosign verify-attestation --key cosign.pub \
  --type slsaprovenance \
  ghcr.io/myorg/myapp:v1.0.0
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Sign and Publish
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write  # Required for keyless signing

jobs:
  build-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: sigstore/cosign-installer@v3

      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      - name: Sign image (keyless)
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

      - name: Generate and attach SBOM
        run: |
          syft ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }} -o cyclonedx-json > sbom.json
          cosign attest --yes \
            --type cyclonedx \
            --predicate sbom.json \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

## Kubernetes Admission Enforcement

### Policy Controller (Sigstore)

```bash
# Install policy-controller
helm repo add sigstore https://sigstore.github.io/helm-charts
helm install policy-controller sigstore/policy-controller \
  --namespace cosign-system --create-namespace
```

```yaml
# Enforce signed images in namespace
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
    - glob: "ghcr.io/myorg/**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: "https://github.com/myorg/.*"
      ctlog:
        url: https://rekor.sigstore.dev
```

### Kyverno Integration

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

## Transparency Log (Rekor)

```bash
# Search Rekor for image signatures
rekor-cli search --email builder@example.com

# Get specific entry
rekor-cli get --uuid <entry-uuid>

# Verify entry inclusion
cosign verify ghcr.io/myorg/myapp:v1.0.0 \
  --certificate-identity=builder@example.com \
  --certificate-oidc-issuer=https://accounts.google.com
```

## Best Practices

1. **Use keyless signing** in CI/CD for automated pipelines
2. **Sign by digest** not by tag for immutable references
3. **Attach SBOM attestations** alongside signatures
4. **Enforce signatures** at admission with policy-controller or Kyverno
5. **Use OIDC identity** verification instead of just key verification
6. **Store keys in KMS** (AWS KMS, GCP KMS, HashiCorp Vault) for key-based signing
7. **Verify the full chain**: signature + certificate + Rekor inclusion
8. **Include build metadata** as annotations on signatures
