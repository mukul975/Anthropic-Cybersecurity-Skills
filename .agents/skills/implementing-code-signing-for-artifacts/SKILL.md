---
name: implementing-code-signing-for-artifacts
description: >
  This skill covers implementing code signing for build artifacts to ensure integrity
  and authenticity throughout the software supply chain. It addresses signing binaries,
  packages, and containers using GPG, Sigstore, and platform-specific signing tools,
  establishing trust chains, and verifying signatures in deployment pipelines.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, code-signing, supply-chain, sigstore, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Code Signing for Artifacts

## When to Use

- When establishing artifact integrity verification to prevent supply chain tampering
- When compliance requires cryptographic proof that build artifacts are authentic and unmodified
- When distributing software to customers who need to verify publisher identity
- When implementing zero-trust deployment pipelines that reject unsigned artifacts
- When meeting SLSA Level 2+ requirements for provenance and integrity

**Do not use** for encrypting artifacts (signing provides integrity, not confidentiality), for container image signing specifically (use cosign), or for source code authentication (use commit signing).

## Prerequisites

- GPG key pair for traditional signing or Sigstore account for keyless signing
- Code signing certificate from a Certificate Authority for public distribution
- CI/CD pipeline with access to signing keys or identity provider
- Verification infrastructure in deployment pipelines

## Workflow

### Step 1: Generate and Manage Signing Keys

```bash
# Generate GPG key for artifact signing
gpg --full-generate-key --batch <<EOF
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: eddsa
Subkey-Curve: ed25519
Name-Real: CI Build System
Name-Email: ci-signing@company.com
Expire-Date: 1y
%no-protection
EOF

# Export public key for distribution
gpg --armor --export ci-signing@company.com > signing-key.pub

# Export private key for CI/CD (store in secrets manager)
gpg --armor --export-secret-keys ci-signing@company.com > signing-key.priv
```

### Step 2: Sign Build Artifacts in CI/CD

```yaml
# .github/workflows/build-sign.yml
name: Build and Sign

on:
  push:
    tags: ['v*']

jobs:
  build-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write  # For Sigstore keyless signing
    steps:
      - uses: actions/checkout@v4

      - name: Build artifacts
        run: |
          make build
          sha256sum dist/* > dist/checksums.sha256

      - name: Import GPG Key
        run: |
          echo "${{ secrets.GPG_PRIVATE_KEY }}" | gpg --batch --import
          gpg --list-secret-keys

      - name: Sign artifacts
        run: |
          for file in dist/*; do
            gpg --detach-sign --armor --local-user ci-signing@company.com "$file"
          done

      - name: Install cosign for keyless signing
        uses: sigstore/cosign-installer@v3

      - name: Keyless sign with Sigstore
        run: |
          for file in dist/*.tar.gz; do
            cosign sign-blob "$file" \
              --output-signature "${file}.sig" \
              --output-certificate "${file}.cert" \
              --yes
          done

      - name: Create Release with signed artifacts
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/*
            dist/*.asc
            dist/*.sig
            dist/*.cert
```

### Step 3: Verify Signatures in Deployment Pipeline

```bash
# Verify GPG signature
gpg --import signing-key.pub
gpg --verify artifact.tar.gz.asc artifact.tar.gz

# Verify Sigstore keyless signature
cosign verify-blob artifact.tar.gz \
  --signature artifact.tar.gz.sig \
  --certificate artifact.tar.gz.cert \
  --certificate-identity ci-signing@company.com \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify checksums
sha256sum --check checksums.sha256
```

### Step 4: Sign npm Packages with Provenance

```json
{
  "scripts": {
    "prepublishOnly": "npm run build && npm run test"
  },
  "publishConfig": {
    "provenance": true
  }
}
```

```bash
# Publish npm package with provenance attestation
npm publish --provenance
```

## Key Concepts

| Term | Definition |
|------|------------|
| Code Signing | Cryptographic process of signing software artifacts to verify publisher identity and artifact integrity |
| Detached Signature | Signature stored in a separate file from the artifact, allowing independent distribution |
| Keyless Signing | Sigstore's approach using short-lived certificates tied to OIDC identities instead of long-lived keys |
| Provenance | Metadata describing how, where, and by whom an artifact was built |
| Transparency Log | Append-only log (Rekor) that records all signing events for public auditability |
| Trust Chain | Hierarchical chain from root CA to signing certificate establishing trust in the signer's identity |
| SLSA | Supply-chain Levels for Software Artifacts — framework defining levels of supply chain security |

## Tools & Systems

- **GPG/PGP**: Traditional asymmetric cryptography tool for signing and verifying artifacts
- **Sigstore (cosign)**: Modern keyless signing infrastructure using OIDC identity and transparency logs
- **Rekor**: Sigstore's transparency log recording all signing events immutably
- **Fulcio**: Sigstore's certificate authority issuing short-lived certificates bound to OIDC identities
- **notation**: Microsoft's artifact signing tool for OCI registries (Project Notary v2)

## Common Scenarios

### Scenario: Establishing Signed Release Pipeline

**Context**: An open-source project needs to sign release artifacts so users can verify authenticity and detect tampering.

**Approach**:
1. Use Sigstore keyless signing in GitHub Actions (no key management overhead)
2. Sign all release binaries with `cosign sign-blob` using OIDC identity
3. Generate and sign checksums file for bulk verification
4. Upload signatures, certificates, and checksums alongside release artifacts
5. Document verification instructions in the project README
6. Add verification step to the Homebrew formula or apt repository

**Pitfalls**: GPG key compromise requires revoking and re-signing all artifacts. Sigstore keyless signing avoids this by using ephemeral keys. Long-lived signing keys in CI/CD secrets are a supply chain risk if the CI system is compromised.

## Output Format

```
Artifact Signing Report
========================
Pipeline: Build and Sign v2.3.0
Date: 2026-02-23
Signing Method: Sigstore Keyless + GPG

SIGNED ARTIFACTS:
  app-v2.3.0-linux-amd64.tar.gz
    GPG:      PASS (ci-signing@company.com, EdDSA/Ed25519)
    Sigstore: PASS (Rekor entry: 24658135, Fulcio cert issued)
    SHA256:   a1b2c3d4...

  app-v2.3.0-darwin-arm64.tar.gz
    GPG:      PASS
    Sigstore: PASS (Rekor entry: 24658136)
    SHA256:   e5f6g7h8...

  checksums.sha256
    GPG:      PASS (detached signature)

TRANSPARENCY LOG:
  Entries recorded: 3
  Log index range: 24658135-24658137
  Verification: https://search.sigstore.dev
```
