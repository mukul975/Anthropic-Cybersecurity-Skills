---
name: implementing-sigstore-for-software-signing
description: 'Implements Sigstore-based software signing and verification using Cosign
  keyless signing, Rekor transparency log verification, and Fulcio certificate authority
  integration to establish cryptographic provenance for container images, binaries,
  and software artifacts. The practitioner configures OIDC-based identity binding,
  verifies signing events against the Rekor transparency log, and integrates signing
  workflows into CI/CD pipelines. Activates for requests involving software supply
  chain signing, keyless container signing, Sigstore deployment, or artifact provenance
  verification.

  '
domain: cybersecurity
subdomain: supply-chain-security
tags:
- sigstore
- cosign
- rekor
- fulcio
- software-signing
- supply-chain
- keyless-signing
- OIDC
- transparency-log
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- GV.SC-01
- GV.SC-03
- GV.SC-06
- GV.SC-07
mitre_attack:
- T1078
- T1190
- T1059
- T1610
- T1611
---
# Implementing Sigstore for Software Signing

## When to Use

- Signing container images and software artifacts without managing long-lived cryptographic keys
- Establishing verifiable provenance for build outputs in CI/CD pipelines using OIDC identity binding
- Querying the Rekor transparency log to audit when and by whom an artifact was signed
- Verifying that container images pulled from registries were signed by authorized identities and issuers
- Integrating Sigstore verification into Kubernetes admission controllers to enforce signed-image policies

**Do not use** for signing artifacts that require air-gapped or offline signing workflows where OIDC authentication is unavailable, for environments that cannot reach the public Sigstore infrastructure (Fulcio, Rekor) and have no private instance deployed, or as a replacement for traditional PGP/GPG signing where regulatory compliance mandates specific key management procedures.

## Prerequisites

- Cosign CLI v2.4+ installed (`go install github.com/sigstore/cosign/v2/cmd/cosign@latest` or binary release)
- Access to an OIDC identity provider supported by Fulcio (Google, GitHub, Microsoft, or a custom OIDC issuer)
- Container registry credentials (for signing container images) with push access to store signature objects
- Python 3.9+ with `sigstore`, `requests`, and `cryptography` packages for the automation agent
- Network access to `fulcio.sigstore.dev`, `rekor.sigstore.dev`, and `tuf-repo-cdn.sigstore.dev` (or private Sigstore instance URLs)

## Workflow

### Step 1: Install and Configure Cosign

Install Cosign and verify it can reach the Sigstore infrastructure:

- **Install from binary release**: Download the appropriate binary from the Cosign GitHub releases page and verify its checksum. On Linux: `curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x cosign-linux-amd64 && sudo mv cosign-linux-amd64 /usr/local/bin/cosign`
- **Verify installation**: Run `cosign version` to confirm the version and check connectivity to Sigstore services with `cosign initialize` which fetches the TUF root of trust
- **Configure custom infrastructure** (optional): If running a private Sigstore stack, set `--fulcio-url`, `--rekor-url`, and `--oidc-issuer` flags or use environment variables `COSIGN_REKOR_URL` and `COSIGN_FULCIO_URL`

### Step 2: Keyless Signing with Cosign and Fulcio

Perform identity-based signing where Fulcio issues a short-lived certificate bound to your OIDC identity:

- **Sign a container image**: Run `cosign sign <IMAGE_DIGEST>` which triggers an OIDC authentication flow. Cosign generates an ephemeral key pair, obtains a short-lived certificate from Fulcio binding the public key to the OIDC identity, signs the image digest, and records the signing event in Rekor. The private key is destroyed immediately after signing.
- **Sign a blob (file)**: Run `cosign sign-blob <file> --bundle artifact.sigstore.json` to sign arbitrary files. The bundle contains the signature, certificate, timestamp, and Rekor inclusion proof.
- **Non-interactive signing in CI**: Set `SIGSTORE_ID_TOKEN` environment variable with a valid OIDC token (e.g., from GitHub Actions OIDC or GCP workload identity) to skip the browser-based authentication flow:
  ```bash
  export SIGSTORE_ID_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -r '.value')
  cosign sign $IMAGE_DIGEST
  ```
- **Supported OIDC providers**: Google (`https://accounts.google.com`), GitHub (`https://github.com/login/oauth`), Microsoft (`https://login.microsoftonline.com`), GitLab (`https://gitlab.com`), and custom providers registered with a private Fulcio instance

### Step 3: Verify Signed Artifacts

Verify that artifacts were signed by expected identities from expected OIDC issuers:

- **Verify a container image**: Run `cosign verify <IMAGE_URI> --certificate-identity=name@example.com --certificate-oidc-issuer=https://accounts.google.com` to confirm the image was signed by the specified identity. Cosign validates the certificate chain, checks the Rekor inclusion proof, and verifies the signature matches the current image digest.
- **Verify a signed blob**: Run `cosign verify-blob <file> --bundle artifact.sigstore.json --certificate-identity=name@example.com --certificate-oidc-issuer=https://accounts.google.com`
- **Regex matching for CI identities**: Use `--certificate-identity-regexp` to match CI workflow identities:
  ```bash
  cosign verify $IMAGE --certificate-identity-regexp="https://github.com/myorg/myrepo/.*" \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
  ```
- **Verification failure modes**: Cosign returns a non-zero exit code on failure. Common failures include certificate identity mismatch, expired certificates without a valid Rekor timestamp, missing Rekor entry, and image digest mismatch (image was modified after signing).

### Step 4: Query the Rekor Transparency Log

Search and verify entries in the Rekor transparency log to audit signing events:

- **Search by email identity**: Use `rekor-cli search --email user@example.com` to find all signing events for an identity
- **Search by artifact hash**: Use `rekor-cli search --sha sha256:<hash>` to find signing events for a specific artifact
- **Retrieve and verify an entry**: Use `rekor-cli get --uuid <entry_uuid>` to retrieve full entry details including the certificate, signature, and artifact hash
- **Verify log inclusion**: Use `rekor-cli verify --entry-uuid <uuid>` to verify the entry's inclusion proof against the signed tree head, confirming the entry exists in the append-only log and has not been tampered with
- **REST API queries**: Query `https://rekor.sigstore.dev/api/v1/index/retrieve` with POST body `{"hash": "sha256:<hash>"}` to retrieve entry UUIDs, then fetch full entries from `/api/v1/log/entries/<uuid>`
- **Monitor for consistency**: Use the rekor-monitor tool or Omniwitness to continuously verify the log remains append-only and entries are never mutated or removed

### Step 5: Integrate into CI/CD Pipelines

Embed signing and verification into build and deployment pipelines:

- **GitHub Actions**: Use `sigstore/cosign-installer` action to install Cosign, then sign images using the GitHub OIDC token as the identity. The signing identity will be the workflow URL (e.g., `https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main`).
- **Kubernetes admission enforcement**: Deploy Sigstore Policy Controller or Kyverno with Cosign verification policies to reject unsigned or incorrectly signed images at admission time
- **Supply chain metadata**: Use `cosign attest` to attach in-toto attestations (SLSA provenance, SBOM, vulnerability scan results) to images, signed with the same keyless flow, enabling consumers to verify both the artifact and its build metadata

## Key Concepts

| Term | Definition |
|------|------------|
| **Keyless Signing** | Identity-based signing that uses short-lived certificates from Fulcio bound to OIDC identities instead of long-lived cryptographic keys, eliminating key management overhead |
| **Fulcio** | Sigstore's certificate authority that issues short-lived X.509 certificates after verifying OIDC tokens, binding an ephemeral public key to a verified identity |
| **Rekor** | Sigstore's immutable, append-only transparency log that records signing events with timestamps, enabling auditors to verify when and by whom an artifact was signed |
| **Cosign** | The primary CLI tool for signing and verifying container images and blobs using the Sigstore infrastructure (Fulcio + Rekor) |
| **TUF Root of Trust** | The Update Framework distribution mechanism for Sigstore's root CA certificate and Rekor public key, ensuring clients trust the correct Sigstore infrastructure |
| **OIDC Identity Binding** | The process where Fulcio verifies a user's identity through an OpenID Connect token and binds it to a short-lived signing certificate |
| **Inclusion Proof** | A cryptographic proof from Rekor demonstrating that a signing event entry exists within the transparency log's Merkle tree |

## Tools & Systems

- **Cosign**: CLI tool for signing containers and blobs, verifying signatures, and attaching attestations using Sigstore keyless signing or traditional key-based signing
- **Fulcio**: Free root certificate authority for code signing certificates issued based on OIDC identity verification with a validity period of approximately 10 minutes
- **Rekor**: Transparency log server providing tamper-evident storage of signing metadata, searchable by identity, artifact hash, or public key
- **Sigstore Policy Controller**: Kubernetes admission webhook that enforces image signing policies by verifying Cosign signatures and attestations before allowing pod creation
- **rekor-cli**: Command-line client for querying, uploading, and verifying entries in the Rekor transparency log

## Common Scenarios

### Scenario: Securing a Container Image Build Pipeline with Keyless Signing

**Context**: A DevOps team builds container images in GitHub Actions and deploys to a Kubernetes cluster. They need to ensure only images built by their CI pipeline can be deployed, preventing supply chain attacks from compromised registries or unauthorized pushes.

**Approach**:
1. Add `sigstore/cosign-installer@v3` to the GitHub Actions workflow and enable OIDC token permissions with `id-token: write`
2. After building and pushing the image, sign it with `cosign sign $IMAGE_DIGEST` using the GitHub Actions OIDC identity automatically
3. Deploy Sigstore Policy Controller to the Kubernetes cluster with a ClusterImagePolicy requiring signatures from `--certificate-identity-regexp=https://github.com/myorg/myrepo/.*` and `--certificate-oidc-issuer=https://token.actions.githubusercontent.com`
4. Verify the signing entry appears in Rekor by querying with the image digest hash to confirm the transparency log recorded the event
5. Test the admission controller by attempting to deploy an unsigned image and confirming it is rejected with a policy violation error

**Pitfalls**:
- Signing the image tag instead of the digest (`cosign sign myimage:latest` vs `cosign sign myimage@sha256:abc...`) means verification breaks when the tag is updated to point to a different digest
- Not pinning the `--certificate-oidc-issuer` during verification allows signatures from any OIDC provider to pass, defeating the purpose of identity binding
- Forgetting to set `id-token: write` permission in GitHub Actions results in OIDC token retrieval failure and signing errors
- Using `--certificate-identity-regexp=.*` in production verification policies effectively disables identity verification

## Output Format

```
## Sigstore Signing Verification Report

**Artifact**: ghcr.io/myorg/myapp@sha256:a1b2c3d4...
**Verification Status**: PASSED

**Certificate Details**:
  Subject: https://github.com/myorg/myapp/.github/workflows/build.yml@refs/heads/main
  Issuer: https://token.actions.githubusercontent.com
  Valid From: 2026-03-19T10:00:00Z
  Valid To: 2026-03-19T10:10:00Z

**Rekor Entry**:
  UUID: 24296fb24b8ad77a8d52...
  Log Index: 89234567
  Integrated Time: 2026-03-19T10:00:05Z
  Inclusion Proof: VERIFIED (tree size: 92000000, root hash: e4f5a6...)

**Policy Check**: Image signed by authorized CI workflow identity
```
