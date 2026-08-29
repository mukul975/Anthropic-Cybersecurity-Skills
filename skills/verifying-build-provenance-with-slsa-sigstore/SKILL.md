---
name: verifying-build-provenance-with-slsa-sigstore
description: Verifies artifact signatures and SLSA provenance using Sigstore's cosign (verify, verify-attestation, verify-blob-attestation) and slsa-verifier (verify-artifact), enforcing keyless OIDC builder identity and source repo against SLSA Build levels. Use when verifying artifacts in CI/CD before deployment, consuming third-party attestations, establishing a SLSA Build L3 pipeline, or confirming provenance during incident response or admission control. Do not use for producing image signatures and attestations or enforcing them at Kubernetes admission - use implementing-image-provenance-verification-with-cosign.
domain: cybersecurity
subdomain: supply-chain-security
tags:
- supply-chain
- slsa
- sigstore
- cosign
- provenance
- attestation
- keyless-signing
- code-signing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-01
mitre_attack:
- T1195
---
# Verifying Build Provenance with SLSA and Sigstore

## Overview

Build-provenance verification answers a question that defeats many supply-chain attacks: *was this artifact actually built from the source I think it was, by the builder I trust, without tampering?* Attackers who compromise a build system, swap a compiled release, or inject a malicious step (as in the SolarWinds and 3CX incidents) produce artifacts that look legitimate but lack verifiable provenance. SLSA (Supply-chain Levels for Software Artifacts, https://slsa.dev) defines Build levels (L1–L3) describing increasing provenance integrity, and Sigstore (https://www.sigstore.dev) provides the signing and transparency infrastructure: **cosign** for signing/verifying artifacts and attestations, **Fulcio** for short-lived keyless certificates bound to an OIDC identity, and **Rekor** as a tamper-evident transparency log.

This skill covers verifying signatures and SLSA provenance with **cosign** (`cosign verify`, `cosign verify-attestation`, `cosign verify-blob-attestation`) and **slsa-verifier** (`slsa-verifier verify-artifact`), enforcing the builder identity (the GitHub Actions workflow that produced the artifact) and the expected source repository. Keyless verification ties trust to an OIDC issuer (e.g., `https://token.actions.githubusercontent.com`) and a certificate identity rather than a long-lived private key.

This maps to MITRE ATT&CK **T1195 — Supply Chain Compromise** (provenance verification detects/blocks tampered artifacts) and NIST CSF **PR.DS-01** (the confidentiality, integrity, and availability of data-at-rest are protected; CSF 2.0 absorbed the retired 1.1 PR.DS-06 integrity-checking outcome here).

## When to Use

- In CI/CD before deploying or promoting any container image or release binary.
- When consuming third-party artifacts (base images, Go/npm releases) that publish attestations.
- When establishing a SLSA Build L3 producer pipeline and enforcing it at the consumer side.
- During incident response to confirm whether a deployed artifact's provenance is intact.
- In admission control (e.g., Kubernetes via policy-controller / Kyverno) to admit only verified images.

## Prerequisites

- **cosign** (Sigstore CLI):
  ```bash
  go install github.com/sigstore/cosign/v2/cmd/cosign@latest
  # or download a release binary from https://github.com/sigstore/cosign/releases
  ```
- **slsa-verifier**:
  ```bash
  go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
  # or:
  curl -sSL https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64 \
    -o /usr/local/bin/slsa-verifier && chmod +x /usr/local/bin/slsa-verifier
  ```
- Network access to Rekor (`https://rekor.sigstore.dev`) and Fulcio for transparency-log verification.
- The artifact plus its provenance/attestation bundle (`.sigstore`, `.intoto.jsonl`, or attached OCI attestation).

## Objectives

- Verify a keyless cosign signature on a container image, pinning OIDC issuer and certificate identity.
- Verify a SLSA provenance attestation on an image with `cosign verify-attestation --type slsaprovenance`.
- Verify a release binary's provenance with `slsa-verifier verify-artifact`, pinning source repo and tag.
- Verify GitHub artifact attestations / blob bundles with `cosign verify-blob-attestation`.
- Gate CI and admission control on successful verification; understand SLSA Build L1–L3.

## MITRE ATT&CK Mapping

| ID | Tactic | Technique Name | Relevance |
|----|--------|----------------|-----------|
| T1195 | Initial Access | Supply Chain Compromise | Verifying provenance and signatures detects artifacts that were tampered with or substituted in the build/distribution chain, preventing supply-chain compromise from reaching deployment. |

## Workflow

### Step 1: Verify a keyless cosign signature on an image
Pin both the OIDC issuer and the certificate identity (the exact workflow that signed). A bare `cosign verify` without identity pinning is meaningless — anyone can sign.

```bash
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/.github/workflows/.*@refs/tags/v.*" \
  ghcr.io/myorg/myrepo:v1.2.3
```
A non-zero exit or empty result means verification failed — do not deploy.

### Step 2: Verify the SLSA provenance attestation on the image
The signature proves *who* signed; the provenance attestation proves *how it was built*. Verify the in-toto SLSA predicate type.

```bash
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build-sign.yml@refs/heads/main" \
  ghcr.io/myorg/myrepo:v1.2.3
```
Supported predicate types include `slsaprovenance`, `slsaprovenance02`, and `slsaprovenance1`.

### Step 3: Inspect the provenance predicate
Decode the verified attestation to confirm the source repo, commit, and builder match expectations.

```bash
cosign verify-attestation --type slsaprovenance \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp '.*' \
  ghcr.io/myorg/myrepo:v1.2.3 \
  | jq -r '.payload' | base64 -d | jq '.predicate.buildDefinition.externalParameters, .predicate.runDetails.builder.id'
```

### Step 4: Verify a release binary with slsa-verifier
For downloadable binaries (e.g., produced by `slsa-github-generator`), pin the source URI and the tag. slsa-verifier checks the cryptographic signature on the provenance and that the expected builder produced it.

```bash
slsa-verifier verify-artifact slsa-test-linux-amd64 \
  --provenance-path slsa-test-linux-amd64.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.2.3

# Optionally pin the builder identity (SLSA L3)
slsa-verifier verify-artifact ./mybin \
  --provenance-path ./mybin.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0
```

### Step 5: Verify GitHub artifact attestations / blob bundles
For artifacts signed via `actions/attest-build-provenance`, the bundle uses the new Sigstore bundle format.

```bash
cosign verify-blob-attestation \
  --bundle ./myartifact.sigstore.json \
  --new-bundle-format \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github.com/myorg/myrepo/" \
  ./myartifact

# Equivalent native GitHub CLI verification
gh attestation verify ./myartifact --repo myorg/myrepo
```

### Step 6: Enforce verification as a gate
Wrap verification so the pipeline fails closed on any error.

```bash
#!/usr/bin/env bash
set -euo pipefail
IMG="ghcr.io/myorg/myrepo:v1.2.3"
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/" "$IMG" >/dev/null
cosign verify-attestation --type slsaprovenance \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/" "$IMG" >/dev/null
echo "[+] $IMG verified: signature + SLSA provenance OK"
```

### Step 7: Map findings to SLSA Build levels
Document the level each consumed artifact achieves:
- **Build L1** — provenance exists (the build process generates it), but it may be unsigned/forgeable.
- **Build L2** — provenance is signed by a hosted build service.
- **Build L3** — provenance is non-forgeable: generated on an isolated, hardened builder where secrets are unavailable to user-defined steps (e.g., `slsa-github-generator` reusable workflows). Require L3 for high-trust artifacts.

## Tools and Resources

| Tool / Resource | Purpose | Link |
|-----------------|---------|------|
| cosign | Sign/verify artifacts and attestations (keyless) | https://github.com/sigstore/cosign |
| slsa-verifier | Verify SLSA provenance from compliant builders | https://github.com/slsa-framework/slsa-verifier |
| slsa-github-generator | Produce SLSA L3 provenance in GitHub Actions | https://github.com/slsa-framework/slsa-github-generator |
| actions/attest-build-provenance | GitHub-native provenance attestation | https://github.com/actions/attest-build-provenance |
| SLSA specification | Build levels and provenance schema | https://slsa.dev/spec/v1.0/ |
| Sigstore docs | Fulcio, Rekor, cosign verification | https://docs.sigstore.dev/cosign/verifying/verify/ |

## Verification Identity Reference

| Field | Where it comes from | Why it matters |
|-------|--------------------|----------------|
| `--certificate-oidc-issuer` | The OIDC issuer (e.g., GitHub Actions) | Restricts who could have requested the signing cert |
| `--certificate-identity[-regexp]` | The exact/patterned workflow identity (SAN) | Restricts which workflow signed; prevents impersonation |
| `--source-uri` (slsa-verifier) | Expected source repo | Confirms the artifact came from your repo |
| `--source-tag` / `--source-versioned-tag` | Expected git tag | Prevents rollback/substitution |
| `--builder-id` | Trusted builder workflow ref | Enforces SLSA L3 non-forgeable builder |

## Validation Criteria

- [ ] cosign and slsa-verifier installed and report versions
- [ ] Image signature verified with pinned OIDC issuer AND certificate identity
- [ ] SLSA provenance attestation verified (`--type slsaprovenance`)
- [ ] Provenance predicate inspected; source repo/commit/builder match
- [ ] Release binary verified with slsa-verifier (source-uri + tag pinned)
- [ ] GitHub blob/bundle attestation verified
- [ ] Verification wired as a fail-closed CI/admission gate
- [ ] Each consumed artifact assigned a SLSA Build level
