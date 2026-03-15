---
name: implementing-supply-chain-security-with-in-toto
description: Implement software supply chain integrity verification for container builds using the in-toto framework to create cryptographically signed attestations across CI/CD pipeline steps.
domain: cybersecurity
subdomain: container-security
tags: [in-toto, supply-chain-security, attestation, slsa, sigstore, container-security, cncf, provenance, sbom]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Supply Chain Security with in-toto

## Overview

in-toto is a CNCF graduated project that ensures the integrity of software supply chains from initiation to end-user installation. It creates a verifiable record of the entire software development lifecycle by generating cryptographically signed attestations (called "link metadata") at each step, proving what happened, who performed it, and what artifacts were produced. For container environments, in-toto verifies that images deployed to Kubernetes followed approved build processes and have not been tampered with.

## Prerequisites

- Python 3.8+ or Go runtime for in-toto client libraries
- GPG or Ed25519 keys for signing attestations
- Container build pipeline (Docker, Buildah, or Kaniko)
- Container registry (Docker Hub, ECR, GCR, or Harbor)
- Kubernetes cluster for deployment verification

## Core Concepts

### Supply Chain Layout

The layout is the central policy document that defines:

- **Steps**: Ordered operations in the supply chain (clone, build, test, package, push)
- **Functionaries**: Authorized entities (people or CI systems) that perform each step
- **Inspections**: Client-side verification checks performed at verification time
- **Expected artifacts**: Input/output relationships between steps

```python
from in_toto.models.layout import Layout, Step, Inspection
from securesystemslib.interface import import_ed25519_privatekey_from_file

# Create the supply chain layout
layout = Layout()
layout.set_relative_expiration(months=3)

# Define the code clone step
step_clone = Step(name="clone")
step_clone.expected_materials = []
step_clone.expected_products = [["CREATE", "src/*"]]
step_clone.pubkeys = [clone_functionary_keyid]
step_clone.expected_command = ["git", "clone"]
step_clone.threshold = 1

# Define the build step
step_build = Step(name="build")
step_build.expected_materials = [["MATCH", "src/*", "WITH", "PRODUCTS", "FROM", "clone"]]
step_build.expected_products = [["CREATE", "image.tar"]]
step_build.pubkeys = [build_functionary_keyid]
step_build.expected_command = ["docker", "build"]
step_build.threshold = 1

# Define the scan step
step_scan = Step(name="scan")
step_scan.expected_materials = [["MATCH", "image.tar", "WITH", "PRODUCTS", "FROM", "build"]]
step_scan.expected_products = [["CREATE", "scan-report.json"]]
step_scan.pubkeys = [scan_functionary_keyid]
step_scan.threshold = 1

layout.steps = [step_clone, step_build, step_scan]
```

### Link Metadata

Each step execution generates a link file containing:

- Materials consumed (input artifacts with hashes)
- Products created (output artifacts with hashes)
- Command executed
- Cryptographic signature of the functionary

### Verification Process

At deployment time, the verifier checks:
1. All required steps were performed
2. Each step was signed by an authorized functionary
3. Artifact hashes chain correctly between steps
4. No unauthorized modifications occurred between steps

## Implementation

### Step 1: Generate Signing Keys

```bash
# Generate Ed25519 key pairs for each functionary
mkdir -p keys

# Project owner key (signs the layout)
in-toto-keygen --type ed25519 keys/owner

# CI builder key
in-toto-keygen --type ed25519 keys/builder

# Security scanner key
in-toto-keygen --type ed25519 keys/scanner
```

### Step 2: Create the Supply Chain Layout

```python
#!/usr/bin/env python3
"""Generate in-toto supply chain layout for container builds."""

from in_toto.models.layout import Layout, Step, Inspection
from in_toto.models.metadata import Envelope
from securesystemslib.signer import CryptoSigner
from securesystemslib.interface import import_ed25519_publickey_from_file

def create_container_build_layout():
    layout = Layout()
    layout.set_relative_expiration(months=6)

    # Load functionary public keys
    builder_key = import_ed25519_publickey_from_file("keys/builder.pub")
    scanner_key = import_ed25519_publickey_from_file("keys/scanner.pub")

    layout.keys = {
        builder_key["keyid"]: builder_key,
        scanner_key["keyid"]: scanner_key,
    }

    # Step 1: Source code checkout
    checkout = Step(name="checkout")
    checkout.expected_materials = []
    checkout.expected_products = [
        ["CREATE", "Dockerfile"],
        ["CREATE", "src/*"],
        ["CREATE", "requirements.txt"],
    ]
    checkout.pubkeys = [builder_key["keyid"]]
    checkout.threshold = 1

    # Step 2: Build container image
    build = Step(name="build")
    build.expected_materials = [
        ["MATCH", "Dockerfile", "WITH", "PRODUCTS", "FROM", "checkout"],
        ["MATCH", "src/*", "WITH", "PRODUCTS", "FROM", "checkout"],
    ]
    build.expected_products = [["CREATE", "image-digest.txt"]]
    build.pubkeys = [builder_key["keyid"]]
    build.threshold = 1

    # Step 3: Security scan
    scan = Step(name="scan")
    scan.expected_materials = [
        ["MATCH", "image-digest.txt", "WITH", "PRODUCTS", "FROM", "build"]
    ]
    scan.expected_products = [
        ["CREATE", "vulnerability-report.json"],
        ["CREATE", "sbom.json"],
    ]
    scan.pubkeys = [scanner_key["keyid"]]
    scan.threshold = 1

    # Inspection: Verify no critical vulnerabilities
    inspect_vulns = Inspection(name="verify-no-critical-vulns")
    inspect_vulns.expected_materials = [
        ["MATCH", "vulnerability-report.json", "WITH", "PRODUCTS", "FROM", "scan"]
    ]
    inspect_vulns.run = [
        "python", "-c",
        "import json,sys; r=json.load(open('vulnerability-report.json')); "
        "sys.exit(1) if any(v['severity']=='CRITICAL' for v in r.get('vulnerabilities',[])) else sys.exit(0)"
    ]

    layout.steps = [checkout, build, scan]
    layout.inspect = [inspect_vulns]

    return layout

if __name__ == "__main__":
    layout = create_container_build_layout()
    # Sign with owner key and save
    owner_signer = CryptoSigner.from_priv_key_uri("file:keys/owner")
    envelope = Envelope.from_signable(layout)
    envelope.create_signature(owner_signer)
    envelope.dump("root.layout")
    print("Layout created and signed: root.layout")
```

### Step 3: Record Pipeline Steps

```bash
# In CI/CD pipeline - record each step

# Step 1: Checkout
in-toto-run --step-name checkout \
  --key keys/builder \
  --products Dockerfile src/* requirements.txt \
  -- git clone https://github.com/org/app.git .

# Step 2: Build
in-toto-run --step-name build \
  --key keys/builder \
  --materials Dockerfile src/* \
  --products image-digest.txt \
  -- bash -c "docker build -t app:latest . && docker inspect --format='{{.Id}}' app:latest > image-digest.txt"

# Step 3: Scan
in-toto-run --step-name scan \
  --key keys/scanner \
  --materials image-digest.txt \
  --products vulnerability-report.json sbom.json \
  -- bash -c "trivy image --format json app:latest > vulnerability-report.json && syft app:latest -o json > sbom.json"
```

### Step 4: Verify Before Deployment

```bash
# Verify the entire supply chain
in-toto-verify --layout root.layout \
  --layout-key keys/owner.pub \
  --link-dir ./link-metadata/

# If verification passes, proceed with deployment
if [ $? -eq 0 ]; then
  kubectl apply -f deployment.yaml
  echo "Supply chain verification passed - deploying"
else
  echo "SUPPLY CHAIN VERIFICATION FAILED - blocking deployment"
  exit 1
fi
```

### Step 5: Kubernetes Admission Control

Integrate with a policy engine to verify attestations at admission:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: in-toto-verifier
webhooks:
  - name: verify.in-toto.io
    rules:
      - apiGroups: ["apps"]
        resources: ["deployments"]
        operations: ["CREATE", "UPDATE"]
    clientConfig:
      service:
        name: in-toto-webhook
        namespace: security
        path: /verify
    failurePolicy: Fail
    sideEffects: None
    admissionReviewVersions: ["v1"]
```

## SLSA Integration

in-toto attestations map directly to SLSA (Supply chain Levels for Software Artifacts) requirements:

| SLSA Level | in-toto Requirement |
|------------|-------------------|
| Level 1 | Build process documented (layout exists) |
| Level 2 | Signed attestations from hosted build service |
| Level 3 | Hardened build platform, non-falsifiable provenance |
| Level 4 | Two-party review, hermetic builds |

## References

- [in-toto Official Website](https://in-toto.io/)
- [in-toto GitHub Repository](https://github.com/in-toto/in-toto)
- [CNCF in-toto Graduation Announcement](https://www.cncf.io/announcements/2025/04/23/cncf-announces-graduation-of-in-toto-security-framework-enhancing-software-supply-chain-integrity-across-industries/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore Integration](https://www.sigstore.dev/)
