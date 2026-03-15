---
name: implementing-gcp-binary-authorization
description: Implement GCP Binary Authorization to enforce deploy-time security controls that ensure only trusted, attested container images are deployed to Google Kubernetes Engine and Cloud Run.
domain: cybersecurity
subdomain: cloud-security
tags: [gcp, binary-authorization, container-security, supply-chain, gke, cloud-run, attestation, software-integrity]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing GCP Binary Authorization

## Overview

Binary Authorization is a Google Cloud deploy-time security control that ensures only trusted container images are deployed on GKE or Cloud Run. It works through a policy-based model where images must have cryptographic attestations confirming they passed predefined requirements such as vulnerability scans, code reviews, or build pipeline verification. Continuous validation (CV) monitors running pods against policies and logs violations.

## Prerequisites

- GCP project with Binary Authorization API enabled
- GKE cluster or Cloud Run service
- Container Analysis API enabled
- KMS keys for attestation signing
- Cloud Build or external CI/CD pipeline

## Enable Binary Authorization

```bash
# Enable required APIs
gcloud services enable binaryauthorization.googleapis.com
gcloud services enable containeranalysis.googleapis.com
gcloud services enable container.googleapis.com

# Enable Binary Authorization on GKE cluster
gcloud container clusters update CLUSTER_NAME \
  --enable-binauthz \
  --zone us-central1-a
```

## Create Attestor

### Create a KMS key for signing

```bash
# Create keyring
gcloud kms keyrings create binauthz-keyring \
  --location global

# Create signing key
gcloud kms keys create attestor-key \
  --keyring binauthz-keyring \
  --location global \
  --algorithm ec-sign-p256-sha256 \
  --purpose asymmetric-signing
```

### Create Container Analysis note

```bash
cat > /tmp/note.json << 'EOF'
{
  "attestation": {
    "hint": {
      "humanReadableName": "Production Build Attestor"
    }
  }
}
EOF

curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://containeranalysis.googleapis.com/v1/projects/PROJECT_ID/notes/?noteId=prod-build-note" \
  -d @/tmp/note.json
```

### Create the attestor

```bash
gcloud container binauthz attestors create prod-build-attestor \
  --attestation-authority-note=prod-build-note \
  --attestation-authority-note-project=PROJECT_ID

# Add KMS key to attestor
gcloud container binauthz attestors public-keys add \
  --attestor=prod-build-attestor \
  --keyversion-project=PROJECT_ID \
  --keyversion-location=global \
  --keyversion-keyring=binauthz-keyring \
  --keyversion-key=attestor-key \
  --keyversion=1
```

## Configure Policy

### Default deny-all policy

```yaml
# binauthz-policy.yaml
admissionWhitelistPatterns:
  - namePattern: "gcr.io/google_containers/*"
  - namePattern: "gcr.io/google-containers/*"
  - namePattern: "k8s.gcr.io/**"
  - namePattern: "gke.gcr.io/**"
  - namePattern: "gcr.io/stackdriver-agents/*"
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
    - projects/PROJECT_ID/attestors/prod-build-attestor
globalPolicyEvaluationMode: ENABLE
```

```bash
gcloud container binauthz policy import binauthz-policy.yaml
```

### Per-cluster rules

```yaml
admissionWhitelistPatterns:
  - namePattern: "gcr.io/google_containers/*"
clusterAdmissionRules:
  us-central1-a.production-cluster:
    evaluationMode: REQUIRE_ATTESTATION
    enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
    requireAttestationsBy:
      - projects/PROJECT_ID/attestors/prod-build-attestor
  us-central1-a.staging-cluster:
    evaluationMode: ALWAYS_ALLOW
    enforcementMode: DRYRUN_AUDIT_LOG_ONLY
defaultAdmissionRule:
  evaluationMode: ALWAYS_DENY
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
```

## Create Attestations

### Attest an image after successful build

```bash
# Get image digest
IMAGE_DIGEST=$(gcloud container images describe \
  gcr.io/PROJECT_ID/my-app:latest \
  --format='get(image_summary.digest)')

# Create attestation
gcloud container binauthz attestations sign-and-create \
  --artifact-url="gcr.io/PROJECT_ID/my-app@${IMAGE_DIGEST}" \
  --attestor="prod-build-attestor" \
  --attestor-project="PROJECT_ID" \
  --keyversion-project="PROJECT_ID" \
  --keyversion-location="global" \
  --keyversion-keyring="binauthz-keyring" \
  --keyversion-key="attestor-key" \
  --keyversion="1"
```

### Cloud Build integration

```yaml
# cloudbuild.yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/my-app:$SHORT_SHA', '.']

  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/my-app:$SHORT_SHA']

  # Vulnerability scanning
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        gcloud artifacts docker images scan \
          gcr.io/$PROJECT_ID/my-app:$SHORT_SHA \
          --format='value(response.scan)'

  # Create attestation after successful scan
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        IMAGE_DIGEST=$(gcloud container images describe \
          gcr.io/$PROJECT_ID/my-app:$SHORT_SHA \
          --format='get(image_summary.digest)')
        gcloud container binauthz attestations sign-and-create \
          --artifact-url="gcr.io/$PROJECT_ID/my-app@$${IMAGE_DIGEST}" \
          --attestor="prod-build-attestor" \
          --attestor-project="$PROJECT_ID" \
          --keyversion-project="$PROJECT_ID" \
          --keyversion-location="global" \
          --keyversion-keyring="binauthz-keyring" \
          --keyversion-key="attestor-key" \
          --keyversion="1"
```

## Continuous Validation

```bash
# Enable CV on a GKE cluster
gcloud container clusters update CLUSTER_NAME \
  --enable-binauthz-monitoring \
  --zone us-central1-a
```

### Monitor CV violations in Cloud Logging

```
resource.type="k8s_cluster"
logName="projects/PROJECT_ID/logs/binaryauthorization.googleapis.com%2Fcontinuous_validation"
```

## Verification and Testing

### Test deployment of unattested image

```bash
# This should be blocked
kubectl run test-unapproved \
  --image=docker.io/library/nginx:latest

# Verify the pod was denied
kubectl get events --field-selector reason=FailedCreate
```

### Verify attestation exists

```bash
gcloud container binauthz attestations list \
  --attestor=prod-build-attestor \
  --attestor-project=PROJECT_ID
```

## Break-Glass Override

For emergency deployments bypassing Binary Authorization:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: emergency-pod
  labels:
    image-policy.k8s.io/break-glass: "true"
  annotations:
    alpha.image-policy.k8s.io/break-glass: "Emergency deployment - ticket INC-12345"
spec:
  containers:
    - name: emergency
      image: gcr.io/PROJECT_ID/emergency-fix:latest
```

## References

- GCP Binary Authorization: https://cloud.google.com/binary-authorization/docs
- SLSA Framework: https://slsa.dev
- Sigstore/Cosign for container signing
- Google Software Supply Chain Security Best Practices
