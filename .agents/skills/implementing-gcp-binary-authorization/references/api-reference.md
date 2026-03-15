# API Reference: Implementing GCP Binary Authorization

## gcloud CLI Commands

```bash
# Enable APIs
gcloud services enable binaryauthorization.googleapis.com containeranalysis.googleapis.com

# Enable on GKE cluster
gcloud container clusters update CLUSTER --enable-binauthz --zone ZONE

# Export policy
gcloud container binauthz policy export --project PROJECT_ID

# Import policy
gcloud container binauthz policy import policy.yaml

# Create attestor
gcloud container binauthz attestors create ATTESTOR_NAME \
  --attestation-authority-note=NOTE_ID \
  --attestation-authority-note-project=PROJECT_ID

# Create attestation
gcloud container binauthz attestations sign-and-create \
  --artifact-url="gcr.io/PROJECT/IMAGE@DIGEST" \
  --attestor="ATTESTOR" --attestor-project="PROJECT" \
  --keyversion-project=PROJECT --keyversion-location=global \
  --keyversion-keyring=KEYRING --keyversion-key=KEY --keyversion=1
```

## Policy Structure

| Field | Values | Description |
|-------|--------|-------------|
| `evaluationMode` | ALWAYS_ALLOW, ALWAYS_DENY, REQUIRE_ATTESTATION | How images are evaluated |
| `enforcementMode` | ENFORCED_BLOCK_AND_AUDIT_LOG, DRYRUN_AUDIT_LOG_ONLY | Block or audit-only |
| `globalPolicyEvaluationMode` | ENABLE, DISABLE | Google-maintained system policy |

## Break-Glass Annotation

```yaml
metadata:
  annotations:
    alpha.image-policy.k8s.io/break-glass: "Emergency - INC-12345"
```

## Cloud Logging Filter (CV Violations)

```
resource.type="k8s_cluster"
logName="projects/PROJECT/logs/binaryauthorization.googleapis.com%2Fcontinuous_validation"
```

### References

- GCP Binary Authorization: https://cloud.google.com/binary-authorization/docs
- Container Analysis API: https://cloud.google.com/container-analysis/docs
- SLSA Framework: https://slsa.dev
