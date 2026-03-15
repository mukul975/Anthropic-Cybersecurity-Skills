# GCP Penetration Testing API Reference

## GCPBucketBrute — Bucket Enumeration

```bash
# Install
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git
cd GCPBucketBrute
pip install -r requirements.txt

# Unauthenticated scan
python3 gcpbucketbrute.py -k company-name -u

# Authenticated with service account
python3 gcpbucketbrute.py -k company-name -f /path/to/service-account-key.json

# Authenticated with user account (uses default gcloud credentials)
python3 gcpbucketbrute.py -k company-name

# Custom subprocesses for speed
python3 gcpbucketbrute.py -k company-name -s 10
```

**Output columns:** Bucket name | Exists | Public | Authenticated Access | Permissions

## gcloud IAM Enumeration

```bash
# List all IAM bindings for a project
gcloud projects get-iam-policy PROJECT_ID --format=json

# List service accounts
gcloud iam service-accounts list --project PROJECT_ID --format=json

# List user-managed keys for a service account
gcloud iam service-accounts keys list \
  --iam-account SA_EMAIL --managed-by=user --format=json

# Describe a role to see its permissions
gcloud iam roles describe roles/editor --format=json

# Test IAM permissions on a resource
gcloud asset search-all-iam-policies --scope=projects/PROJECT_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers"
```

## gsutil Bucket Permission Testing

```bash
# Check if bucket is listable
gsutil ls gs://target-bucket/

# Check bucket IAM policy
gcloud storage buckets get-iam-policy gs://target-bucket --format=json

# Test specific permissions
gsutil acl get gs://target-bucket/
```

## Privilege Escalation Permissions

Dangerous IAM permissions that enable privilege escalation:

| Permission | Risk |
|------------|------|
| `iam.serviceAccounts.actAs` | Impersonate any SA |
| `iam.serviceAccountKeys.create` | Create keys for any SA |
| `resourcemanager.projects.setIamPolicy` | Grant yourself any role |
| `deploymentmanager.deployments.create` | Deploy as project SA |
| `cloudfunctions.functions.create` | Execute as function SA |
| `compute.instances.create` | Launch VM as any SA |

## Google Cloud Storage Python Client

```python
from google.cloud import storage

client = storage.Client()
bucket = client.bucket("target-bucket")
# Test permissions via testIamPermissions
permissions = bucket.test_iam_permissions(["storage.objects.list", "storage.objects.get"])
```
