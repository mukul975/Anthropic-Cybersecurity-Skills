# API Reference: Implementing Zero Trust with BeyondCorp

## gcloud IAP Commands

```bash
# Enable IAP on backend service
gcloud iap web enable --resource-type=backend-services \
  --service=my-backend --project=my-project

# Get IAP IAM policy
gcloud iap web get-iam-policy --project=my-project

# Grant IAP access with access level condition
gcloud iap web add-iam-policy-binding --project=my-project \
  --member="group:team@example.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition="expression=accessPolicies/123/accessLevels/corp_device,title=CorpDevice"

# Enable required APIs
gcloud services enable iap.googleapis.com
gcloud services enable accesscontextmanager.googleapis.com
gcloud services enable beyondcorp.googleapis.com
```

## Access Context Manager Commands

```bash
# Create access policy
gcloud access-context-manager policies create --organization=ORG_ID --title="Corp Policy"

# Create access level (device + IP)
gcloud access-context-manager levels create corp_trusted \
  --policy=POLICY_ID --title="Corporate Trusted" \
  --basic-level-spec=level_spec.yaml

# List access levels
gcloud access-context-manager levels list --policy=POLICY_ID --format=json
```

## Access Level Spec (YAML)

```yaml
conditions:
  - ipSubnetworks:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
    devicePolicy:
      requireScreenlock: true
      osConstraints:
        - osType: DESKTOP_WINDOWS
          minimumVersion: "10.0.19041"
        - osType: DESKTOP_MAC
          minimumVersion: "12.0.0"
      allowedEncryptionStatuses:
        - ENCRYPTED
    regions:
      - "US"
      - "GB"
```

## IAP Roles

| Role | Description |
|------|-------------|
| roles/iap.httpsResourceAccessor | Access IAP-protected resources |
| roles/iap.admin | Full IAP administration |
| roles/iap.settingsAdmin | Modify IAP settings |
| roles/iap.tunnelResourceAccessor | Access via IAP TCP tunneling |

## Python SDK

```python
from google.cloud import iap_v1
client = iap_v1.IdentityAwareProxyAdminServiceClient()
# List tunnel destinations
request = iap_v1.ListTunnelDestGroupsRequest(parent=f"projects/{project}/iap_tunnel/locations/-")
```

## Audit Log Query (Cloud Logging)

```
resource.type="gce_backend_service"
logName="projects/PROJECT/logs/cloudaudit.googleapis.com%2Fdata_access"
protoPayload.methodName="AuthorizeUser"
protoPayload.authenticationInfo.principalEmail!=""
```

### References

- BeyondCorp Enterprise: https://cloud.google.com/beyondcorp
- IAP Concepts: https://cloud.google.com/iap/docs/concepts-overview
- Access Context Manager: https://cloud.google.com/access-context-manager/docs
