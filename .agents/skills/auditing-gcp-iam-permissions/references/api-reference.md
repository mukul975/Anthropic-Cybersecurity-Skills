# API Reference: Auditing GCP IAM Permissions

## google-cloud-asset

### Search All IAM Policies

```python
from google.cloud import asset_v1

client = asset_v1.AssetServiceClient()
request = asset_v1.SearchAllIamPoliciesRequest(
    scope="organizations/ORG_ID",
    query="policy:roles/owner",
    page_size=500,
)
for result in client.search_all_iam_policies(request=request):
    print(result.resource, result.policy.bindings)
```

### Analyze IAM Policy (Who Can Access What)

```python
request = asset_v1.AnalyzeIamPolicyRequest(
    analysis_query=asset_v1.IamPolicyAnalysisQuery(
        scope="organizations/ORG_ID",
        identity_selector=asset_v1.IamPolicyAnalysisQuery.IdentitySelector(
            identity="user:dev@company.com"
        ),
    )
)
response = client.analyze_iam_policy(request=request)
```

## google-cloud-iam (Service Accounts)

```python
from google.cloud import iam_admin_v1

client = iam_admin_v1.IAMClient()

# List service accounts
request = iam_admin_v1.ListServiceAccountsRequest(name="projects/PROJECT_ID")
for sa in client.list_service_accounts(request=request):
    print(sa.email, sa.disabled)

# List user-managed keys
key_req = iam_admin_v1.ListServiceAccountKeysRequest(
    name=sa.name,
    key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED],
)
```

## google-cloud-resource-manager

```python
from google.cloud import resourcemanager_v3

client = resourcemanager_v3.ProjectsClient()
policy = client.get_iam_policy(request={"resource": "projects/PROJECT_ID"})
for binding in policy.bindings:
    print(binding.role, list(binding.members))
```

## Key GCP IAM Roles to Flag

| Role | Risk Level |
|------|-----------|
| `roles/owner` | Critical (full control) |
| `roles/editor` | High (write access all services) |
| `roles/iam.serviceAccountTokenCreator` | High (impersonation) |
| `roles/iam.serviceAccountKeyAdmin` | High (key creation) |

### References

- google-cloud-asset: https://pypi.org/project/google-cloud-asset/
- google-cloud-iam: https://pypi.org/project/google-cloud-iam/
- google-cloud-resource-manager: https://pypi.org/project/google-cloud-resource-manager/
- GCP IAM docs: https://cloud.google.com/iam/docs
