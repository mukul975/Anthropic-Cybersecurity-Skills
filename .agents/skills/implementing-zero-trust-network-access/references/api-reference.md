# API Reference: Implementing Zero Trust Network Access

## AWS Verified Access API

| Operation | Description |
|-----------|-------------|
| `ec2.create_verified_access_instance()` | Create a Verified Access instance for ZTNA |
| `ec2.create_verified_access_trust_provider()` | Register OIDC or device trust provider |
| `ec2.create_verified_access_group()` | Create access group with Cedar policy |
| `ec2.create_verified_access_endpoint()` | Expose internal app through Verified Access |
| `ec2.describe_verified_access_instances()` | List all Verified Access instances |
| `ec2.modify_verified_access_instance_logging_configuration()` | Enable CloudWatch or S3 logging |

## GCP Identity-Aware Proxy API

| Operation | Description |
|-----------|-------------|
| `gcloud iap web enable` | Enable IAP on App Engine or backend service |
| `gcloud iap web add-iam-policy-binding` | Grant IAP access to users or groups |
| `gcloud access-context-manager levels create` | Create device/context access levels |
| `compute.backendServices.get()` | Check IAP status on backend services |

## Azure Conditional Access (MS Graph)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/identity/conditionalAccess/policies` | POST | Create conditional access policy |
| `/identity/conditionalAccess/policies/{id}` | PATCH | Update policy conditions or grants |
| `/identity/conditionalAccess/namedLocations` | GET | List trusted network locations |

## AWS Security Groups (Micro-Segmentation)

| Operation | Description |
|-----------|-------------|
| `ec2.describe_security_groups()` | Audit ingress/egress rules for open CIDR ranges |
| `ec2.authorize_security_group_ingress()` | Add least-privilege ingress rule by source SG |
| `ec2.revoke_security_group_ingress()` | Remove overly permissive rules |

## Key Libraries

- **boto3**: AWS SDK for Python — Verified Access and EC2 security group APIs
- **google-cloud-compute**: GCP Compute client for backend service IAP checks
- **azure-identity + azure-mgmt-network**: Azure Private Endpoint management
- **msgraph-sdk**: Microsoft Graph SDK for Conditional Access policies

## Configuration

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | AWS CLI profile with `ec2:Describe*` and `ec2:Create*` permissions |
| `GOOGLE_CLOUD_PROJECT` | GCP project ID for IAP configuration |
| `AZURE_TENANT_ID` | Azure AD tenant for Conditional Access policies |

## References

- [AWS Verified Access Documentation](https://docs.aws.amazon.com/verified-access/)
- [GCP Identity-Aware Proxy](https://cloud.google.com/iap/docs)
- [Azure Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
- [BeyondCorp Enterprise](https://cloud.google.com/beyondcorp-enterprise/docs)
