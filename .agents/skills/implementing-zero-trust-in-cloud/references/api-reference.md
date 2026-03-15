# API Reference: Implementing Zero Trust in Cloud

## Libraries

### boto3 (AWS Zero Trust Checks)
- **Install**: `pip install boto3`
- IAM: `list_users()`, `list_mfa_devices()`, `get_account_summary()`
- EC2: `describe_instances()`, `describe_security_groups()`
- S3: `get_bucket_encryption()`, `get_public_access_block()`
- CloudTrail: `describe_trails()`, `get_trail_status()`

### azure-identity + azure-mgmt-authorization
- **Install**: `pip install azure-identity azure-mgmt-authorization`
- `AuthorizationManagementClient` -- RBAC role assignments
- `DefaultAzureCredential()` -- Auto-detect auth

### google-cloud-compute
- **Install**: `pip install google-cloud-compute`
- `FirewallsClient` -- VPC firewall rules audit
- `InstancesClient` -- VM network configuration

## Zero Trust Pillars (NIST SP 800-207)

| Pillar | Key Checks |
|--------|-----------|
| Identity | MFA enforcement, least privilege, conditional access |
| Device | Compliance policies, MDM, certificate identity |
| Network | Micro-segmentation, private endpoints, no public IPs |
| Application | OAuth2/OIDC, API gateway auth, no VPN dependency |
| Data | Encryption at rest/transit, DLP, classification |
| Visibility | Centralized logging, SIEM, UEBA, real-time alerts |

## AWS Zero Trust Services

| Service | Zero Trust Function |
|---------|-------------------|
| IAM Identity Center | Centralized identity and SSO |
| VPC PrivateLink | Private service connectivity |
| Verified Access | Identity-based application access |
| Security Hub | Continuous posture assessment |
| GuardDuty | Threat detection and monitoring |
| CloudTrail | API activity audit logging |

## Azure Zero Trust Services

| Service | Zero Trust Function |
|---------|-------------------|
| Entra ID Conditional Access | Policy-based access decisions |
| Azure Private Link | Private endpoint connectivity |
| Microsoft Defender for Cloud | CSPM and CWP |
| Azure Sentinel | SIEM and SOAR |

## GCP Zero Trust Services

| Service | Zero Trust Function |
|---------|-------------------|
| BeyondCorp Enterprise | Identity-Aware Proxy |
| VPC Service Controls | API-level perimeter |
| Binary Authorization | Container image trust |
| Security Command Center | Cloud posture management |

## Maturity Levels
- **Traditional**: Perimeter-based, VPN-dependent, implicit trust
- **Initial**: Some identity verification, partial segmentation
- **Advanced**: Continuous verification, micro-segmentation, encrypted everywhere

## External References
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final
- Google BeyondCorp: https://cloud.google.com/beyondcorp
- AWS Verified Access: https://docs.aws.amazon.com/verified-access/
- Azure Zero Trust: https://learn.microsoft.com/en-us/security/zero-trust/
- CISA Zero Trust Maturity Model: https://www.cisa.gov/zero-trust-maturity-model
