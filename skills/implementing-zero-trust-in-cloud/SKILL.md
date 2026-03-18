---
name: implementing-zero-trust-in-cloud
description: >
  This skill guides organizations through implementing zero trust architecture in cloud
  environments following NIST SP 800-207 and Google BeyondCorp principles. It covers
  identity-centric access controls, micro-segmentation, continuous verification, device
  trust assessment, and deploying Identity-Aware Proxy to eliminate implicit network
  trust in AWS, Azure, and GCP environments.
domain: cybersecurity
subdomain: cloud-security
tags: [zero-trust, beyondcorp, identity-aware-proxy, micro-segmentation, continuous-verification]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Zero Trust in Cloud

## When to Use

- When migrating from traditional perimeter-based security to identity-centric access controls
- When eliminating VPN dependencies for remote workforce access to cloud applications
- When implementing continuous verification for every access request regardless of network location
- When designing micro-segmentation strategies for multi-cloud workloads
- When regulatory requirements mandate zero trust architecture adoption (federal mandates, NIST guidelines)

**Do not use** for simple VPN replacement without broader architectural changes, for network firewall rule management alone (see implementing-cloud-network-segmentation), or for identity provider initial setup (see managing-cloud-identity-with-okta).

## Prerequisites

- Identity provider capable of OIDC/SAML integration (Okta, Azure AD, Google Workspace)
- Device management solution for endpoint trust assessment (Intune, Jamf, Google Endpoint Verification)
- Cloud workloads accessible via HTTPS with load balancer or reverse proxy infrastructure
- SIEM platform for continuous monitoring of access decisions and anomaly detection

## Workflow

### Step 1: Define Zero Trust Principles and Architecture

Establish the core principles following NIST SP 800-207: never trust, always verify. Every access request must be authenticated, authorized, and encrypted regardless of origin.

```
Zero Trust Architecture Components:
+-------------------------------------------------------------------+
|                        Policy Decision Point                       |
|  +-------------------+  +------------------+  +-----------------+ |
|  | Identity Provider |  | Device Trust     |  | Risk Engine     | |
|  | (Okta/Azure AD)   |  | (Intune/Jamf)    |  | (Continuous)    | |
|  +-------------------+  +------------------+  +-----------------+ |
+-------------------------------------------------------------------+
                              |
                    +--------------------+
                    | Policy Enforcement |
                    | Point (IAP/Proxy)  |
                    +--------------------+
                              |
          +-------------------+-------------------+
          |                   |                   |
    +----------+        +----------+        +----------+
    | App A    |        | App B    |        | App C    |
    | (AWS)    |        | (Azure)  |        | (GCP)    |
    +----------+        +----------+        +----------+
```

### Step 2: Deploy Identity-Aware Proxy

Configure Identity-Aware Proxy (IAP) to enforce identity and context-based access decisions before requests reach applications. Eliminate direct network access to application backends.

```bash
# GCP: Enable Identity-Aware Proxy for a backend service
gcloud services enable iap.googleapis.com

# Configure IAP for an App Engine application
gcloud iap web enable --resource-type=app-engine

# Set IAP access policy requiring specific user group
gcloud iap web add-iam-policy-binding \
  --resource-type=app-engine \
  --member="group:engineering@company.com" \
  --role="roles/iap.httpsResourceAccessor"

# Create Access Level requiring corporate device and MFA
gcloud access-context-manager levels create corporate-device \
  --title="Corporate Device with MFA" \
  --basic-level-spec='{
    "conditions": [
      {
        "devicePolicy": {
          "requireScreenlock": true,
          "allowedEncryptionStatuses": ["ENCRYPTED"],
          "osConstraints": [
            {"osType": "DESKTOP_CHROME_OS", "minimumVersion": "100.0"},
            {"osType": "DESKTOP_MAC", "minimumVersion": "12.0"},
            {"osType": "DESKTOP_WINDOWS", "minimumVersion": "10.0.19041"}
          ]
        },
        "requiredAccessLevels": ["accessPolicies/POLICY_ID/accessLevels/require-mfa"]
      }
    ]
  }'
```

```bash
# AWS: Configure AWS Verified Access for zero trust application access
aws ec2 create-verified-access-instance \
  --description "Zero Trust Access Instance"

aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type oidc \
  --oidc-options '{
    "Issuer": "https://company.okta.com/oauth2/default",
    "AuthorizationEndpoint": "https://company.okta.com/oauth2/default/v1/authorize",
    "TokenEndpoint": "https://company.okta.com/oauth2/default/v1/token",
    "UserInfoEndpoint": "https://company.okta.com/oauth2/default/v1/userinfo",
    "ClientId": "verified-access-client-id",
    "ClientSecret": "verified-access-client-secret",
    "Scope": "openid profile groups"
  }'
```

### Step 3: Implement Continuous Verification

Configure real-time risk assessment that evaluates every access request based on identity, device posture, location, behavior patterns, and threat intelligence signals.

```yaml
# Azure Conditional Access Policy (JSON representation)
{
  "displayName": "Zero Trust - Require MFA and Compliant Device",
  "state": "enabled",
  "conditions": {
    "users": {"includeUsers": ["All"]},
    "applications": {"includeApplications": ["All"]},
    "locations": {
      "includeLocations": ["All"],
      "excludeLocations": ["AllTrusted"]
    },
    "signInRiskLevels": ["medium", "high"],
    "deviceStates": {
      "includeStates": ["All"],
      "excludeStates": ["Compliant", "DomainJoined"]
    }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": [
      "mfa",
      "compliantDevice"
    ]
  },
  "sessionControls": {
    "signInFrequency": {"value": 4, "type": "hours"},
    "persistentBrowser": {"mode": "never"}
  }
}
```

### Step 4: Enforce Micro-Segmentation

Apply network-level zero trust by segmenting cloud workloads into isolated zones with explicit allow rules for each communication path.

```bash
# AWS: Create isolated VPC with no default routes
aws ec2 create-vpc --cidr-block 10.100.0.0/16 --no-amazon-provided-ipv6-cidr-block

# Create security groups implementing micro-segmentation
aws ec2 create-security-group \
  --group-name web-tier-sg \
  --description "Web tier - accepts traffic from ALB only" \
  --vpc-id vpc-abc123

aws ec2 authorize-security-group-ingress \
  --group-id sg-web123 \
  --protocol tcp --port 8080 \
  --source-group sg-alb123

aws ec2 create-security-group \
  --group-name app-tier-sg \
  --description "App tier - accepts traffic from web tier only"

aws ec2 authorize-security-group-ingress \
  --group-id sg-app123 \
  --protocol tcp --port 8443 \
  --source-group sg-web123
```

### Step 5: Implement Device Trust Assessment

Integrate endpoint verification to assess device security posture before granting access. Require encryption, OS patches, and endpoint protection.

```bash
# Google Endpoint Verification with BeyondCorp
gcloud access-context-manager levels create managed-device \
  --title="Managed and Encrypted Device" \
  --basic-level-spec='{
    "conditions": [{
      "devicePolicy": {
        "requireScreenlock": true,
        "requireAdminApproval": true,
        "allowedEncryptionStatuses": ["ENCRYPTED"],
        "allowedDeviceManagementLevels": ["COMPLETE"]
      }
    }]
  }'

# Apply access level to IAP-protected resource
gcloud iap web set-iam-policy \
  --resource-type=backend-services \
  --service=web-app-backend \
  --condition='expression=accessPolicies/POLICY_ID/accessLevels/managed-device'
```

### Step 6: Monitor and Adapt with Continuous Analytics

Deploy logging and analytics to monitor all access decisions, detect anomalies, and continuously refine zero trust policies based on real usage patterns.

```bash
# Export IAP access logs to BigQuery for analysis
gcloud logging sinks create iap-access-logs \
  bigquery.googleapis.com/projects/my-project/datasets/security_logs \
  --log-filter='resource.type="gce_backend_service" AND protoPayload.serviceName="iap.googleapis.com"'

# AWS Verified Access logs to CloudWatch
aws ec2 modify-verified-access-instance-logging-configuration \
  --verified-access-instance-id vai-abc123 \
  --access-logs '{
    "CloudWatchLogs": {"Enabled": true, "LogGroup": "/aws/verified-access/logs"},
    "S3": {"Enabled": true, "BucketName": "verified-access-logs"}
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Zero Trust | Security model that eliminates implicit trust by requiring continuous authentication, authorization, and encryption for every access request |
| BeyondCorp | Google's implementation of zero trust that shifts access controls from network perimeter to individual users and devices |
| Identity-Aware Proxy | Reverse proxy that verifies user identity and context before forwarding requests to backend applications, replacing VPN-based access |
| Continuous Verification | Real-time assessment of identity, device posture, location, and behavior for every access request, not just at initial authentication |
| Device Trust | Assessment of endpoint security posture including encryption status, OS version, patch level, and MDM compliance before granting access |
| NIST SP 800-207 | National Institute of Standards and Technology publication defining zero trust architecture principles and deployment models |
| Access Context Manager | GCP service for defining conditional access policies based on device attributes, IP ranges, and identity properties |
| AWS Verified Access | AWS service providing zero trust application access based on identity and device trust signals without VPN |

## Tools & Systems

- **Google BeyondCorp Enterprise**: End-to-end zero trust platform with Identity-Aware Proxy, Access Context Manager, and Endpoint Verification
- **AWS Verified Access**: Zero trust application access service integrating with identity providers and device trust services
- **Azure Conditional Access**: Policy engine enforcing identity, device, location, and risk-based access controls for Azure AD applications
- **Zscaler Private Access**: Zero trust network access platform replacing VPN with identity and context-based application access
- **Cloudflare Access**: Zero trust proxy for securing internal applications with identity verification and device posture checks

## Common Scenarios

### Scenario: Eliminating VPN for Remote Engineering Access

**Context**: An organization has 500 engineers accessing internal tools via VPN. The VPN concentrator is a single point of failure and recent credential theft incidents showed that VPN access grants excessive lateral movement capability.

**Approach**:
1. Inventory all internal applications accessed via VPN and classify by sensitivity level
2. Deploy Identity-Aware Proxy (GCP) or Verified Access (AWS) in front of each application
3. Configure OIDC integration with the corporate identity provider requiring MFA for all access
4. Implement device trust policies requiring encrypted devices with current OS patches and endpoint protection
5. Enable continuous session evaluation with 4-hour re-authentication for sensitive applications
6. Gradually migrate teams from VPN to IAP access, monitoring for access failures and adjusting policies
7. Decommission VPN after 100% migration and 30-day parallel operation period

**Pitfalls**: Deploying zero trust without device management in place blocks legitimate users with personal devices. Setting re-authentication intervals too short disrupts developer productivity with excessive login prompts.

## Output Format

```
Zero Trust Architecture Assessment Report
===========================================
Organization: Acme Corp
Cloud Providers: AWS, Azure, GCP
Assessment Date: 2025-02-23

MATURITY LEVEL: Level 2 (Advanced) - NIST ZTA Maturity Model

IDENTITY PILLAR:
  MFA Enforcement: 98% of users (target: 100%)
  Phishing-Resistant MFA: 34% (target: 80%)
  SSO Coverage: 87% of applications
  Conditional Access Policies: 12 active policies

DEVICE PILLAR:
  MDM Enrollment: 92% of corporate devices
  Encryption Enforcement: 95%
  OS Patch Compliance: 78% (30-day window)
  Endpoint Protection: 96%

NETWORK PILLAR:
  VPN Dependency: 3 applications remaining (target: 0)
  IAP-Protected Applications: 47/50
  Micro-Segmented Workloads: 65%
  East-West Traffic Encryption: 40% (mTLS adoption)

APPLICATION PILLAR:
  Applications Behind Zero Trust Proxy: 94%
  Session Re-Authentication: Configured for 85% of apps
  Runtime Access Logging: 100%

RECOMMENDATIONS:
  1. [HIGH] Migrate remaining 3 VPN-dependent apps to IAP
  2. [HIGH] Increase phishing-resistant MFA to 80% within 6 months
  3. [MEDIUM] Expand micro-segmentation to remaining 35% of workloads
  4. [MEDIUM] Deploy service mesh for east-west mTLS encryption
```
