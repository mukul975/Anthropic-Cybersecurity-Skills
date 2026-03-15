---
name: securing-azure-with-microsoft-defender
description: >
  This skill instructs security practitioners on deploying Microsoft Defender for Cloud
  as a cloud-native application protection platform for Azure, multi-cloud, and hybrid
  environments. It covers enabling Defender plans for servers, containers, storage, and
  databases, configuring security recommendations, managing Secure Score, and integrating
  with the unified Defender portal for centralized threat management.
domain: cybersecurity
subdomain: cloud-security
tags: [microsoft-defender, azure-security, cnapp, secure-score, cloud-workload-protection]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing Azure with Microsoft Defender

## When to Use

- When deploying cloud workload protection across Azure subscriptions and resource groups
- When establishing a Secure Score baseline and prioritizing security recommendations
- When extending threat protection to multi-cloud environments including AWS and GCP
- When enabling container security for AKS clusters and Azure Container Registry
- When integrating AI workload security with the Data and AI security dashboard

**Do not use** for AWS-only environments (see implementing-aws-security-hub), for identity provider configuration (see managing-cloud-identity-with-okta), or for network-level firewall rule management (see implementing-cloud-waf-rules).

## Prerequisites

- Azure subscription with Security Admin or Contributor role
- Azure Policy initiative for Defender for Cloud enabled at the management group level
- Log Analytics workspace provisioned for security data collection
- Microsoft Defender for Cloud plans licensed (P1 or P2 for server protection)

## Workflow

### Step 1: Enable Defender for Cloud Plans

Activate Defender plans for each workload type: Servers, Containers, App Service, Storage, Databases, Key Vault, Resource Manager, and DNS. Each plan provides specialized threat detection and vulnerability assessment.

```powershell
# Enable Defender for Servers Plan 2
az security pricing create --name VirtualMachines --tier Standard --subplan P2

# Enable Defender for Containers
az security pricing create --name Containers --tier Standard

# Enable Defender for Storage with malware scanning
az security pricing create --name StorageAccounts --tier Standard \
  --extensions '[{"name":"OnUploadMalwareScanning","isEnabled":"True",
  "additionalExtensionProperties":{"CapGBPerMonthPerStorageAccount":"5000"}}]'

# Enable Defender for Databases
az security pricing create --name SqlServers --tier Standard
az security pricing create --name CosmosDbs --tier Standard

# Enable Defender for Key Vault
az security pricing create --name KeyVaults --tier Standard

# Verify all enabled plans
az security pricing list --query "[?pricingTier=='Standard'].{Plan:name, Tier:pricingTier, SubPlan:subPlan}" -o table
```

### Step 2: Configure Environment Connectors for Multi-Cloud

Connect AWS accounts and GCP projects to Defender for Cloud for unified security posture management across cloud providers.

```powershell
# Create AWS connector for CSPM
az security security-connector create \
  --name aws-production-connector \
  --resource-group security-rg \
  --environment-name AWS \
  --hierarchy-identifier "123456789012" \
  --offerings '[{
    "offeringType": "CspmMonitorAws",
    "nativeCloudConnection": {"cloudRoleArn": "arn:aws:iam::123456789012:role/DefenderForCloudRole"}
  }]'

# Create GCP connector
az security security-connector create \
  --name gcp-production-connector \
  --resource-group security-rg \
  --environment-name GCP \
  --hierarchy-identifier "my-gcp-project-id" \
  --offerings '[{"offeringType": "CspmMonitorGcp"}]'
```

### Step 3: Review and Prioritize Secure Score Recommendations

Analyze the Secure Score across all subscriptions. Each recommendation includes a risk priority based on asset exposure, internet exposure, and threat intelligence context.

```powershell
# Get current Secure Score
az security secure-score list \
  --query "[].{Name:displayName, Score:current, Max:max, Percentage:percentage}" -o table

# List unhealthy recommendations sorted by severity
az security assessment list \
  --query "[?properties.status.code=='Unhealthy'].{Name:properties.displayName, Severity:properties.metadata.severity, Resources:properties.resourceDetails.id}" \
  --output table

# Get specific recommendation details
az security assessment show \
  --assessment-name "4fb67663-9ab9-475d-b026-8c544cced439" \
  --query "{Name:properties.displayName, Description:properties.metadata.description, Remediation:properties.metadata.remediationDescription}"
```

### Step 4: Configure Adaptive Application Controls and JIT Access

Enable Just-In-Time VM access to reduce the attack surface by opening management ports only when needed, and deploy adaptive application controls to whitelist approved executables.

```powershell
# Enable JIT VM access policy
az security jit-policy create \
  --resource-group production-rg \
  --location eastus \
  --name default \
  --virtual-machines '[{
    "id": "/subscriptions/sub-id/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-01",
    "ports": [
      {"number": 22, "protocol": "TCP", "allowedSourceAddressPrefix": "10.0.0.0/8", "maxRequestAccessDuration": "PT3H"},
      {"number": 3389, "protocol": "TCP", "allowedSourceAddressPrefix": "10.0.0.0/8", "maxRequestAccessDuration": "PT1H"}
    ]
  }]'

# Request JIT access
az security jit-policy initiate \
  --resource-group production-rg \
  --location eastus \
  --name default \
  --virtual-machines '[{
    "id": "/subscriptions/sub-id/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-01",
    "ports": [{"number": 22, "duration": "PT1H", "allowedSourceAddressPrefix": "203.0.113.10"}]
  }]'
```

### Step 5: Set Up Security Alerts and Workflow Automation

Configure workflow automation to trigger Logic Apps or Azure Functions when security alerts are generated. Set up email notifications for Critical and High severity alerts.

```powershell
# Create workflow automation for high severity alerts
az security automation create \
  --name high-severity-alert-automation \
  --resource-group security-rg \
  --scopes '[{"description": "Production subscription", "scopePath": "/subscriptions/<sub-id>"}]' \
  --sources '[{
    "eventSource": "Alerts",
    "ruleSets": [{"rules": [{"propertyJPath": "Severity", "propertyType": "String", "expectedValue": "High", "operator": "Equals"}]}]
  }]' \
  --actions '[{
    "logicAppResourceId": "/subscriptions/<sub-id>/resourceGroups/security-rg/providers/Microsoft.Logic/workflows/alert-handler",
    "actionType": "LogicApp"
  }]'

# Configure email notifications
az security contact create \
  --name default \
  --email "soc-team@company.com" \
  --alert-notifications "on" \
  --alerts-to-admins "on"
```

### Step 6: Enable Cloud Security Graph and Attack Path Analysis

Use the cloud security graph to visualize attack paths that adversaries could exploit to reach critical assets. Prioritize remediation based on actual exploitability rather than individual finding severity.

```
# Query attack paths via Resource Graph
az graph query -q "
  securityresources
  | where type == 'microsoft.security/attackpaths'
  | extend riskLevel = properties.riskLevel
  | extend entryPoint = properties.attackPathDisplayName
  | where riskLevel == 'Critical'
  | project entryPoint, riskLevel, properties.description
  | limit 20
"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Secure Score | A numerical measure of an organization's security posture based on the percentage of implemented security recommendations, scored per subscription and aggregated at the management group level |
| Cloud Security Graph | A graph database mapping relationships between cloud resources, identities, network exposure, and vulnerabilities to identify exploitable attack paths |
| Attack Path Analysis | Visualization of multi-step attack chains an adversary could follow from an entry point to a high-value target, prioritized by real-world exploitability |
| Just-In-Time Access | Security control that blocks management ports by default and opens them temporarily upon approved request, reducing the VM attack surface |
| Adaptive Application Controls | Machine-learning-based allowlisting that recommends which applications should run on VMs and alerts on deviations |
| Defender CSPM | Enhanced cloud security posture management plan providing agentless scanning, attack path analysis, and cloud security graph capabilities |
| Security Connector | Integration point connecting AWS or GCP environments to Defender for Cloud for multi-cloud posture management |

## Tools & Systems

- **Microsoft Defender for Cloud**: Core CNAPP platform providing CSPM, CWP, and threat protection across Azure, AWS, and GCP
- **Azure Resource Graph**: Query engine for exploring cloud security graph data and attack paths at scale
- **Azure Logic Apps**: Workflow automation platform for building remediation playbooks triggered by Defender alerts
- **Microsoft Defender Portal**: Unified security operations console integrating Defender for Cloud with XDR, Sentinel, and threat intelligence
- **Azure Policy**: Governance engine for enforcing Defender for Cloud recommendations as compliance requirements

## Common Scenarios

### Scenario: Internet-Exposed SQL Server with Known Vulnerability

**Context**: Defender for Cloud identifies an Azure SQL Server with a public endpoint, an unpatched critical CVE, and a service principal with database owner permissions that also has access to a Key Vault containing production encryption keys.

**Approach**:
1. Review the attack path in the cloud security graph showing: Internet -> SQL Server (CVE) -> Service Principal -> Key Vault
2. Immediately restrict the SQL Server firewall to private endpoints only
3. Apply the SQL Server security patch through Azure Update Management
4. Rotate the service principal credentials and scope its permissions to only the required database operations
5. Add a Key Vault access policy requiring the service principal to authenticate via managed identity rather than secret-based credentials
6. Verify the attack path is resolved in Defender CSPM within 24 hours

**Pitfalls**: Focusing on the SQL vulnerability alone misses the lateral movement path to Key Vault. Restricting the endpoint without updating application connection strings causes an outage.

## Output Format

```
Microsoft Defender for Cloud Security Report
=============================================
Tenant: acme-corp.onmicrosoft.com
Subscriptions Monitored: 12
Report Date: 2025-02-23

SECURE SCORE: 72/100

DEFENDER PLANS STATUS:
  Servers (P2):     ENABLED - 156 VMs covered
  Containers:       ENABLED - 8 AKS clusters covered
  Storage:          ENABLED - 342 storage accounts, malware scanning active
  Databases:        ENABLED - 23 SQL servers, 5 Cosmos DB accounts
  Key Vault:        ENABLED - 18 vaults monitored
  AWS Connector:    ENABLED - 3 accounts connected
  GCP Connector:    ENABLED - 2 projects connected

CRITICAL ATTACK PATHS:
  [AP-001] Internet -> VM (RDP open) -> Managed Identity -> Storage (PII data)
    Risk: Critical | Affected Resources: 3 | Remediation: Close RDP, restrict MI scope
  [AP-002] Internet -> App Service (SQLi vuln) -> SQL DB -> Service Principal -> Key Vault
    Risk: Critical | Affected Resources: 5 | Remediation: Patch app, private endpoint

ALERT SUMMARY (Last 30 Days):
  Critical: 5 | High: 23 | Medium: 67 | Low: 134
  Top Alert Types:
    - Suspicious login activity (18)
    - Malware detected in storage (7)
    - Anomalous resource deployment (12)
```
