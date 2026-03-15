# API Reference: Implementing Azure Defender for Cloud

## Libraries

### azure-mgmt-security
- **Install**: `pip install azure-mgmt-security azure-identity`
- **Docs**: https://learn.microsoft.com/en-us/python/api/azure-mgmt-security/

### azure-identity
- **Install**: `pip install azure-identity`
- `DefaultAzureCredential()` -- Auto-detect credentials (CLI, managed identity, env vars)

## SecurityCenter Client Methods

| Method | Description |
|--------|-------------|
| `pricings.list()` | List Defender plan pricing tiers |
| `pricings.update()` | Enable/disable a Defender plan |
| `secure_scores.list()` | Get current secure score |
| `secure_score_controls.list()` | List score controls with health counts |
| `assessments.list(scope)` | List security assessments for a scope |
| `assessments.get(resource_id, name)` | Get specific assessment details |
| `alerts.list()` | List all security alerts |
| `alerts.update_subscription_level_state_to_dismiss()` | Dismiss an alert |
| `regulatory_compliance_standards.list()` | List compliance standards |
| `regulatory_compliance_controls.list()` | Controls per standard |
| `jit_network_access_policies.list()` | JIT VM access policies |
| `jit_network_access_policies.initiate()` | Request JIT access |
| `auto_provisioning_settings.list()` | Auto-provisioning status |

## Defender Plan Names

| Plan | `name` Parameter |
|------|-----------------|
| CSPM | `CloudPosture` |
| Servers | `VirtualMachines` |
| Containers | `Containers` |
| Storage | `StorageAccounts` |
| SQL | `SqlServers` |
| Key Vault | `KeyVaults` |
| App Service | `AppServices` |
| DNS | `Dns` |

## Severity Levels
- `High`, `Medium`, `Low`

## Compliance Standards
- CIS Azure 2.0: `CIS-Azure-2.0`
- PCI DSS 4.0: `PCI-DSS-4.0`
- NIST 800-53 r5: `NIST-SP-800-53-R5`
- SOC 2: `SOC-2`

## Azure CLI Equivalents
- `az security pricing create --name VirtualMachines --tier standard`
- `az security assessment list`
- `az security alert list`
- `az security secure-score list`

## External References
- Defender for Cloud Docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/
- Python SDK Reference: https://learn.microsoft.com/en-us/python/api/azure-mgmt-security/
- REST API: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/
