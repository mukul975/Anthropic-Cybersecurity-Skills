# API Reference: Securing Azure with Microsoft Defender

## Azure CLI Security Commands

### Defender Plans
```bash
az security pricing list                    # List all Defender plan statuses
az security pricing create --name <plan> --tier Standard  # Enable a plan
```

### Secure Score
```bash
az security secure-score list               # Get current secure score
az security secure-score-controls list      # List score control categories
```

### Assessments
```bash
az security assessment list                 # List all security assessments
az security assessment show --name <id>     # Get assessment details
```

### Alerts
```bash
az security alert list                      # List active security alerts
az security alert update --name <id> --status Dismissed  # Update alert status
```

### Security Contacts
```bash
az security contact create --name default --email soc@company.com --alert-notifications on
```

## Azure Resource Graph (Attack Paths)
```bash
az graph query -q "securityresources | where type == 'microsoft.security/attackpaths'"
```

## Defender Plan Names
| Plan Name | Protection Scope |
|-----------|-----------------|
| `VirtualMachines` | Servers (P1/P2) |
| `Containers` | AKS, ACR, container runtime |
| `StorageAccounts` | Blob, File, Queue storage |
| `SqlServers` | Azure SQL Database |
| `CosmosDbs` | Cosmos DB accounts |
| `KeyVaults` | Key Vault operations |
| `AppServices` | App Service/Functions |
| `Dns` | DNS layer protection |
| `Arm` | Azure Resource Manager |

## JIT VM Access
```bash
az security jit-policy create --resource-group <rg> --location <loc> --name default \
  --virtual-machines '[{"id": "<vm-resource-id>", "ports": [{"number": 22, ...}]}]'
```

## References
- Defender for Cloud docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/
- Azure CLI security reference: https://learn.microsoft.com/en-us/cli/azure/security
- Secure Score overview: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls
