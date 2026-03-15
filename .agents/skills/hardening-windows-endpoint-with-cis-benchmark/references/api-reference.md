# API Reference: Windows CIS Benchmark Hardening

## CIS Benchmark Sections

| Section | Topic |
|---------|-------|
| 1 | Account Policies (passwords, lockout) |
| 2 | Local Policies (audit, user rights, security options) |
| 9 | Windows Firewall |
| 17 | Advanced Audit Policy |
| 18 | Administrative Templates |
| 19 | User Configuration |

## PowerShell Commands

### Password Policy
```powershell
net accounts
# or
Get-ADDefaultDomainPasswordPolicy
```

### Audit Policy
```powershell
auditpol /get /category:*
```

### Firewall Status
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
```

### Registry Checks
```powershell
Get-ItemProperty -Path 'HKLM:\...' -Name 'ValueName'
```

## Key Registry Settings

| Path | Value | Recommended |
|------|-------|-------------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` | DWORD | 5 (NTLMv2 only) |
| `HKLM\...\Policies\System\EnableLUA` | DWORD | 1 (UAC enabled) |
| `HKLM\...\LanManServer\Parameters\SMB1` | DWORD | 0 (disabled) |
| `HKLM\...\Policies\System\ConsentPromptBehaviorAdmin` | DWORD | 2 |

## Password Policy Settings

| Setting | CIS Recommendation |
|---------|-------------------|
| Minimum length | >= 14 characters |
| Maximum age | <= 365 days |
| Minimum age | >= 1 day |
| Complexity | Enabled |
| Lockout threshold | <= 5 attempts |
| Lockout duration | >= 15 minutes |

## Advanced Audit Policy

| Subcategory | Recommended |
|-------------|-------------|
| Credential Validation | Success and Failure |
| Logon/Logoff | Success and Failure |
| Account Management | Success |
| Process Creation | Success |
| Policy Change | Success |

## GPO Export and Analysis

### Export GPO
```powershell
gpresult /H gpo-report.html
```

### Secedit Export
```cmd
secedit /export /cfg security-config.inf
```

## Automated Tools

### Microsoft Security Compliance Toolkit
```powershell
# Download from Microsoft
# Includes GPO baselines and LGPO tool
LGPO.exe /g .\GPO-Backup
```

### CIS-CAT
```bash
# CIS Configuration Assessment Tool
cis-cat.bat -b benchmark.xml -p "CIS Windows 11 Enterprise"
```

## Windows Optional Features

### Check SMBv1
```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### Disable SMBv1
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```
