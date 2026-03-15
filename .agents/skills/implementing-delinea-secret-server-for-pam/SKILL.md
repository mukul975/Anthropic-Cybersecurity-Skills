---
name: implementing-delinea-secret-server-for-pam
description: >
  Implements Delinea Secret Server for privileged access management (PAM) including
  secret vault configuration, role-based access policies, automated password rotation,
  session recording, and integration with Active Directory and cloud platforms.
  Activates for requests involving PAM deployment, privileged credential vaulting,
  secret server administration, or password rotation automation.
domain: cybersecurity
subdomain: identity-access-management
tags: [PAM, Delinea, Secret-Server, privileged-access, password-vault, credential-management]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Delinea Secret Server for PAM

## When to Use

- Organization needs centralized privileged credential management across hybrid infrastructure
- Compliance requirements mandate privileged access controls (SOX, PCI-DSS, HIPAA, NIST 800-53)
- Service accounts and shared credentials are stored in spreadsheets or plaintext files
- Need to implement automated password rotation for privileged accounts
- Require session recording and keystroke logging for privileged user activity
- Migrating from manual PAM processes to an enterprise vault solution

**Do not use** for standard end-user password management; Delinea Secret Server is designed for privileged and shared account credential management requiring enterprise-grade controls.

## Prerequisites

- Delinea Secret Server license (On-Premises or Cloud)
- Windows Server 2019/2022 for on-premises deployment with IIS and SQL Server
- Active Directory service account with read permissions for discovery
- SSL/TLS certificate for web interface encryption
- Network connectivity to target systems for password rotation
- PowerShell 5.1+ for automation scripts

## Workflow

### Step 1: Deploy Secret Server Infrastructure

Install and configure the Secret Server application server:

```powershell
# Pre-installation checks for on-premises deployment
# Verify IIS is installed with required features
Import-Module ServerManager
Install-WindowsFeature Web-Server, Web-Asp-Net45, Web-Windows-Auth, Web-Mgmt-Console

# Verify SQL Server connectivity
$sqlConn = New-Object System.Data.SqlClient.SqlConnection
$sqlConn.ConnectionString = "Server=sql01.corp.local;Database=master;Integrated Security=True"
$sqlConn.Open()
Write-Host "SQL Server connection successful: $($sqlConn.ServerVersion)"
$sqlConn.Close()

# Create Secret Server database
Invoke-Sqlcmd -ServerInstance "sql01.corp.local" -Query @"
CREATE DATABASE SecretServer
GO
ALTER DATABASE SecretServer SET RECOVERY FULL
GO
"@

# Download and run Secret Server installer
# Navigate to https://thy.center/ss/link/SSDownload for latest version
# Run setup.exe and follow the installation wizard

# Post-installation: Configure application pool
Import-Module WebAdministration
Set-ItemProperty "IIS:\AppPools\SecretServer" -Name processModel.identityType -Value SpecificUser
Set-ItemProperty "IIS:\AppPools\SecretServer" -Name processModel.userName -Value "CORP\svc-secretserver"
```

### Step 2: Configure Secret Templates and Folder Structure

Define secret templates and organize the vault hierarchy:

```powershell
# Connect to Secret Server API
$baseUrl = "https://pam.corp.local/SecretServer"
$creds = @{
    username = "ss-admin"
    password = $env:SS_ADMIN_PASSWORD
    grant_type = "password"
}
$token = (Invoke-RestMethod "$baseUrl/oauth2/token" -Method POST -Body $creds).access_token
$headers = @{ Authorization = "Bearer $token" }

# Create folder structure for organizing secrets
$folders = @(
    @{ folderName = "Windows Servers"; parentFolderId = -1; inheritPermissions = $false },
    @{ folderName = "Linux Servers"; parentFolderId = -1; inheritPermissions = $false },
    @{ folderName = "Network Devices"; parentFolderId = -1; inheritPermissions = $false },
    @{ folderName = "Cloud Accounts"; parentFolderId = -1; inheritPermissions = $false },
    @{ folderName = "Service Accounts"; parentFolderId = -1; inheritPermissions = $false },
    @{ folderName = "Database Accounts"; parentFolderId = -1; inheritPermissions = $false }
)

foreach ($folder in $folders) {
    Invoke-RestMethod "$baseUrl/api/v1/folders" -Method POST -Headers $headers `
        -ContentType "application/json" -Body ($folder | ConvertTo-Json)
}

# Create custom secret template for database credentials
$template = @{
    name = "Database Credential"
    fields = @(
        @{ name = "Server"; isRequired = $true; fieldType = "Text" },
        @{ name = "Port"; isRequired = $true; fieldType = "Text" },
        @{ name = "Database"; isRequired = $true; fieldType = "Text" },
        @{ name = "Username"; isRequired = $true; fieldType = "Text" },
        @{ name = "Password"; isRequired = $true; fieldType = "Password" },
        @{ name = "Connection String"; isRequired = $false; fieldType = "Notes" }
    )
}
Invoke-RestMethod "$baseUrl/api/v1/secret-templates" -Method POST -Headers $headers `
    -ContentType "application/json" -Body ($template | ConvertTo-Json -Depth 3)
```

### Step 3: Configure Discovery and Account Onboarding

Set up automated discovery of privileged accounts across the environment:

```powershell
# Configure Active Directory discovery source
$adDiscovery = @{
    name = "Corporate AD Discovery"
    discoverySourceType = "ActiveDirectory"
    active = $true
    settings = @{
        domainName = "corp.local"
        friendlyName = "Corporate Domain"
        discoveryAccountId = 12  # Service account secret ID
        ouFilters = @(
            "OU=Servers,DC=corp,DC=local",
            "OU=Workstations,DC=corp,DC=local"
        )
    }
    scanInterval = 86400  # 24 hours
}
Invoke-RestMethod "$baseUrl/api/v1/discovery" -Method POST -Headers $headers `
    -ContentType "application/json" -Body ($adDiscovery | ConvertTo-Json -Depth 3)

# Configure local account discovery for Windows servers
$localDiscovery = @{
    name = "Windows Local Account Discovery"
    discoverySourceType = "Machine"
    active = $true
    settings = @{
        machineType = "Windows"
        accountScanTemplate = "Windows Local Account"
        dependencyScanTemplate = "Windows Service"
    }
}
Invoke-RestMethod "$baseUrl/api/v1/discovery" -Method POST -Headers $headers `
    -ContentType "application/json" -Body ($localDiscovery | ConvertTo-Json -Depth 3)

# Import discovered accounts as secrets
# After discovery runs, review and import found accounts
$discoveredAccounts = Invoke-RestMethod "$baseUrl/api/v1/discovery/status" -Headers $headers
Write-Host "Discovered $($discoveredAccounts.totalAccounts) accounts"
Write-Host "  - Domain Admins: $($discoveredAccounts.domainAdmins)"
Write-Host "  - Local Admins: $($discoveredAccounts.localAdmins)"
Write-Host "  - Service Accounts: $($discoveredAccounts.serviceAccounts)"
```

### Step 4: Implement Password Rotation Policies

Configure automated password rotation with complexity requirements:

```powershell
# Create password rotation policy
$rotationPolicy = @{
    name = "High-Security 30-Day Rotation"
    rotationIntervalDays = 30
    passwordRequirements = @{
        minimumLength = 24
        maximumLength = 32
        requireUpperCase = $true
        requireLowerCase = $true
        requireNumbers = $true
        requireSymbols = $true
        allowedSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    }
    rotationType = "AutoChange"
    autoChangeSchedule = @{
        changeType = "RecurringSchedule"
        recurrenceType = "Monthly"
        dayOfMonth = 1
        startTime = "02:00"
    }
}
Invoke-RestMethod "$baseUrl/api/v1/remote-password-changing/configuration" -Method POST `
    -Headers $headers -ContentType "application/json" -Body ($rotationPolicy | ConvertTo-Json -Depth 4)

# Configure Remote Password Changing (RPC) for Windows accounts
$rpcConfig = @{
    secretId = 100  # Target secret
    autoChangeEnabled = $true
    autoChangeNextPassword = $true
    privilegedAccountSecretId = 50  # Account used to perform the change
    changePasswordUsing = "PrivilegedAccount"
}
Invoke-RestMethod "$baseUrl/api/v1/secrets/100/remote-password-changing" -Method PUT `
    -Headers $headers -ContentType "application/json" -Body ($rpcConfig | ConvertTo-Json)

# Configure heartbeat monitoring to verify credential validity
$heartbeat = @{
    enabled = $true
    intervalMinutes = 60
    onFailure = "SendAlert"
    alertEmailGroupId = 5
}
Invoke-RestMethod "$baseUrl/api/v1/secrets/100/heartbeat" -Method PUT `
    -Headers $headers -ContentType "application/json" -Body ($heartbeat | ConvertTo-Json)
```

### Step 5: Configure Session Recording and Monitoring

Enable session recording for privileged access sessions:

```powershell
# Enable session recording policy
$sessionPolicy = @{
    name = "Full Recording Policy"
    recordSessions = $true
    recordKeystrokes = $true
    recordApplications = $true
    maxSessionDurationMinutes = 480
    requireComment = $true
    requireTicketNumber = $true
    ticketSystemId = 1  # ServiceNow integration
    settings = @{
        videoCodec = "H264"
        videoQuality = "High"
        captureInterval = 1000  # milliseconds
        storageLocation = "\\\\fileserver\\SSRecordings"
        retentionDays = 365
    }
}
Invoke-RestMethod "$baseUrl/api/v1/secret-policy" -Method POST -Headers $headers `
    -ContentType "application/json" -Body ($sessionPolicy | ConvertTo-Json -Depth 3)

# Configure session launcher for RDP sessions
$rdpLauncher = @{
    launcherType = "RDP"
    enableRecording = $true
    enableDualControl = $true
    approverGroupId = 10  # Security team group
    connectAsSecretId = 100
    settings = @{
        useSSL = $true
        restrictedEndpoints = @("192.168.1.0/24")
        inactivityTimeout = 30  # minutes
    }
}
Invoke-RestMethod "$baseUrl/api/v1/launchers" -Method POST -Headers $headers `
    -ContentType "application/json" -Body ($rdpLauncher | ConvertTo-Json -Depth 3)

# Configure dual control / approval workflow
$approvalWorkflow = @{
    name = "Tier-0 Account Approval"
    requireApproval = $true
    approvers = @(
        @{ groupId = 10; requiredApprovals = 1 }
    )
    accessRequestExpirationMinutes = 60
    notifyOnApproval = $true
    notifyOnDenial = $true
}
```

### Step 6: Integrate with SIEM and Compliance Reporting

Connect Secret Server events to security monitoring:

```powershell
# Configure Syslog forwarding to SIEM
$syslogConfig = @{
    enabled = $true
    syslogServer = "siem.corp.local"
    port = 514
    protocol = "TLS"
    facility = "Auth"
    severity = "Informational"
    events = @(
        "SecretView", "SecretEdit", "SecretCreate", "SecretDelete",
        "PasswordChange", "PasswordChangeFailure",
        "SessionStart", "SessionEnd",
        "LoginFailure", "LoginSuccess",
        "PermissionChange", "ApprovalRequest"
    )
}
Invoke-RestMethod "$baseUrl/api/v1/configuration/syslog" -Method PUT -Headers $headers `
    -ContentType "application/json" -Body ($syslogConfig | ConvertTo-Json -Depth 2)

# Generate compliance report
$report = @{
    reportType = "PasswordCompliance"
    dateRange = @{
        startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
        endDate = (Get-Date).ToString("yyyy-MM-dd")
    }
    filters = @{
        folderIds = @(1, 2, 3, 4, 5, 6)
        includeSubFolders = $true
    }
}
$reportResult = Invoke-RestMethod "$baseUrl/api/v1/reports" -Method POST -Headers $headers `
    -ContentType "application/json" -Body ($report | ConvertTo-Json -Depth 3)

# Display compliance summary
Write-Host "PAM Compliance Report"
Write-Host "====================="
Write-Host "Total Secrets:         $($reportResult.totalSecrets)"
Write-Host "Rotation Compliant:    $($reportResult.rotationCompliant) ($($reportResult.rotationCompliancePct)%)"
Write-Host "Heartbeat Healthy:     $($reportResult.heartbeatHealthy) ($($reportResult.heartbeatHealthyPct)%)"
Write-Host "Password Age > 90d:    $($reportResult.passwordAgeViolations)"
Write-Host "Orphaned Accounts:     $($reportResult.orphanedAccounts)"
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Privileged Access Management (PAM)** | Security framework for controlling, monitoring, and auditing elevated access to critical systems and data through credential vaulting and session management |
| **Secret** | A stored credential or sensitive data item in the vault, including passwords, SSH keys, API tokens, and certificates |
| **Remote Password Changing (RPC)** | Automated mechanism that connects to target systems to rotate passwords according to defined policies without manual intervention |
| **Heartbeat** | Periodic check that validates stored credentials against target systems to ensure vault contents remain synchronized and functional |
| **Dual Control** | Security mechanism requiring approval from a second authorized user before granting access to highly sensitive secrets |
| **Discovery** | Automated scanning of infrastructure to identify privileged accounts, service accounts, and dependencies across Active Directory, servers, and network devices |
| **Session Recording** | Capture of complete privileged session activity including video, keystrokes, and application usage for audit and forensic review |

## Tools & Systems

- **Delinea Secret Server**: Enterprise PAM solution providing credential vaulting, password rotation, session recording, and privileged access workflows
- **Delinea Distributed Engine**: Agent deployed in network segments to enable password changing and discovery across firewalled environments
- **Secret Server REST API**: RESTful API for programmatic secret management, automation, and integration with DevOps pipelines
- **Secret Server SDK**: .NET and PowerShell SDKs for application-level integration with Secret Server vault

## Common Scenarios

### Scenario: Migrating Shared Admin Credentials to Vault

**Context**: An organization stores 500+ shared administrator credentials in Excel spreadsheets and password-protected documents. Auditors flagged this as a critical finding requiring remediation within 90 days.

**Approach**:
1. Deploy Secret Server with SQL Server backend and configure HTTPS access
2. Design folder hierarchy mirroring the organizational structure (by department, system type, environment)
3. Create secret templates matching the credential types in use (Windows, Linux, database, network device)
4. Import existing credentials via CSV import or PowerShell bulk creation
5. Configure discovery to find undocumented privileged accounts across AD and local systems
6. Enable Remote Password Changing starting with non-production accounts to validate rotation
7. Roll out session launchers to replace direct RDP/SSH connections
8. Gradually enable dual control for Tier-0 accounts (Domain Admins, root accounts)
9. Configure SIEM integration and compliance reporting for audit evidence

**Pitfalls**:
- Not identifying all service account dependencies before enabling password rotation (causes service outages)
- Enabling RPC for production accounts without testing in non-production first
- Setting rotation intervals too short for service accounts that require coordinated restarts
- Not configuring Distributed Engines for network segments separated by firewalls

## Output Format

```
DELINEA SECRET SERVER PAM DEPLOYMENT REPORT
=============================================
Environment:       Hybrid (On-Premises + Azure)
Version:           Secret Server 11.6
Deployment Mode:   On-Premises (High Availability)

VAULT STATISTICS
Total Secrets:           1,247
  Windows Credentials:   523
  Linux/SSH Keys:        312
  Database Accounts:     198
  Network Devices:       87
  Cloud API Keys:        127

PASSWORD ROTATION STATUS
Auto-Change Enabled:     1,089 / 1,247 (87.3%)
Rotation Compliant:      1,056 / 1,089 (97.0%)
Heartbeat Healthy:       1,198 / 1,247 (96.1%)
Failed Rotations (30d):  12

SESSION MANAGEMENT
Active Sessions:         23
Recorded Sessions (30d): 4,567
Average Session Length:  22 minutes
Approval Requests (30d): 189 (174 approved, 15 denied)

DISCOVERY RESULTS
Scanned Systems:         2,340
Discovered Accounts:     3,891
Onboarded to Vault:      1,247 (32.1%)
Pending Review:          892

COMPLIANCE
SOX Controls Met:        12/12
PCI-DSS Requirements:    8/8
Password Age Violations: 3 (remediation in progress)
```
