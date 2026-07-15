<#
.SYNOPSIS
    Deploys Active Directory honeytoken accounts for deception-based detection.

.DESCRIPTION
    Creates decoy user accounts with Service Principal Names (SPNs) to detect
    Kerberoasting, credential theft, and lateral movement attempts. Honeytokens
    have no legitimate use; any access triggers high-confidence security alerts.

.PARAMETER Domain
    Target domain (e.g., corp.local)

.PARAMETER OUPath
    Organizational Unit path for honeytoken accounts

.PARAMETER AddToDomainAdmins
    Add honeytokens to Domain Admins group (high visibility)

.PARAMETER Quantity
    Number of honeytokens to deploy (default: 5)

.EXAMPLE
    .\Deploy-Honeytokens.ps1 -Domain "corp.local" -OUPath "OU=Service Accounts,DC=corp,DC=local"

.EXAMPLE
    .\Deploy-Honeytokens.ps1 -AddToDomainAdmins -Quantity 10

.NOTES
    Author: dakshverma23
    Version: 1.0
    Requires: Active Directory PowerShell Module, Domain Admin privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain = "corp.local",
    
    [Parameter(Mandatory=$false)]
    [string]$OUPath = "OU=Service Accounts,DC=corp,DC=local",
    
    [Parameter(Mandatory=$false)]
    [switch]$AddToDomainAdmins,
    
    [Parameter(Mandatory=$false)]
    [int]$Quantity = 5
)

# Import Active Directory module
Import-Module ActiveDirectory -ErrorAction Stop

# Honeytoken templates
$HoneytokenTemplates = @(
    @{
        NamePrefix = "svc-sql"
        Suffix = @("backup", "reporting", "etl", "replication", "monitoring")
        SPNType = "MSSQLSvc"
        HostPattern = "sql{0}.{1}:1433"
        Description = "SQL Server {0} service account"
        Groups = @("Backup Operators")
    },
    @{
        NamePrefix = "svc-vmware"
        Suffix = @("mgmt", "backup", "vmotion", "ha", "drs")
        SPNType = "HTTP"
        HostPattern = "vmware-{0}.{1}"
        Description = "VMware {0} management service"
        Groups = @("Server Operators")
    },
    @{
        NamePrefix = "svc-backup"
        Suffix = @("exec", "agent", "master", "replica", "catalog")
        SPNType = "BackupExec"
        HostPattern = "backup-{0}.{1}"
        Description = "Backup Exec {0} service account"
        Groups = @("Backup Operators")
    },
    @{
        NamePrefix = "adm"
        Suffix = @("helpdesk-t2", "tier1-backup", "servicedesk", "desktop-support", "dba-readonly")
        SPNType = $null
        HostPattern = $null
        Description = "{0} administrator account"
        Groups = @("Account Operators")
    },
    @{
        NamePrefix = "svc-web"
        Suffix = @("apppool", "iis-worker", "api-backend", "frontend", "cdn")
        SPNType = "HTTP"
        HostPattern = "web-{0}.{1}"
        Description = "Web application {0} service account"
        Groups = @()
    }
)

function Get-SecurePassword {
    # Generate cryptographically secure password
    $Length = 24
    $Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $Bytes = New-Object byte[]($Length)
    $RNG.GetBytes($Bytes)
    
    $Password = -join ($Bytes | ForEach-Object { $Chars[$_ % $Chars.Length] })
    return $Password
}

function New-Honeytoken {
    param(
        [string]$Name,
        [string]$SPN,
        [string]$Description,
        [string[]]$Groups,
        [string]$OUPath,
        [string]$Domain
    )
    
    try {
        # Check if user already exists
        $Existing = Get-ADUser -Filter {SamAccountName -eq $Name} -ErrorAction SilentlyContinue
        if ($Existing) {
            Write-Warning "User $Name already exists, skipping"
            return $false
        }
        
        # Generate secure password
        $Password = Get-SecurePassword
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        
        # Create user
        New-ADUser -Name $Name `
                   -SamAccountName $Name `
                   -UserPrincipalName "$Name@$Domain" `
                   -Description $Description `
                   -Enabled $true `
                   -PasswordNeverExpires $true `
                   -CannotChangePassword $true `
                   -AccountPassword $SecurePassword `
                   -Path $OUPath `
                   -ErrorAction Stop
        
        Write-Host "    ✓ User created: $Name" -ForegroundColor Green
        
        # Set SPN if specified
        if ($SPN) {
            Set-ADUser -Identity $Name -ServicePrincipalNames @{Add=$SPN} -ErrorAction Stop
            Write-Host "    ✓ SPN configured: $SPN" -ForegroundColor Green
        }
        
        # Add to groups
        foreach ($Group in $Groups) {
            try {
                Add-ADGroupMember -Identity $Group -Members $Name -ErrorAction Stop
                Write-Host "    ✓ Added to group: $Group" -ForegroundColor Green
            } catch {
                Write-Warning "    Failed to add to group $Group : $_"
            }
        }
        
        return $true
        
    } catch {
        Write-Error "Failed to create honeytoken $Name : $_"
        return $false
    }
}

# Main execution
Write-Host "`n═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   Active Directory Honeytoken Deployment" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Domain:               $Domain"
Write-Host "  OU Path:              $OUPath"
Write-Host "  Add to Domain Admins: $AddToDomainAdmins"
Write-Host "  Quantity:             $Quantity`n"

# Validate OU exists
try {
    $null = Get-ADOrganizationalUnit -Identity $OUPath -ErrorAction Stop
} catch {
    Write-Error "OU path does not exist: $OUPath"
    exit 1
}

# Generate honeytokens
$DeployedCount = 0
$HoneytokensToCreate = @()

for ($i = 0; $i -lt $Quantity; $i++) {
    $Template = $HoneytokenTemplates[$i % $HoneytokenTemplates.Count]
    $SuffixIndex = $i % $Template.Suffix.Count
    $Suffix = $Template.Suffix[$SuffixIndex]
    
    $Name = "$($Template.NamePrefix)-$Suffix"
    
    # Generate SPN if applicable
    if ($Template.SPNType) {
        $Host = $Template.HostPattern -f $Suffix, $Domain
        $SPN = "$($Template.SPNType)/$Host"
    } else {
        $SPN = $null
    }
    
    $Description = $Template.Description -f $Suffix
    
    # Add to Domain Admins if switch enabled
    $Groups = $Template.Groups
    if ($AddToDomainAdmins) {
        $Groups += "Domain Admins"
    }
    
    $HoneytokensToCreate += @{
        Name = $Name
        SPN = $SPN
        Description = $Description
        Groups = $Groups
    }
}

Write-Host "Creating $($HoneytokensToCreate.Count) honeytoken(s)...`n" -ForegroundColor Yellow

foreach ($Token in $HoneytokensToCreate) {
    Write-Host "[*] Deploying: $($Token.Name)" -ForegroundColor Cyan
    
    $Success = New-Honeytoken -Name $Token.Name `
                              -SPN $Token.SPN `
                              -Description $Token.Description `
                              -Groups $Token.Groups `
                              -OUPath $OUPath `
                              -Domain $Domain
    
    if ($Success) {
        $DeployedCount++
    }
    
    Write-Host ""
}

# Summary
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   Deployment Summary" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Successfully deployed: $DeployedCount/$($HoneytokensToCreate.Count) honeytokens" -ForegroundColor Green

if ($DeployedCount -gt 0) {
    Write-Host "`n⚠️  NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  1. Configure SIEM alerting for Event IDs 4768, 4769, 4776, 4624"
    Write-Host "  2. Test detection with Rubeus or Impacket GetUserSPNs.py"
    Write-Host "  3. Document honeytoken account list (restricted access)"
    Write-Host "  4. Schedule monthly verification audit"
    Write-Host "  5. Update SOC runbook with honeytoken response procedures`n"
}

Write-Host "═══════════════════════════════════════════`n" -ForegroundColor Cyan
