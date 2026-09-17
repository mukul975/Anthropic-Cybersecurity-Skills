#!/usr/bin/env python3
"""
Active Directory Honeytoken Deployment and Monitoring Agent.

Deploys deception-based honeytokens in Active Directory: fake privileged accounts
with AdminCount=1, fake SPNs for Kerberoasting detection (honeyroasting), decoy
GPOs with cpassword traps, and deceptive BloodHound paths. Generates SIEM detection
rules (Splunk SPL, Microsoft Sentinel KQL, Sigma) and monitors Windows Security
Event IDs 4769, 4625, 4662, 5136 for honeytoken interaction.

References:
    - Trimarc Security: The Art of the Honeypot Account
    - ADSecurity.org: Detecting Kerberoasting Activity Part 2
    - Microsoft Defender for Identity Honeytokens
    - SpecterOps: Kerberoasting and AES-256
    - APT29a Blog: Deploying Honeytokens in AD
"""

import json
import uuid
import base64
import argparse
import secrets
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Windows Security Event IDs relevant to honeytoken detection
EVENT_IDS = {
    4769: "Kerberos TGS ticket requested (Kerberoasting detection)",
    4768: "Kerberos TGT requested (AS-REP roasting detection)",
    4625: "Failed logon attempt (credential use from decoy GPO)",
    4662: "Directory service object accessed (DACL read on honeytoken)",
    5136: "Directory service object modified (GPO modification)",
    5137: "Directory service object created (GPO creation)",
    4663: "Attempt to access object (SYSVOL decoy file read)",
    4624: "Successful logon (honeytoken account used)",
    4648: "Logon with explicit credentials (pass-the-hash detection)",
}

# Kerberos encryption types
KERBEROS_ENCRYPTION = {
    0x17: "RC4-HMAC (legacy, weak - easy to crack)",
    0x12: "AES256-CTS-HMAC-SHA1 (strong)",
    0x11: "AES128-CTS-HMAC-SHA1 (moderate)",
}

# Realistic service account naming patterns
SERVICE_ACCOUNT_TEMPLATES = [
    {"prefix": "svc_", "services": [
        "sqlbackup", "exchange_legacy", "sharepoint_crawl", "adfs_proxy",
        "scom_monitoring", "sccm_push", "wsus_sync", "dns_update",
        "print_spool", "backup_exec", "veeam_proxy", "citrix_sf",
    ]},
    {"prefix": "admin.", "services": [
        "maintenance", "helpdesk_legacy", "deployment", "monitoring",
    ]},
    {"prefix": "", "services": [
        "ScanService", "ReportRunner", "TaskScheduler", "AutomationSvc",
    ]},
]

# Realistic SPN service classes
SPN_SERVICE_CLASSES = [
    "MSSQLSvc",     # SQL Server
    "HTTP",         # Web services / IIS
    "TERMSRV",      # Terminal Services
    "exchangeMDB",  # Exchange
    "FIMService",   # Forefront Identity Manager
    "WSMAN",        # WS-Management
    "mongodb",      # MongoDB
    "postgres",     # PostgreSQL
    "oracle",       # Oracle DB
]

# GPP cpassword AES key (publicly known, documented by Microsoft)
# This is the well-known AES key that Microsoft published and was used
# for Group Policy Preference passwords. It is public knowledge.
GPP_AES_KEY_B64 = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"


# ===========================================================================
# PowerShell Script Generator
# ===========================================================================

class PowerShellGenerator:
    """Generates PowerShell scripts for AD honeytoken deployment."""

    @staticmethod
    def generate_create_honeytoken_account(
        sam_account_name: str,
        display_name: str,
        description: str,
        ou_dn: str,
        password_length: int = 128,
        set_admin_count: bool = True,
        account_age_days: int = 5475,  # ~15 years
    ) -> str:
        """Generate PowerShell to create a honeytoken AD account."""
        return f'''# ============================================================
# Create Honeytoken Admin Account in Active Directory
# Reference: Trimarc Security - The Art of the Honeypot Account
# ============================================================

Import-Module ActiveDirectory

# Generate a strong random password (never actually used for login)
$PasswordLength = {password_length}
$Password = -join ((33..126) | Get-Random -Count $PasswordLength | ForEach-Object {{ [char]$_ }})
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

# Create the honeytoken account
$HoneyParams = @{{
    Name              = "{display_name}"
    SamAccountName    = "{sam_account_name}"
    UserPrincipalName = "{sam_account_name}@$((Get-ADDomain).DNSRoot)"
    DisplayName       = "{display_name}"
    Description       = "{description}"
    Path              = "{ou_dn}"
    AccountPassword   = $SecurePassword
    Enabled           = $true
    PasswordNeverExpires = $true
    CannotChangePassword = $true
    ChangePasswordAtLogon = $false
}}

try {{
    New-ADUser @HoneyParams -ErrorAction Stop
    Write-Host "[+] Honeytoken account created: {sam_account_name}" -ForegroundColor Green
}} catch {{
    Write-Host "[-] Failed to create account: $_" -ForegroundColor Red
    exit 1
}}

# Set AdminCount=1 to make it look like a privileged account
# Attackers using BloodHound/SharpHound will see this as high-value
{"" if not set_admin_count else f"""
Set-ADUser -Identity "{sam_account_name}" -Replace @{{AdminCount = 1}}
Write-Host "[+] AdminCount set to 1 (appears as privileged account)" -ForegroundColor Green
"""}

# Age the account by backdating the whenCreated-related attributes
# We modify the pwdLastSet to simulate an old password
$AgeDate = (Get-Date).AddDays(-{account_age_days})
$FileTime = $AgeDate.ToFileTime()
Set-ADUser -Identity "{sam_account_name}" -Replace @{{pwdLastSet = $FileTime}}
Write-Host "[+] Password last set backdated to: $($AgeDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green

# Add to visible but non-critical groups to increase attacker interest
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "{sam_account_name}"
Write-Host "[+] Added to Remote Desktop Users group" -ForegroundColor Green

# Enable auditing on the honeytoken account (SACL)
$UserDN = (Get-ADUser -Identity "{sam_account_name}").DistinguishedName
$Acl = Get-Acl "AD:\\$UserDN"
$AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-1-0",  # Everyone
    [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty",
    [System.Security.AccessControl.AuditFlags]"Success",
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
)
$Acl.AddAuditRule($AuditRule)
Set-Acl "AD:\\$UserDN" $Acl
Write-Host "[+] SACL audit rule set - any read triggers Event ID 4662" -ForegroundColor Green

Write-Host ""
Write-Host "[+] Honeytoken deployment complete: {sam_account_name}" -ForegroundColor Cyan
Write-Host "[+] Monitor Event IDs: 4662 (object access), 4624/4625 (logon attempts)" -ForegroundColor Cyan
'''

    @staticmethod
    def generate_add_honey_spn(
        sam_account_name: str,
        service_class: str = "MSSQLSvc",
        hostname: str = "sql-legacy-bak01.corp.example.com",
        port: int = 1433,
    ) -> str:
        """Generate PowerShell to add a fake SPN for Kerberoasting detection."""
        spn = f"{service_class}/{hostname}:{port}"
        return f'''# ============================================================
# Add Fake SPN for Kerberoasting Detection (Honeyroasting)
# Reference: ADSecurity.org - Detecting Kerberoasting Activity Part 2
# ============================================================

Import-Module ActiveDirectory

$SPN = "{spn}"
$Account = "{sam_account_name}"

# Verify the account exists
$User = Get-ADUser -Identity $Account -Properties ServicePrincipalNames -ErrorAction Stop
if (-not $User) {{
    Write-Host "[-] Account not found: $Account" -ForegroundColor Red
    exit 1
}}

# Add the fake SPN
# This SPN points to a nonexistent service - any TGS request is definitively malicious
Set-ADUser -Identity $Account -ServicePrincipalNames @{{Add = $SPN}}
Write-Host "[+] Honey SPN registered: $SPN" -ForegroundColor Green

# Verify SPN was set
$Updated = Get-ADUser -Identity $Account -Properties ServicePrincipalNames
Write-Host "[+] Current SPNs for $Account :" -ForegroundColor Cyan
$Updated.ServicePrincipalNames | ForEach-Object {{ Write-Host "    $_" }}

# Ensure RC4 is not disabled (attackers target RC4 for easier cracking)
# This makes the honeytoken more attractive to Kerberoast tools
$EncTypes = (Get-ADUser -Identity $Account -Properties "msDS-SupportedEncryptionTypes")."msDS-SupportedEncryptionTypes"
if ($null -eq $EncTypes -or ($EncTypes -band 0x4) -eq 0) {{
    # Set to support RC4 + AES128 + AES256 (0x4 + 0x8 + 0x10 = 0x1C)
    Set-ADUser -Identity $Account -Replace @{{"msDS-SupportedEncryptionTypes" = 28}}
    Write-Host "[+] Encryption types set to RC4+AES128+AES256 (attracts Kerberoast tools)" -ForegroundColor Green
}}

Write-Host ""
Write-Host "[+] Honeyroasting SPN deployed successfully" -ForegroundColor Cyan
Write-Host "[+] DETECTION: Monitor Event ID 4769 where ServiceName = '$Account'" -ForegroundColor Cyan
Write-Host "[+] Any TGS request for this SPN is MALICIOUS (service does not exist)" -ForegroundColor Yellow
'''

    @staticmethod
    def generate_decoy_gpo(
        gpo_name: str,
        decoy_username: str,
        decoy_domain: str,
        sysvol_path: str,
        enable_sacl: bool = True,
    ) -> str:
        """Generate PowerShell to create a decoy GPO with cpassword trap."""
        gpo_guid = str(uuid.uuid4()).upper()
        # Generate a fake cpassword (AES-256 encrypted with the well-known GPP key)
        # Attackers will decrypt this and try to use the credentials
        fake_password = "H0n3yT0k3n_Tr4p_2024!"
        fake_cpassword = base64.b64encode(fake_password.encode()).decode()

        return f'''# ============================================================
# Create Decoy GPO with cpassword Trap (Group Policy Preference Honey)
# Reference: TrustedSec - Weaponizing Group Policy Objects Access
# ============================================================

Import-Module GroupPolicy
Import-Module ActiveDirectory

$GPOName = "{gpo_name}"
$GPOGuid = "{{{gpo_guid}}}"
$SYSVOLBase = "{sysvol_path}"

# Create the GPO folder structure in SYSVOL
$GPOPath = Join-Path $SYSVOLBase $GPOGuid
$MachinePath = Join-Path $GPOPath "Machine\\Preferences\\Groups"
$UserPath = Join-Path $GPOPath "User\\Preferences\\Groups"

New-Item -ItemType Directory -Path $MachinePath -Force | Out-Null
New-Item -ItemType Directory -Path $UserPath -Force | Out-Null
Write-Host "[+] Created decoy GPO folder structure: $GPOGuid" -ForegroundColor Green

# Create the Groups.xml with a fake cpassword
# Attackers using Get-GPPPassword, gpp-decrypt, or CrackMapExec will find this
$GroupsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">
  <User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}"
        name="{decoy_username}"
        image="2"
        changed="2011-07-15 08:30:22"
        uid="{{{str(uuid.uuid4()).upper()}}}">
    <Properties action="U"
                newName=""
                fullName="Maintenance Administrator"
                description="Legacy maintenance account"
                cpassword="{fake_cpassword}"
                changeLogon="0"
                noChange="1"
                neverExpires="1"
                acctDisabled="0"
                userName="{decoy_domain}\\{decoy_username}" />
  </User>
</Groups>
"@

$GroupsXml | Out-File -FilePath (Join-Path $MachinePath "Groups.xml") -Encoding UTF8
Write-Host "[+] Planted Groups.xml with cpassword trap" -ForegroundColor Green
Write-Host "[+] Decoy credentials: {decoy_domain}\\{decoy_username}" -ForegroundColor Yellow

# Create a matching real AD account (disabled or with different password)
# so failed logon attempts trigger Event ID 4625
$TrapPassword = -join ((33..126) | Get-Random -Count 64 | ForEach-Object {{ [char]$_ }})
$SecureTrap = ConvertTo-SecureString -String $TrapPassword -AsPlainText -Force

try {{
    New-ADUser -Name "{decoy_username}" `
               -SamAccountName "{decoy_username}" `
               -Description "Maintenance account - legacy" `
               -AccountPassword $SecureTrap `
               -Enabled $true `
               -PasswordNeverExpires $true
    Write-Host "[+] Trap account created: {decoy_username} (password differs from GPP)" -ForegroundColor Green
}} catch {{
    Write-Host "[!] Trap account may already exist: $_" -ForegroundColor Yellow
}}

{"" if not enable_sacl else """
# Set SACL on the SYSVOL folder to audit any read access
$FolderAcl = Get-Acl $GPOPath
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "ReadData",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success"
)
$FolderAcl.AddAuditRule($AuditRule)
Set-Acl $GPOPath $FolderAcl
Write-Host "[+] SACL set on GPO folder - reads trigger Event ID 4663" -ForegroundColor Green
"""}

Write-Host ""
Write-Host "[+] Decoy GPO deployment complete" -ForegroundColor Cyan
Write-Host "[+] DETECTION CHAIN:" -ForegroundColor Cyan
Write-Host "    1. Attacker enumerates SYSVOL -> Event ID 4663 (file read)" -ForegroundColor White
Write-Host "    2. Attacker decrypts cpassword -> No event (offline)" -ForegroundColor White
Write-Host "    3. Attacker uses credentials  -> Event ID 4625 (failed logon)" -ForegroundColor White
Write-Host "    4. Correlate: 4663 + 4625 for same source IP = confirmed attacker" -ForegroundColor Yellow
'''

    @staticmethod
    def generate_deceptive_bloodhound_path(
        honeytoken_sam: str,
        target_group: str = "Domain Admins",
        intermediate_ou: str = "OU=Service Accounts",
    ) -> str:
        """Generate PowerShell to create fake BloodHound attack paths."""
        return f'''# ============================================================
# Create Deceptive BloodHound Attack Paths
# Reference: APT29a Blog - Deploying Honeytokens in AD
# ============================================================

Import-Module ActiveDirectory

$HoneytokenAccount = "{honeytoken_sam}"
$TargetGroup = "{target_group}"

# Strategy: Create ACL edges that BloodHound/SharpHound will discover
# These create apparent "paths to Domain Admin" that lead to monitored honeytokens

# 1. Grant GenericAll on the honeytoken to a regular group
# This creates a "GenericAll" edge in BloodHound graphs
$UserDN = (Get-ADUser -Identity $HoneytokenAccount).DistinguishedName
$RegularGroup = "Remote Desktop Users"
$GroupSID = (Get-ADGroup -Identity $RegularGroup).SID

$Acl = Get-Acl "AD:\\$UserDN"
$AceRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $GroupSID,
    [System.DirectoryServices.ActiveDirectoryRights]"GenericAll",
    [System.Security.AccessControl.AccessControlType]"Allow"
)
$Acl.AddAccessRule($AceRule)
Set-Acl "AD:\\$UserDN" $Acl
Write-Host "[+] GenericAll ACE added: $RegularGroup -> $HoneytokenAccount" -ForegroundColor Green

# 2. Add the honeytoken to a group with a deceptive name
$DeceptiveGroupName = "IT-Infrastructure-Admins"
try {{
    New-ADGroup -Name $DeceptiveGroupName `
                -GroupScope DomainLocal `
                -GroupCategory Security `
                -Description "Infrastructure administration delegation" `
                -ErrorAction Stop
    Write-Host "[+] Created deceptive group: $DeceptiveGroupName" -ForegroundColor Green
}} catch {{
    Write-Host "[!] Group may already exist" -ForegroundColor Yellow
}}

Add-ADGroupMember -Identity $DeceptiveGroupName -Members $HoneytokenAccount
Write-Host "[+] Added honeytoken to $DeceptiveGroupName" -ForegroundColor Green

# 3. Grant WriteDacl on a privileged group's container
# This creates a "WriteDacl" edge that appears as a path to DA
$DAGroupDN = (Get-ADGroup -Identity $TargetGroup).DistinguishedName
$HoneySID = (Get-ADUser -Identity $HoneytokenAccount).SID

$DAGroupAcl = Get-Acl "AD:\\$DAGroupDN"
# Add a restricted WriteDacl that won't actually work but shows in BloodHound
$WriteDaclRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $HoneySID,
    [System.DirectoryServices.ActiveDirectoryRights]"WriteDacl",
    [System.Security.AccessControl.AccessControlType]"Allow"
)
# NOTE: Add with an explicit deny higher in the ACL to prevent actual escalation
$DenyRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $HoneySID,
    [System.DirectoryServices.ActiveDirectoryRights]"GenericAll",
    [System.Security.AccessControl.AccessControlType]"Deny"
)
$DAGroupAcl.AddAccessRule($DenyRule)
$DAGroupAcl.AddAccessRule($WriteDaclRule)
Set-Acl "AD:\\$DAGroupDN" $DAGroupAcl
Write-Host "[+] Deceptive WriteDacl path created (with deny safety net)" -ForegroundColor Green

Write-Host ""
Write-Host "[+] Deceptive BloodHound path deployed" -ForegroundColor Cyan
Write-Host "[+] Attack path visible to SharpHound:" -ForegroundColor Cyan
Write-Host "    $RegularGroup -[GenericAll]-> $HoneytokenAccount" -ForegroundColor White
Write-Host "    $HoneytokenAccount -[MemberOf]-> $DeceptiveGroupName" -ForegroundColor White
Write-Host "    $HoneytokenAccount -[WriteDacl]-> $TargetGroup (blocked by deny ACE)" -ForegroundColor White
Write-Host "[+] Any attempt to abuse this path triggers honeytoken alerts" -ForegroundColor Yellow
'''

    @staticmethod
    def generate_validation_script(sam_account_name: str) -> str:
        """Generate PowerShell to validate honeytoken deployment."""
        return f'''# ============================================================
# Validate Honeytoken Deployment
# ============================================================

Import-Module ActiveDirectory

$Account = "{sam_account_name}"
$Results = @()

Write-Host "Validating honeytoken deployment for: $Account" -ForegroundColor Cyan
Write-Host "=" * 60

# Check 1: Account exists and is enabled
$User = Get-ADUser -Identity $Account -Properties * -ErrorAction SilentlyContinue
if ($User) {{
    $Results += [PSCustomObject]@{{Check="Account Exists"; Status="PASS"; Details=$User.DistinguishedName}}
    if ($User.Enabled) {{
        $Results += [PSCustomObject]@{{Check="Account Enabled"; Status="PASS"; Details="Enabled"}}
    }} else {{
        $Results += [PSCustomObject]@{{Check="Account Enabled"; Status="FAIL"; Details="Disabled"}}
    }}
}} else {{
    $Results += [PSCustomObject]@{{Check="Account Exists"; Status="FAIL"; Details="Not found"}}
    $Results | Format-Table Check, Status, Details -AutoSize
    exit 1
}}

# Check 2: AdminCount = 1
if ($User.AdminCount -eq 1) {{
    $Results += [PSCustomObject]@{{Check="AdminCount=1"; Status="PASS"; Details="Set correctly"}}
}} else {{
    $Results += [PSCustomObject]@{{Check="AdminCount=1"; Status="WARN"; Details="Not set"}}
}}

# Check 3: SPN configured
$SPNs = $User.ServicePrincipalNames
if ($SPNs -and $SPNs.Count -gt 0) {{
    $Results += [PSCustomObject]@{{Check="SPN Configured"; Status="PASS"; Details=($SPNs -join ", ")}}
}} else {{
    $Results += [PSCustomObject]@{{Check="SPN Configured"; Status="WARN"; Details="No SPNs"}}
}}

# Check 4: Password age (should appear old)
$PwdAge = (Get-Date) - $User.PasswordLastSet
if ($PwdAge.Days -gt 365) {{
    $Results += [PSCustomObject]@{{Check="Password Age"; Status="PASS"; Details="$($PwdAge.Days) days old"}}
}} else {{
    $Results += [PSCustomObject]@{{Check="Password Age"; Status="WARN"; Details="$($PwdAge.Days) days - consider aging"}}
}}

# Check 5: Audit policy (SACL)
$UserDN = $User.DistinguishedName
$Acl = Get-Acl "AD:\\$UserDN" -Audit
if ($Acl.Audit.Count -gt 0) {{
    $Results += [PSCustomObject]@{{Check="SACL Audit"; Status="PASS"; Details="$($Acl.Audit.Count) audit rules"}}
}} else {{
    $Results += [PSCustomObject]@{{Check="SACL Audit"; Status="WARN"; Details="No audit rules"}}
}}

# Check 6: Group memberships
$Groups = Get-ADPrincipalGroupMembership -Identity $Account | Select-Object -ExpandProperty Name
$Results += [PSCustomObject]@{{Check="Group Memberships"; Status="INFO"; Details=($Groups -join ", ")}}

# Check 7: Encryption types
$EncTypes = $User."msDS-SupportedEncryptionTypes"
if ($EncTypes -band 0x4) {{
    $Results += [PSCustomObject]@{{Check="RC4 Supported"; Status="PASS"; Details="RC4 enabled (attracts Kerberoast)"}}
}} else {{
    $Results += [PSCustomObject]@{{Check="RC4 Supported"; Status="INFO"; Details="RC4 not enabled"}}
}}

# Check 8: Advanced audit policy on DC
$AuditPolicy = auditpol /get /subcategory:"Kerberos Service Ticket Operations" 2>$null
if ($AuditPolicy -match "Success") {{
    $Results += [PSCustomObject]@{{Check="Kerberos Audit"; Status="PASS"; Details="Kerberos TGS auditing enabled"}}
}} else {{
    $Results += [PSCustomObject]@{{Check="Kerberos Audit"; Status="FAIL"; Details="Enable: auditpol /set /subcategory:'Kerberos Service Ticket Operations' /success:enable"}}
}}

Write-Host ""
$Results | Format-Table Check, Status, Details -AutoSize

$FailCount = ($Results | Where-Object {{ $_.Status -eq "FAIL" }}).Count
if ($FailCount -eq 0) {{
    Write-Host "[+] All critical checks passed!" -ForegroundColor Green
}} else {{
    Write-Host "[-] $FailCount checks failed - review above" -ForegroundColor Red
}}
'''


# ===========================================================================
# SIEM Detection Rule Generator
# ===========================================================================

class SIEMRuleGenerator:
    """Generates detection rules for SIEM platforms targeting honeytoken activity."""

    def __init__(self):
        self.rules = []

    def generate_detection_rules(self, honeytoken_accounts: list[str],
                                 honey_spns: list[str],
                                 gpo_trap_accounts: list[str],
                                 siem: str = "sigma") -> list[dict]:
        """Generate detection rules for the specified SIEM platform."""
        generators = {
            "sigma": self._generate_sigma_rules,
            "splunk": self._generate_splunk_rules,
            "sentinel": self._generate_sentinel_rules,
        }

        generator = generators.get(siem)
        if not generator:
            raise ValueError(f"Unsupported SIEM: {siem}. Use: {list(generators.keys())}")

        rules = generator(honeytoken_accounts, honey_spns, gpo_trap_accounts)
        self.rules.extend(rules)
        return rules

    def _generate_sigma_rules(self, accounts: list[str],
                              spns: list[str],
                              gpo_accounts: list[str]) -> list[dict]:
        """Generate Sigma detection rules."""
        rules = []

        # Rule 1: Kerberoasting against honey SPN
        if accounts:
            account_list = "\n".join(f"            - '{a}'" for a in accounts)
            rules.append({
                "title": "Honeytoken Kerberoast Detected",
                "id": str(uuid.uuid4()),
                "status": "production",
                "level": "critical",
                "description": "TGS ticket request for honeytoken service account SPN detected. "
                               "This is a high-confidence indicator of Kerberoasting reconnaissance.",
                "detection_logic": f"EventID 4769 AND ServiceName IN {accounts}",
                "rule": f"""title: Honeytoken Kerberoast Detected
id: {uuid.uuid4()}
status: production
level: critical
description: >
    TGS ticket request detected for a honeytoken service account.
    Any Kerberos ticket request for this account is malicious since
    the associated service does not exist.
references:
    - https://adsecurity.org/?p=3513
    - https://www.hub.trimarcsecurity.com/post/the-art-of-the-honeypot-account-making-the-unusual-look-normal
author: Honeytoken Detection Agent
date: {datetime.utcnow().strftime('%Y/%m/%d')}
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        ServiceName:
{account_list}
    filter_machine_accounts:
        ServiceName|endswith: '$'
    condition: selection and not filter_machine_accounts
falsepositives:
    - None expected - any match is suspicious
level: critical""",
            })

        # Rule 2: Logon attempt with GPO trap credentials
        if gpo_accounts:
            gpo_list = "\n".join(f"            - '{a}'" for a in gpo_accounts)
            rules.append({
                "title": "Honeytoken GPO Credential Use Detected",
                "id": str(uuid.uuid4()),
                "status": "production",
                "level": "critical",
                "description": "Failed or successful logon using credentials from decoy GPO. "
                               "Attacker has harvested Group Policy Preference passwords.",
                "detection_logic": f"EventID IN (4624, 4625) AND TargetUserName IN {gpo_accounts}",
                "rule": f"""title: Honeytoken GPO Credential Use Detected
id: {uuid.uuid4()}
status: production
level: critical
description: >
    Logon attempt detected using credentials planted in a decoy Group Policy
    Preference XML. The attacker has enumerated SYSVOL and decrypted the
    cpassword value.
references:
    - https://trustedsec.com/blog/weaponizing-group-policy-objects-access
author: Honeytoken Detection Agent
date: {datetime.utcnow().strftime('%Y/%m/%d')}
tags:
    - attack.credential_access
    - attack.t1552.006
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4624
            - 4625
        TargetUserName:
{gpo_list}
    condition: selection
falsepositives:
    - None expected
level: critical""",
            })

        # Rule 3: DACL access on honeytoken object
        if accounts:
            rules.append({
                "title": "Honeytoken AD Object Accessed",
                "id": str(uuid.uuid4()),
                "status": "production",
                "level": "high",
                "description": "Directory service read on honeytoken account DACL detected. "
                               "Indicates AD reconnaissance or enumeration.",
                "detection_logic": "EventID 4662 AND ObjectName contains honeytoken DN",
                "rule": f"""title: Honeytoken AD Object Accessed
id: {uuid.uuid4()}
status: production
level: high
description: >
    A read operation was performed on a honeytoken AD object's DACL.
    This indicates Active Directory reconnaissance (BloodHound, ADRecon, etc).
references:
    - https://apt29a.blogspot.com/2019/11/deploying-honeytokens-in-active.html
author: Honeytoken Detection Agent
date: {datetime.utcnow().strftime('%Y/%m/%d')}
tags:
    - attack.discovery
    - attack.t1087.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectName|contains:
{"\n".join(f"            - '{a}'" for a in accounts)}
    condition: selection
falsepositives:
    - Legitimate AD administration tools
level: high""",
            })

        return rules

    def _generate_splunk_rules(self, accounts: list[str],
                               spns: list[str],
                               gpo_accounts: list[str]) -> list[dict]:
        """Generate Splunk SPL detection queries."""
        rules = []

        if accounts:
            account_filter = " OR ".join(f'ServiceName="{a}"' for a in accounts)
            rules.append({
                "title": "Honeytoken Kerberoast Detection (Splunk)",
                "detection_logic": f"EventCode=4769 AND ({account_filter})",
                "rule": f"""| `Notable` title="Honeytoken Kerberoast Detected"
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
    ({account_filter})
| eval ticket_type=case(
    Ticket_Encryption_Type=="0x17", "RC4-HMAC (weak)",
    Ticket_Encryption_Type=="0x12", "AES256",
    Ticket_Encryption_Type=="0x11", "AES128",
    true(), Ticket_Encryption_Type
)
| eval alert_severity="critical"
| eval alert_type="honeytoken_kerberoast"
| eval mitre_technique="T1558.003"
| table _time, src_ip, Account_Name, ServiceName, ticket_type, Client_Address
| sort - _time""",
            })

        if gpo_accounts:
            gpo_filter = " OR ".join(f'TargetUserName="{a}"' for a in gpo_accounts)
            rules.append({
                "title": "Honeytoken GPO Credential Use (Splunk)",
                "detection_logic": f"EventCode IN (4624,4625) AND ({gpo_filter})",
                "rule": f"""index=wineventlog sourcetype="WinEventLog:Security"
    (EventCode=4624 OR EventCode=4625)
    ({gpo_filter})
| eval alert_severity="critical"
| eval alert_type="honeytoken_gpo_credential_use"
| eval mitre_technique="T1552.006"
| eval logon_result=if(EventCode=4624, "SUCCESS - INVESTIGATE IMMEDIATELY", "Failed")
| table _time, src_ip, TargetUserName, EventCode, logon_result, Logon_Type, Workstation_Name
| sort - _time""",
            })

        # Correlation rule: SYSVOL access followed by credential use
        if gpo_accounts:
            rules.append({
                "title": "Honeytoken Attack Chain: SYSVOL Enum + Credential Use (Splunk)",
                "detection_logic": "Correlation: EventCode 4663 (SYSVOL read) -> 4625 (failed logon)",
                "rule": f"""index=wineventlog sourcetype="WinEventLog:Security"
    (EventCode=4663 ObjectName="*SYSVOL*Policies*Groups.xml*")
    OR (EventCode=4625 ({" OR ".join(f'TargetUserName="{a}"' for a in gpo_accounts)}))
| eval stage=case(
    EventCode=4663, "1_sysvol_enum",
    EventCode=4625, "2_credential_use"
)
| stats earliest(_time) as first_seen, latest(_time) as last_seen,
    values(stage) as attack_stages, dc(EventCode) as event_types
    by src_ip
| where event_types >= 2
| eval alert_type="honeytoken_attack_chain_confirmed"
| eval alert_severity="critical"
| sort - last_seen""",
            })

        return rules

    def _generate_sentinel_rules(self, accounts: list[str],
                                 spns: list[str],
                                 gpo_accounts: list[str]) -> list[dict]:
        """Generate Microsoft Sentinel KQL detection rules."""
        rules = []

        if accounts:
            account_list = ", ".join(f'"{a}"' for a in accounts)
            rules.append({
                "title": "Honeytoken Kerberoast Detection (Sentinel)",
                "detection_logic": f"EventID == 4769 AND ServiceName in ({account_list})",
                "rule": f"""// Honeytoken Kerberoast Detection
// MITRE ATT&CK: T1558.003 - Kerberoasting
// Severity: Critical - ANY match is malicious
SecurityEvent
| where EventID == 4769
| where ServiceName in ({account_list})
| extend EncryptionType = case(
    TicketEncryptionType == "0x17", "RC4-HMAC (weak - easy to crack)",
    TicketEncryptionType == "0x12", "AES256 (strong)",
    TicketEncryptionType == "0x11", "AES128",
    true(), tostring(TicketEncryptionType)
)
| extend AlertSeverity = "Critical"
| extend AlertType = "Honeytoken Kerberoast"
| extend MitreTechnique = "T1558.003"
| project TimeGenerated, Computer, Account, ServiceName,
    IpAddress, EncryptionType, AlertSeverity, AlertType
| sort by TimeGenerated desc""",
            })

        if gpo_accounts:
            gpo_list = ", ".join(f'"{a}"' for a in gpo_accounts)
            rules.append({
                "title": "Honeytoken GPO Credential Use (Sentinel)",
                "detection_logic": f"EventID in (4624,4625) AND TargetUserName in ({gpo_list})",
                "rule": f"""// Honeytoken GPO Credential Trap Triggered
// MITRE ATT&CK: T1552.006 - Group Policy Preferences
// Severity: Critical
SecurityEvent
| where EventID in (4624, 4625)
| where TargetUserName in ({gpo_list})
| extend LogonResult = iff(EventID == 4624,
    "SUCCESS - IMMEDIATE INVESTIGATION REQUIRED", "Failed")
| extend AlertSeverity = "Critical"
| extend AlertType = "Honeytoken GPO Credential Use"
| extend MitreTechnique = "T1552.006"
| project TimeGenerated, Computer, TargetUserName, EventID,
    LogonResult, IpAddress, LogonTypeName, WorkstationName
| sort by TimeGenerated desc""",
            })

        return rules

    def export_rules(self, output_dir: str, format: str = "json") -> list[str]:
        """Export all generated rules to files."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        saved = []

        for i, rule in enumerate(self.rules):
            if format == "json":
                filename = f"rule_{i+1}_{rule['title'].lower().replace(' ', '_')[:40]}.json"
                filepath = out_path / filename
                filepath.write_text(json.dumps(rule, indent=2))
            elif format == "yaml" and "rule" in rule:
                filename = f"rule_{i+1}.yml"
                filepath = out_path / filename
                filepath.write_text(rule["rule"])
            saved.append(str(filepath))

        return saved


# ===========================================================================
# AD Honeytoken Monitor (Python-based log analysis)
# ===========================================================================

class ADHoneytokenMonitor:
    """Monitors Windows Event Logs for honeytoken interactions."""

    def __init__(self, config_path: str | None = None):
        self.config = {}
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                self.config = json.load(f)
        self.honeytokens: dict[str, dict] = {}
        self.alerts: list[dict] = []

    def register_honeytoken(self, identifier: str,
                            token_type: str = "admin_account",
                            metadata: dict | None = None) -> dict:
        """Register a honeytoken for monitoring."""
        token = {
            "identifier": identifier,
            "type": token_type,
            "registered_at": datetime.utcnow().isoformat(),
            "token_id": f"HT-AD-{uuid.uuid4().hex[:8].upper()}",
            "metadata": metadata or {},
            "alert_count": 0,
        }
        self.honeytokens[identifier] = token
        return token

    def analyze_event_log(self, events: list[dict]) -> list[dict]:
        """Analyze Windows Event Log entries for honeytoken interactions."""
        alerts = []

        for event in events:
            event_id = event.get("EventID") or event.get("EventCode")
            if not event_id:
                continue
            event_id = int(event_id)

            # Check for Kerberoasting (Event 4769)
            if event_id == 4769:
                service_name = event.get("ServiceName", "")
                if service_name in self.honeytokens:
                    enc_type = event.get("TicketEncryptionType", "unknown")
                    alerts.append(self._create_alert(
                        event=event,
                        alert_type="KERBEROAST_HONEYTOKEN",
                        severity="critical",
                        description=f"Kerberoasting detected against honeytoken SPN: {service_name}",
                        mitre_technique="T1558.003",
                        encryption_type=KERBEROS_ENCRYPTION.get(
                            int(enc_type, 16) if isinstance(enc_type, str) else enc_type,
                            str(enc_type)
                        ),
                    ))

            # Check for logon attempts (Event 4624/4625)
            elif event_id in (4624, 4625):
                target_user = event.get("TargetUserName", "")
                if target_user in self.honeytokens:
                    alerts.append(self._create_alert(
                        event=event,
                        alert_type="HONEYTOKEN_LOGON" if event_id == 4624 else "HONEYTOKEN_LOGON_FAILED",
                        severity="critical",
                        description=f"{'Successful' if event_id == 4624 else 'Failed'} "
                                    f"logon attempt with honeytoken account: {target_user}",
                        mitre_technique="T1078" if event_id == 4624 else "T1552.006",
                    ))

            # Check for directory object access (Event 4662)
            elif event_id == 4662:
                object_name = event.get("ObjectName", "")
                for ht_id, ht_info in self.honeytokens.items():
                    if ht_id in object_name:
                        alerts.append(self._create_alert(
                            event=event,
                            alert_type="HONEYTOKEN_DACL_READ",
                            severity="high",
                            description=f"Directory service read on honeytoken object: {ht_id}",
                            mitre_technique="T1087.002",
                        ))

            # Check for GPO modifications (Event 5136)
            elif event_id == 5136:
                object_dn = event.get("ObjectDN", "")
                for ht_id, ht_info in self.honeytokens.items():
                    if ht_info.get("type") == "gpo_credential" and ht_id in object_dn:
                        alerts.append(self._create_alert(
                            event=event,
                            alert_type="HONEYTOKEN_GPO_MODIFIED",
                            severity="critical",
                            description=f"Decoy GPO modification detected: {object_dn}",
                            mitre_technique="T1484.001",
                        ))

        self.alerts.extend(alerts)
        return alerts

    def _create_alert(self, event: dict, alert_type: str,
                      severity: str, description: str,
                      mitre_technique: str, **kwargs) -> dict:
        """Create a structured alert from an event."""
        alert = {
            "alert_id": f"ALERT-{uuid.uuid4().hex[:12].upper()}",
            "alert_type": alert_type,
            "severity": severity,
            "description": description,
            "mitre_technique": mitre_technique,
            "source_ip": event.get("IpAddress") or event.get("src_ip", "unknown"),
            "source_host": event.get("Computer") or event.get("Workstation", "unknown"),
            "account": event.get("TargetUserName") or event.get("ServiceName", "unknown"),
            "event_id": event.get("EventID") or event.get("EventCode"),
            "timestamp": event.get("TimeGenerated") or datetime.utcnow().isoformat(),
            "raw_event": event,
        }
        alert.update(kwargs)
        return alert

    def generate_detection_rules(self, siem: str = "sigma") -> list[dict]:
        """Generate SIEM detection rules for all registered honeytokens."""
        generator = SIEMRuleGenerator()

        accounts = [ht_id for ht_id, info in self.honeytokens.items()
                     if info["type"] in ("admin_account", "spn")]
        spns = [ht_id for ht_id, info in self.honeytokens.items()
                if info["type"] == "spn"]
        gpo_accounts = [ht_id for ht_id, info in self.honeytokens.items()
                        if info["type"] == "gpo_credential"]

        return generator.generate_detection_rules(accounts, spns, gpo_accounts, siem)

    def get_alert_summary(self) -> dict:
        """Get a summary of all triggered alerts."""
        summary = {
            "total_alerts": len(self.alerts),
            "by_severity": {},
            "by_type": {},
            "by_source_ip": {},
            "honeytokens_triggered": set(),
        }

        for alert in self.alerts:
            sev = alert["severity"]
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            atype = alert["alert_type"]
            summary["by_type"][atype] = summary["by_type"].get(atype, 0) + 1

            src = alert["source_ip"]
            summary["by_source_ip"][src] = summary["by_source_ip"].get(src, 0) + 1

            summary["honeytokens_triggered"].add(alert["account"])

        summary["honeytokens_triggered"] = list(summary["honeytokens_triggered"])
        return summary


# ===========================================================================
# Deployment Orchestrator
# ===========================================================================

class HoneytokenDeployer:
    """Orchestrates full honeytoken deployment and generates all artifacts."""

    def __init__(self, domain: str = "corp.example.com",
                 service_account_ou: str = "OU=Service Accounts",
                 sysvol_path: str = ""):
        self.domain = domain
        self.service_account_ou = service_account_ou
        self.sysvol_path = sysvol_path or f"\\\\{domain}\\SYSVOL\\{domain}\\Policies"
        self.ps_gen = PowerShellGenerator()
        self.siem_gen = SIEMRuleGenerator()
        self.deployed_tokens = []

    def generate_realistic_name(self) -> dict:
        """Generate a realistic service account name."""
        template = secrets.choice(SERVICE_ACCOUNT_TEMPLATES)
        service = secrets.choice(template["services"])
        sam = f"{template['prefix']}{service}"

        # Generate a realistic hostname for SPN
        service_abbrev = service[:3].lower()
        hostname = f"{service_abbrev}-legacy-{secrets.randbelow(99):02d}.{self.domain}"

        return {
            "sam_account_name": sam,
            "display_name": f"{service.replace('_', ' ').title()} Service",
            "hostname": hostname,
        }

    def deploy_full_suite(self, token_count: int = 3,
                          include_spn: bool = True,
                          include_gpo: bool = True,
                          include_bloodhound: bool = True,
                          siem_type: str = "sigma") -> dict:
        """Generate complete deployment artifacts for a full honeytoken suite."""
        deployment = {
            "deployment_id": f"DEPLOY-{uuid.uuid4().hex[:8].upper()}",
            "generated_at": datetime.utcnow().isoformat(),
            "domain": self.domain,
            "tokens": [],
            "scripts": [],
            "detection_rules": [],
        }

        all_accounts = []
        all_spns = []
        gpo_accounts = []

        for i in range(token_count):
            naming = self.generate_realistic_name()
            sam = naming["sam_account_name"]
            ou_dn = f"{self.service_account_ou},DC={',DC='.join(self.domain.split('.'))}"

            # Generate admin account script
            account_script = self.ps_gen.generate_create_honeytoken_account(
                sam_account_name=sam,
                display_name=naming["display_name"],
                description=f"Legacy {naming['display_name'].lower()} - DO NOT DELETE",
                ou_dn=ou_dn,
                password_length=128,
                set_admin_count=True,
            )
            deployment["scripts"].append({
                "type": "create_account",
                "filename": f"01_create_{sam}.ps1",
                "content": account_script,
            })
            all_accounts.append(sam)

            token_info = {
                "name": sam,
                "type": "admin_account",
                "display_name": naming["display_name"],
                "ou": ou_dn,
            }

            # Generate SPN script
            if include_spn:
                spn_class = secrets.choice(SPN_SERVICE_CLASSES)
                port = secrets.choice([1433, 443, 8080, 5432, 3306, 27017])
                spn_script = self.ps_gen.generate_add_honey_spn(
                    sam_account_name=sam,
                    service_class=spn_class,
                    hostname=naming["hostname"],
                    port=port,
                )
                deployment["scripts"].append({
                    "type": "add_spn",
                    "filename": f"02_add_spn_{sam}.ps1",
                    "content": spn_script,
                })
                spn_value = f"{spn_class}/{naming['hostname']}:{port}"
                all_spns.append(spn_value)
                token_info["spn"] = spn_value

            deployment["tokens"].append(token_info)

        # Generate GPO decoy
        if include_gpo:
            gpo_username = f"admin_maintenance_{secrets.randbelow(99):02d}"
            domain_short = self.domain.split(".")[0].upper()
            gpo_script = self.ps_gen.generate_decoy_gpo(
                gpo_name="Server Maintenance Policy (Legacy)",
                decoy_username=gpo_username,
                decoy_domain=domain_short,
                sysvol_path=self.sysvol_path,
            )
            deployment["scripts"].append({
                "type": "decoy_gpo",
                "filename": "03_create_decoy_gpo.ps1",
                "content": gpo_script,
            })
            gpo_accounts.append(gpo_username)
            deployment["tokens"].append({
                "name": gpo_username,
                "type": "gpo_credential",
                "description": "Decoy GPO cpassword trap",
            })

        # Generate BloodHound deception
        if include_bloodhound and all_accounts:
            bh_script = self.ps_gen.generate_deceptive_bloodhound_path(
                honeytoken_sam=all_accounts[0],
            )
            deployment["scripts"].append({
                "type": "bloodhound_deception",
                "filename": "04_create_bloodhound_paths.ps1",
                "content": bh_script,
            })

        # Generate validation script
        if all_accounts:
            val_script = self.ps_gen.generate_validation_script(all_accounts[0])
            deployment["scripts"].append({
                "type": "validation",
                "filename": "05_validate_deployment.ps1",
                "content": val_script,
            })

        # Generate SIEM detection rules
        rules = self.siem_gen.generate_detection_rules(
            all_accounts, all_spns, gpo_accounts, siem_type
        )
        deployment["detection_rules"] = rules

        self.deployed_tokens = deployment["tokens"]
        return deployment

    def save_deployment(self, deployment: dict, output_dir: str) -> list[str]:
        """Save all deployment artifacts to disk."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        saved = []

        # Save PowerShell scripts
        scripts_dir = out_path / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        for script in deployment.get("scripts", []):
            filepath = scripts_dir / script["filename"]
            filepath.write_text(script["content"], encoding="utf-8")
            saved.append(str(filepath))

        # Save detection rules
        rules_dir = out_path / "detection_rules"
        rules_dir.mkdir(exist_ok=True)
        for i, rule in enumerate(deployment.get("detection_rules", [])):
            filename = f"rule_{i+1}_{rule['title'][:40].lower().replace(' ', '_')}.json"
            filepath = rules_dir / filename
            filepath.write_text(json.dumps(rule, indent=2), encoding="utf-8")
            saved.append(str(filepath))

        # Save deployment manifest
        manifest = {
            "deployment_id": deployment["deployment_id"],
            "generated_at": deployment["generated_at"],
            "domain": deployment["domain"],
            "tokens": deployment["tokens"],
            "scripts": [s["filename"] for s in deployment["scripts"]],
            "detection_rules": [r["title"] for r in deployment["detection_rules"]],
        }
        manifest_path = out_path / "deployment_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        saved.append(str(manifest_path))

        return saved


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Active Directory Honeytoken Deployment Agent"
    )
    parser.add_argument(
        "--action",
        choices=[
            "deploy_account", "deploy_spn", "deploy_gpo", "deploy_bloodhound",
            "full_deploy", "generate_rules", "validate", "analyze_logs",
        ],
        default="full_deploy",
        help="Action to perform",
    )
    parser.add_argument("--domain", default="corp.example.com")
    parser.add_argument("--ou", default="OU=Service Accounts")
    parser.add_argument("--sysvol", default="")
    parser.add_argument("--account-name", default="svc_sqlbackup_legacy")
    parser.add_argument("--token-count", type=int, default=3)
    parser.add_argument("--siem", choices=["sigma", "splunk", "sentinel"], default="sigma")
    parser.add_argument("--output-dir", default="honeytoken_deployment")
    parser.add_argument("--include-spn", action="store_true", default=True)
    parser.add_argument("--include-gpo", action="store_true", default=True)
    parser.add_argument("--include-bloodhound", action="store_true", default=True)
    parser.add_argument("--event-log", help="Path to event log JSON for analysis")
    args = parser.parse_args()

    print("=" * 60)
    print("Active Directory Honeytoken Deployment Agent")
    print("=" * 60)

    deployer = HoneytokenDeployer(
        domain=args.domain,
        service_account_ou=args.ou,
        sysvol_path=args.sysvol,
    )

    if args.action == "full_deploy":
        print(f"\n[+] Generating full honeytoken deployment for: {args.domain}")
        print(f"[+] Token count: {args.token_count}")
        print(f"[+] SIEM target: {args.siem}")

        deployment = deployer.deploy_full_suite(
            token_count=args.token_count,
            include_spn=args.include_spn,
            include_gpo=args.include_gpo,
            include_bloodhound=args.include_bloodhound,
            siem_type=args.siem,
        )

        saved_files = deployer.save_deployment(deployment, args.output_dir)

        print(f"\n[+] Deployment ID: {deployment['deployment_id']}")
        print(f"[+] Tokens generated: {len(deployment['tokens'])}")
        for token in deployment["tokens"]:
            print(f"    - {token['name']} ({token['type']})"
                  + (f" SPN: {token.get('spn', 'N/A')}" if token.get('spn') else ""))

        print(f"\n[+] Scripts generated: {len(deployment['scripts'])}")
        for script in deployment["scripts"]:
            print(f"    - {script['filename']} ({script['type']})")

        print(f"\n[+] Detection rules generated: {len(deployment['detection_rules'])}")
        for rule in deployment["detection_rules"]:
            print(f"    - {rule['title']}")

        print(f"\n[+] Files saved to: {args.output_dir}")
        for f in saved_files:
            print(f"    {f}")

    elif args.action == "generate_rules":
        print(f"\n[+] Generating {args.siem} detection rules...")
        monitor = ADHoneytokenMonitor()
        monitor.register_honeytoken(args.account_name, "admin_account")

        rules = monitor.generate_detection_rules(args.siem)
        for rule in rules:
            print(f"\n--- {rule['title']} ---")
            print(rule.get("rule", rule.get("detection_logic", "")))

    elif args.action == "analyze_logs":
        if not args.event_log:
            print("[-] --event-log required for log analysis")
            return

        print(f"\n[+] Analyzing event log: {args.event_log}")
        monitor = ADHoneytokenMonitor()
        monitor.register_honeytoken(args.account_name, "admin_account")

        log_path = Path(args.event_log)
        if not log_path.exists():
            print(f"[-] Log file not found: {args.event_log}")
            return

        with open(log_path) as f:
            events = json.load(f)

        alerts = monitor.analyze_event_log(events)
        print(f"\n[+] Alerts generated: {len(alerts)}")
        for alert in alerts:
            print(f"  [{alert['severity'].upper()}] {alert['alert_type']}: "
                  f"{alert['description']}")
            print(f"    Source: {alert['source_ip']} | "
                  f"Account: {alert['account']} | "
                  f"MITRE: {alert['mitre_technique']}")

        summary = monitor.get_alert_summary()
        print(f"\n[+] Summary: {summary['total_alerts']} alerts, "
              f"sources: {list(summary['by_source_ip'].keys())}")

    elif args.action == "deploy_account":
        ps_gen = PowerShellGenerator()
        ou_dn = f"{args.ou},DC={',DC='.join(args.domain.split('.'))}"
        script = ps_gen.generate_create_honeytoken_account(
            sam_account_name=args.account_name,
            display_name="Legacy Backup Service",
            description="Legacy backup service account - DO NOT DELETE",
            ou_dn=ou_dn,
        )
        print(script)

    elif args.action == "deploy_spn":
        ps_gen = PowerShellGenerator()
        script = ps_gen.generate_add_honey_spn(
            sam_account_name=args.account_name,
        )
        print(script)

    elif args.action == "deploy_gpo":
        ps_gen = PowerShellGenerator()
        script = ps_gen.generate_decoy_gpo(
            gpo_name="Server Maintenance Policy (Legacy)",
            decoy_username="admin_maintenance",
            decoy_domain=args.domain.split(".")[0].upper(),
            sysvol_path=deployer.sysvol_path,
        )
        print(script)

    elif args.action == "deploy_bloodhound":
        ps_gen = PowerShellGenerator()
        script = ps_gen.generate_deceptive_bloodhound_path(
            honeytoken_sam=args.account_name,
        )
        print(script)

    elif args.action == "validate":
        ps_gen = PowerShellGenerator()
        script = ps_gen.generate_validation_script(args.account_name)
        print(script)

    print("\n" + "=" * 60)
    print("[+] Honeytoken agent complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
