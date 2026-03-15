---
name: implementing-passwordless-auth-with-microsoft-entra
description: >
  Implements passwordless authentication using Microsoft Entra ID with FIDO2 security keys,
  Windows Hello for Business, Microsoft Authenticator passkeys, and certificate-based
  authentication to eliminate password-based attacks.
  Activates for requests involving passwordless deployment, FIDO2 passkey configuration,
  phishing-resistant MFA, or Microsoft Entra authentication method policies.
domain: cybersecurity
subdomain: identity-access-management
tags: [passwordless, FIDO2, passkeys, Microsoft-Entra, Windows-Hello, phishing-resistant-MFA]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Passwordless Auth with Microsoft Entra

## When to Use

- Organization wants to eliminate password-based attacks (phishing, credential stuffing, brute force)
- Regulatory or internal mandate requires phishing-resistant MFA (Executive Order 14028, CISA guidance)
- Deploying FIDO2 security keys or Windows Hello for Business across the enterprise
- Migrating from legacy MFA (SMS, phone call) to phishing-resistant authentication methods
- Implementing passkey support for hybrid or cloud-joined Windows devices
- Reducing helpdesk costs from password reset requests

**Do not use** for environments that cannot support modern authentication protocols; legacy applications using NTLM or basic authentication must be migrated first.

## Prerequisites

- Microsoft Entra ID P1 or P2 license (Azure AD Premium)
- Windows 10/11 22H2+ for Windows Hello for Business deployment
- FIDO2-compliant security keys (YubiKey 5 Series, Feitian BioPass, Google Titan)
- Microsoft Authenticator app 6.8+ for passkey support on iOS 16+/Android 14+
- Hybrid Azure AD join or Azure AD join configured for Windows devices
- Conditional Access policies configured for authentication strength

## Workflow

### Step 1: Configure Authentication Methods Policy

Enable passwordless authentication methods in Microsoft Entra:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod", "User.ReadWrite.All"

# Enable FIDO2 Security Key authentication method
$fido2Policy = @{
    "@odata.type" = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
    state = "enabled"
    isAttestationEnforced = $true
    isSelfServiceRegistrationAllowed = $true
    keyRestrictions = @{
        isEnforced = $true
        enforcementType = "allow"
        aaGuids = @(
            "cb69481e-8ff7-4039-93ec-0a2729a154a8",  # YubiKey 5 Series
            "ee882879-721c-4913-9775-3dfcce97072a",  # YubiKey 5 NFC
            "fa2b99dc-9e39-4257-8f92-4a30d23c4118",  # YubiKey 5C NFC
            "2fc0579f-8113-47ea-b116-bb5a8db9202a",  # YubiKey Bio
            "73bb0cd4-e502-49b8-9c6f-b59445bf720b"   # Google Titan
        )
    }
    includeTargets = @(
        @{
            targetType = "group"
            id = "all_users"  # Or specific security group ID
        }
    )
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "fido2" `
    -BodyParameter $fido2Policy

# Enable Microsoft Authenticator with passkey support
$authenticatorPolicy = @{
    "@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
    state = "enabled"
    featureSettings = @{
        displayAppInformationRequiredState = @{
            state = "enabled"
            includeTarget = @{
                targetType = "group"
                id = "all_users"
            }
        }
        displayLocationInformationRequiredState = @{
            state = "enabled"
            includeTarget = @{
                targetType = "group"
                id = "all_users"
            }
        }
        companionAppAllowedState = @{
            state = "enabled"
        }
    }
    includeTargets = @(
        @{
            targetType = "group"
            id = "all_users"
            authenticationMode = "any"
        }
    )
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "microsoftAuthenticator" `
    -BodyParameter $authenticatorPolicy

# Enable Windows Hello for Business
$whfbPolicy = @{
    "@odata.type" = "#microsoft.graph.windowsHelloForBusinessAuthenticationMethodConfiguration"
    state = "enabled"
    pinMinimumLength = 6
    pinMaximumLength = 127
    pinLowercaseCharactersUsage = "allowed"
    pinUppercaseCharactersUsage = "allowed"
    pinSpecialCharactersUsage = "allowed"
    securityKeyForSignIn = "enabled"
    includeTargets = @(
        @{
            targetType = "group"
            id = "all_users"
        }
    )
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "windowsHelloForBusiness" `
    -BodyParameter $whfbPolicy

Write-Host "Passwordless authentication methods enabled successfully"
```

### Step 2: Configure Authentication Strength Conditional Access

Create Conditional Access policies requiring phishing-resistant authentication:

```powershell
# Create custom authentication strength for phishing-resistant MFA
$authStrength = @{
    displayName = "Phishing-Resistant Passwordless"
    description = "Requires FIDO2, WHfB, or certificate-based authentication"
    allowedCombinations = @(
        "fido2",
        "windowsHelloForBusiness",
        "x509CertificateMultiFactor"
    )
    requirementsSatisfied = "mfa"
}
$strengthPolicy = New-MgPolicyAuthenticationStrengthPolicy -BodyParameter $authStrength

# Create Conditional Access policy requiring phishing-resistant auth
$caPolicy = @{
    displayName = "Require Phishing-Resistant Auth for All Apps"
    state = "enabledForReportingButNotEnforced"  # Start in report-only
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeGroups = @("Passwordless-Exclusion-Group")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "OR"
        authenticationStrength = @{
            id = $strengthPolicy.Id
        }
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $caPolicy

# Create stricter policy for admin portals
$adminPolicy = @{
    displayName = "Require Security Key for Admin Access"
    state = "enabled"
    conditions = @{
        users = @{
            includeRoles = @(
                "62e90394-69f5-4237-9190-012177145e10",  # Global Admin
                "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Admin
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Admin
                "29232cdf-9323-42fd-ade2-1d097af3e4de"   # Exchange Admin
            )
        }
        applications = @{
            includeApplications = @(
                "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Azure Portal
                "00000006-0000-0ff1-ce00-000000000000",  # Microsoft 365 Admin
                "0000000a-0000-0000-c000-000000000000"   # Entra Admin Center
            )
        }
    }
    grantControls = @{
        operator = "OR"
        authenticationStrength = @{
            id = $strengthPolicy.Id
        }
    }
    sessionControls = @{
        signInFrequency = @{
            value = 4
            type = "hours"
            isEnabled = $true
        }
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $adminPolicy
```

### Step 3: Deploy Windows Hello for Business via Intune

Configure WHfB deployment through Microsoft Intune MDM:

```powershell
# Create Windows Hello for Business configuration profile in Intune
$whfbProfile = @{
    "@odata.type" = "#microsoft.graph.windowsIdentityProtectionConfiguration"
    displayName = "WHfB - Enterprise Deployment"
    description = "Windows Hello for Business configuration for all managed devices"
    useSecurityKeyForSignin = $true
    windowsHelloForBusinessBlocked = $false
    pinMinimumLength = 6
    pinMaximumLength = 127
    pinUppercaseCharactersUsage = "allowed"
    pinLowercaseCharactersUsage = "allowed"
    pinSpecialCharactersUsage = "allowed"
    enhancedAntiSpoofingForFacialFeaturesEnabled = $true
    pinRecoveryEnabled = $true
    securityDeviceRequired = $true  # Require TPM
    unlockWithBiometricsEnabled = $true
    useCertificatesForOnPremisesAuthEnabled = $true  # For hybrid scenarios
    # Cloud Kerberos Trust for hybrid join (recommended over key trust)
    windowsHelloForBusinessAuthenticationMethod = "cloudKerberosTrust"
}

# Create the configuration profile
$profile = New-MgDeviceManagementDeviceConfiguration -BodyParameter $whfbProfile

# Assign to all Windows devices
$assignment = @{
    target = @{
        "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
    }
}
New-MgDeviceManagementDeviceConfigurationAssignment `
    -DeviceConfigurationId $profile.Id `
    -BodyParameter $assignment

# Configure Cloud Kerberos Trust (for hybrid Azure AD joined devices)
# This eliminates the need for PKI infrastructure
# Requires Azure AD Kerberos module

Import-Module AzureADHybridAuthenticationManagement

# Create Azure AD Kerberos Server object in on-premises AD
$domain = "corp.local"
$cloudCredential = Get-Credential -Message "Enter Azure AD Global Admin credentials"
$domainCredential = Get-Credential -Message "Enter on-premises Domain Admin credentials"

Set-AzureADKerberosServer `
    -Domain $domain `
    -CloudCredential $cloudCredential `
    -DomainCredential $domainCredential

# Verify Kerberos Server object
Get-AzureADKerberosServer -Domain $domain -CloudCredential $cloudCredential `
    -DomainCredential $domainCredential

Write-Host "Cloud Kerberos Trust configured for hybrid WHfB deployment"
```

### Step 4: Register FIDO2 Security Keys for Users

Implement security key registration workflow:

```powershell
# Bulk FIDO2 security key registration via Temporary Access Pass
# Step 1: Issue Temporary Access Pass for key registration

function Issue-TemporaryAccessPass {
    param(
        [string]$UserId,
        [int]$LifetimeMinutes = 60,
        [bool]$IsUsableOnce = $true
    )

    $tap = @{
        "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
        lifetimeInMinutes = $LifetimeMinutes
        isUsableOnce = $IsUsableOnce
    }

    $result = New-MgUserAuthenticationTemporaryAccessPassMethod `
        -UserId $UserId `
        -BodyParameter $tap

    return @{
        UserId = $UserId
        TemporaryAccessPass = $result.TemporaryAccessPass
        ExpiresAt = $result.CreatedDateTime.AddMinutes($LifetimeMinutes)
    }
}

# Bulk issue TAPs for security key registration event
$registrationUsers = Import-Csv "security_key_registration_list.csv"

$tapResults = foreach ($user in $registrationUsers) {
    $tap = Issue-TemporaryAccessPass -UserId $user.UserPrincipalName
    [PSCustomObject]@{
        User = $user.UserPrincipalName
        TAP = $tap.TemporaryAccessPass
        Expires = $tap.ExpiresAt
        KeySerial = $user.AssignedKeySerial
    }
}

# Export TAPs for secure distribution to registration team
$tapResults | Export-Csv "tap_assignments.csv" -NoTypeInformation

# Monitor FIDO2 registration progress
function Get-Fido2RegistrationStatus {
    $allUsers = Get-MgUser -All -Property "id,userPrincipalName,department"

    $registrationStatus = foreach ($user in $allUsers) {
        $methods = Get-MgUserAuthenticationFido2Method -UserId $user.Id

        [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            Department = $user.Department
            Fido2KeyCount = $methods.Count
            KeyModels = ($methods.Model -join ", ")
            RegistrationDates = ($methods.CreatedDateTime -join ", ")
            HasBackupKey = $methods.Count -ge 2
        }
    }

    return $registrationStatus
}

$status = Get-Fido2RegistrationStatus
$total = $status.Count
$registered = ($status | Where-Object { $_.Fido2KeyCount -gt 0 }).Count
$withBackup = ($status | Where-Object { $_.HasBackupKey }).Count

Write-Host "FIDO2 Registration Progress"
Write-Host "  Total Users: $total"
Write-Host "  Registered:  $registered ($([math]::Round($registered/$total*100,1))%)"
Write-Host "  With Backup: $withBackup ($([math]::Round($withBackup/$total*100,1))%)"
```

### Step 5: Disable Legacy Authentication Methods

Phase out phishable authentication factors:

```powershell
# Disable SMS and voice call authentication
$smsPolicy = @{
    "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
    state = "disabled"
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "sms" `
    -BodyParameter $smsPolicy

$voicePolicy = @{
    "@odata.type" = "#microsoft.graph.voiceAuthenticationMethodConfiguration"
    state = "disabled"
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "voice" `
    -BodyParameter $voicePolicy

# Block legacy authentication protocols via Conditional Access
$blockLegacyPolicy = @{
    displayName = "Block Legacy Authentication"
    state = "enabled"
    conditions = @{
        users = @{ includeUsers = @("All") }
        applications = @{ includeApplications = @("All") }
        clientAppTypes = @(
            "exchangeActiveSync",
            "other"
        )
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $blockLegacyPolicy

# Audit users still using legacy authentication
$legacyAuthReport = Get-MgAuditLogSignIn -Filter "clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'" `
    -Top 1000 | Group-Object userPrincipalName | Select-Object Count, Name |
    Sort-Object Count -Descending

Write-Host "Users with Legacy Auth (last 30 days):"
$legacyAuthReport | Format-Table -AutoSize
```

### Step 6: Monitor Passwordless Adoption Metrics

Track deployment progress and authentication method usage:

```powershell
# Generate passwordless adoption dashboard data
function Get-PasswordlessAdoptionMetrics {
    # Authentication method registration statistics
    $registrationReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -All

    $metrics = @{
        TotalUsers = $registrationReport.Count
        PasswordlessCapable = ($registrationReport | Where-Object { $_.IsPasswordlessCapable }).Count
        MfaRegistered = ($registrationReport | Where-Object { $_.IsMfaRegistered }).Count
        Fido2Registered = ($registrationReport | Where-Object { "fido2" -in $_.MethodsRegistered }).Count
        WhfbRegistered = ($registrationReport | Where-Object { "windowsHelloForBusiness" -in $_.MethodsRegistered }).Count
        AuthenticatorRegistered = ($registrationReport | Where-Object { "microsoftAuthenticator" -in $_.MethodsRegistered }).Count
        SmsOnly = ($registrationReport | Where-Object {
            "sms" -in $_.MethodsRegistered -and
            "fido2" -notin $_.MethodsRegistered -and
            "windowsHelloForBusiness" -notin $_.MethodsRegistered
        }).Count
    }

    # Authentication method usage from sign-in logs
    $signInLogs = Get-MgAuditLogSignIn -Top 10000 -Filter "createdDateTime ge $((Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'))"

    $authMethodUsage = $signInLogs |
        Group-Object { $_.AuthenticationMethodsUsed -join "," } |
        Select-Object Count, Name | Sort-Object Count -Descending

    return @{
        Registration = $metrics
        Usage = $authMethodUsage
    }
}

$adoption = Get-PasswordlessAdoptionMetrics
$reg = $adoption.Registration

Write-Host "PASSWORDLESS ADOPTION REPORT"
Write-Host "============================"
Write-Host "Total Users:              $($reg.TotalUsers)"
Write-Host "Passwordless Capable:     $($reg.PasswordlessCapable) ($([math]::Round($reg.PasswordlessCapable/$reg.TotalUsers*100,1))%)"
Write-Host "  FIDO2 Keys:             $($reg.Fido2Registered)"
Write-Host "  Windows Hello:          $($reg.WhfbRegistered)"
Write-Host "  Authenticator:          $($reg.AuthenticatorRegistered)"
Write-Host "MFA Registered:           $($reg.MfaRegistered) ($([math]::Round($reg.MfaRegistered/$reg.TotalUsers*100,1))%)"
Write-Host "SMS Only (needs upgrade): $($reg.SmsOnly)"
```

## Key Concepts

| Term | Definition |
|------|------------|
| **FIDO2** | Fast Identity Online 2 standard enabling passwordless authentication using public-key cryptography bound to hardware authenticators or platform credentials |
| **Passkey** | FIDO2 credential that can be device-bound (security key) or synced across devices, providing phishing-resistant authentication without passwords |
| **Windows Hello for Business** | Windows platform authenticator using PIN, fingerprint, or facial recognition backed by TPM-protected asymmetric keys for passwordless sign-in |
| **Cloud Kerberos Trust** | Deployment model for hybrid WHfB that uses Azure AD Kerberos to authenticate to on-premises resources without requiring PKI certificate infrastructure |
| **Temporary Access Pass** | Time-limited passcode issued by admins enabling users to register passwordless methods or recover access when their primary method is unavailable |
| **Authentication Strength** | Conditional Access capability in Microsoft Entra that specifies which authentication method combinations satisfy MFA requirements for a given policy |

## Tools & Systems

- **Microsoft Entra Admin Center**: Portal for configuring authentication methods, Conditional Access policies, and monitoring sign-in analytics
- **Microsoft Intune**: MDM/MAM platform for deploying Windows Hello for Business configuration profiles to managed devices
- **Microsoft Graph API**: Programmatic interface for managing authentication methods, policies, and generating adoption reports
- **FIDO2 Security Keys**: Hardware authenticators (YubiKey, Feitian, Google Titan) storing cryptographic credentials for phishing-resistant authentication

## Common Scenarios

### Scenario: Enterprise-Wide Passwordless Migration

**Context**: Organization with 5,000 users plans to eliminate passwords within 12 months after experiencing a phishing attack that compromised 47 accounts. Current state: 60% use SMS MFA, 30% use Authenticator app, 10% have no MFA.

**Approach**:
1. Phase 1 (Month 1-2): Enable FIDO2 and WHfB authentication methods in report-only Conditional Access
2. Phase 2 (Month 2-3): Deploy WHfB to all managed Windows devices via Intune with Cloud Kerberos Trust
3. Phase 3 (Month 3-5): Distribute FIDO2 security keys to executives, IT admins, and finance (highest-risk users first)
4. Phase 4 (Month 5-8): Enable Authenticator passkeys for mobile-primary users and field workers
5. Phase 5 (Month 8-10): Switch Conditional Access from report-only to enforced for phishing-resistant auth
6. Phase 6 (Month 10-12): Disable SMS and voice call methods, block legacy authentication protocols
7. Ongoing: Monitor adoption metrics, issue TAPs for stragglers, maintain break-glass accounts

**Pitfalls**:
- Not deploying Cloud Kerberos Trust causes WHfB to fail for on-premises resource access in hybrid environments
- Enforcing passwordless without ensuring all applications support modern authentication breaks access
- Issuing only one security key per user without a backup creates lockout risk if the key is lost
- Not configuring Temporary Access Pass as a recovery method before disabling password-based sign-in

## Output Format

```
PASSWORDLESS AUTHENTICATION DEPLOYMENT REPORT
================================================
Tenant:            corp.onmicrosoft.com
Users:             5,247
Deployment Phase:  Phase 4 (Authenticator Passkeys)

AUTHENTICATION METHOD REGISTRATION
Passwordless Capable:    4,103 / 5,247 (78.2%)
  FIDO2 Security Keys:   892 (17.0%)
  Windows Hello:          2,847 (54.3%)
  Authenticator Passkey:  1,234 (23.5%)
  Certificate-Based:      312 (5.9%)

LEGACY METHOD STATUS
SMS-Only Users:          387 (7.4%) -- migration in progress
Voice-Only Users:        0 (disabled)
No MFA Users:            42 (0.8%) -- TAPs issued

CONDITIONAL ACCESS
Phishing-Resistant Policy:  ENFORCED (all users except exclusion group)
Legacy Auth Block:          ENABLED
Admin Portal Policy:        SECURITY KEY REQUIRED

SIGN-IN ANALYTICS (Last 30 Days)
Total Sign-Ins:          847,293
  Passwordless:          623,891 (73.6%)
  Password + MFA:        198,402 (23.4%)
  Password Only:         0 (blocked)
  Legacy Protocol:       0 (blocked)

SECURITY IMPACT
Phishing Incidents:      0 (down from 47 pre-deployment)
Password Reset Tickets:  -82% reduction
Avg Sign-In Time:        8.2s (passwordless) vs 24.1s (password)
```
