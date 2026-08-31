# FIDO2 Registration, Legacy Disablement, and Adoption Monitoring Scripts

Companion depth for `SKILL.md` Steps 4, 5, and 6. Full Microsoft Graph PowerShell
scripts for the security-key registration workflow, phasing out phishable methods,
and tracking passwordless adoption.

## Step 4: Register FIDO2 Security Keys for Users

Implement a security key registration workflow using Temporary Access Pass (TAP) to
bootstrap enrollment without a password.

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

## Step 5: Disable Legacy Authentication Methods

Phase out phishable authentication factors (SMS, voice) and block legacy protocols.

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

## Step 6: Monitor Passwordless Adoption Metrics

Track deployment progress and authentication method usage.

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
