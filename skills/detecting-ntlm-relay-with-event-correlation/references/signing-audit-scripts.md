# SMB/LDAP Signing Audit and NTLM Restriction Configuration

Companion depth for `SKILL.md` Steps 4 and 6. SMB signing prevents relay to SMB
services; LDAP signing and channel binding prevent relay to LDAP/LDAPS on domain
controllers. NTLM auditing (Event 8004) reveals all NTLM usage before restriction.

## SMB Signing Enforcement Audit (Step 4)

```powershell
# PowerShell: Audit SMB Signing Status Across Domain
# SMB signing prevents NTLM relay to SMB services

# Check local SMB signing configuration
Write-Host "=== LOCAL SMB SIGNING STATUS ==="
$smbServer = Get-SmbServerConfiguration
Write-Host "[*] SMB Server RequireSecuritySignature: $($smbServer.RequireSecuritySignature)"
Write-Host "[*] SMB Server EnableSecuritySignature: $($smbServer.EnableSecuritySignature)"

$smbClient = Get-SmbClientConfiguration
Write-Host "[*] SMB Client RequireSecuritySignature: $($smbClient.RequireSecuritySignature)"
Write-Host "[*] SMB Client EnableSecuritySignature: $($smbClient.EnableSecuritySignature)"

# Check via registry (works on older systems)
$serverSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$clientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue

Write-Host "`n=== REGISTRY VALUES ==="
Write-Host "[*] Server RequireSecuritySignature: $($serverSigning.RequireSecuritySignature) (1=Required, 0=Not Required)"
Write-Host "[*] Client RequireSecuritySignature: $($clientSigning.RequireSecuritySignature) (1=Required, 0=Not Required)"
```

```powershell
# PowerShell: Domain-Wide SMB Signing Audit
# Scan all domain computers for SMB signing enforcement

$domainComputers = Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object { $_.OperatingSystem -like "*Windows*" -and $_.Enabled -eq $true } |
    Select-Object -ExpandProperty DNSHostName

$results = @()
foreach ($computer in $domainComputers) {
    try {
        $session = New-CimSession -ComputerName $computer -ErrorAction Stop
        $smbConfig = Get-SmbServerConfiguration -CimSession $session -ErrorAction Stop
        $results += [PSCustomObject]@{
            Computer = $computer
            RequireSigning = $smbConfig.RequireSecuritySignature
            EnableSigning = $smbConfig.EnableSecuritySignature
            Status = if ($smbConfig.RequireSecuritySignature) { "ENFORCED" } else { "VULNERABLE" }
        }
        Remove-CimSession $session
    } catch {
        $results += [PSCustomObject]@{
            Computer = $computer
            RequireSigning = "ERROR"
            EnableSigning = "ERROR"
            Status = "UNREACHABLE"
        }
    }
}

# Display results sorted by vulnerability
$results | Sort-Object Status | Format-Table -AutoSize

# Export vulnerable hosts
$vulnerable = $results | Where-Object { $_.Status -eq "VULNERABLE" }
Write-Host "`n[!] VULNERABLE HOSTS (SMB Signing Not Required): $($vulnerable.Count)"
$vulnerable | Export-Csv -Path "smb_signing_audit.csv" -NoTypeInformation
```

```powershell
# PowerShell: Audit LDAP Signing Status on Domain Controllers
# LDAP signing prevents NTLM relay to LDAP/LDAPS services

# Check LDAP signing requirement on domain controllers
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($dc in $dcs) {
    # Check LDAP server signing requirement
    $ldapSigning = Invoke-Command -ComputerName $dc -ScriptBlock {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $value = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
        return $value.LDAPServerIntegrity
    } -ErrorAction SilentlyContinue

    $status = switch ($ldapSigning) {
        0 { "NONE (Vulnerable)" }
        1 { "Negotiate Signing (Default - Vulnerable to relay)" }
        2 { "Require Signing (Secure)" }
        default { "Unknown/Error" }
    }
    Write-Host "[*] $dc LDAP Signing: $status"

    # Check LDAP channel binding
    $channelBinding = Invoke-Command -ComputerName $dc -ScriptBlock {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $value = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
        return $value.LdapEnforceChannelBinding
    } -ErrorAction SilentlyContinue

    $cbStatus = switch ($channelBinding) {
        0 { "Disabled (Vulnerable)" }
        1 { "When Supported" }
        2 { "Always Required (Secure)" }
        default { "Not Configured (Vulnerable)" }
    }
    Write-Host "[*] $dc LDAP Channel Binding: $cbStatus"
}
```

```spl
# Splunk: Monitor for SMB sessions without signing
# Requires Zeek SMB logging or packet capture analysis

index=network sourcetype="zeek:smb_mapping:json" OR sourcetype="bro:smb_mapping:json"
| where NOT security_mode="signing_required"
| stats count dc(id_orig_h) as unique_clients by id_resp_h security_mode
| sort -unique_clients
| rename id_resp_h as smb_server
| table smb_server security_mode unique_clients count
```

## NTLM Audit and Restriction Policy Configuration (Step 6)

```powershell
# PowerShell: Enable NTLM Auditing via Group Policy Registry Settings
# Must be applied via GPO for domain-wide coverage

# Audit all NTLM authentication in this domain
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings >
#      Local Policies > Security Options >
#      Network Security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all

# Registry equivalent (apply via GPO preferences or startup script)
# Domain Controller setting:
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
#     -Name "AuditNTLMInDomain" -Value 7 -Type DWord

# Audit incoming NTLM traffic on all servers:
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
#     -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord

# After enabling auditing, NTLM events appear in:
# Applications and Services Logs > Microsoft > Windows > NTLM > Operational

# Query NTLM operational log for audit events
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(8001, 8002, 8003, 8004) } |
    Select-Object TimeCreated, Id,
        @{N='EventType'; E={
            switch ($_.Id) {
                8001 { "NTLM client blocked audit" }
                8002 { "NTLM server blocked audit" }
                8003 { "NTLM server blocked in domain" }
                8004 { "NTLM authentication to DC audit" }
            }
        }},
        @{N='Detail'; E={$_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))}} |
    Format-Table -AutoSize
```

```spl
# Splunk: Monitor NTLM Audit Events (Event ID 8004)
# Shows all NTLM authentications passing through domain controllers

index=wineventlog source="WinEventLog:Microsoft-Windows-NTLM/Operational"
    EventCode=8004
| rex field=Message "Calling client name:\s+(?<client_name>[^\r\n]+)"
| rex field=Message "Calling client IP:\s+(?<client_ip>[^\r\n]+)"
| rex field=Message "Server name:\s+(?<server_name>[^\r\n]+)"
| stats count dc(server_name) as unique_servers by client_name client_ip
| sort -count
| table client_name client_ip unique_servers count
```
