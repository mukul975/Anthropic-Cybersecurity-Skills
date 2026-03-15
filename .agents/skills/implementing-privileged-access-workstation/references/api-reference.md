# API Reference — Implementing Privileged Access Workstation

## Libraries Used
- **subprocess**: Execute PowerShell cmdlets for device hardening, group membership, software inventory
- **json**: Parse PowerShell ConvertTo-Json output

## CLI Interface
```
python agent.py harden
python agent.py admins
python agent.py software
python agent.py network
python agent.py full
```

## Core Functions

### `check_device_hardening()` — Audit 7 PAW hardening controls
Checks: Credential Guard, VBS status, Secure Boot, BitLocker, AppLocker,
Windows Firewall profiles, UAC level via registry.

### `check_local_admin_group()` — JIT access audit
Enumerates local Administrators group via `Get-LocalGroupMember`.
Flags unexpected members not matching known admin accounts.

### `check_installed_software()` — Software allowlist enforcement
Queries installed software from registry. Checks against blocked list:
browsers (Chrome, Firefox), personal apps (Spotify, Steam, Slack, Zoom, Dropbox).

### `check_network_restrictions()` — Network isolation verification
Counts outbound firewall block rules. Tests general internet connectivity.
PAW Tier 0 should block internet — only management endpoints allowed.

### `full_paw_audit()` — Comprehensive compliance report

## PAW Hardening Checks
| Check | PowerShell Source | Pass Criteria |
|-------|------------------|---------------|
| Credential Guard | Win32_DeviceGuard | SecurityServicesRunning > 0 |
| VBS | Win32_DeviceGuard | VirtualizationBasedSecurityStatus = 2 |
| Secure Boot | Confirm-SecureBootUEFI | Returns True |
| BitLocker | Get-BitLockerVolume | ProtectionStatus = On |
| AppLocker | Get-AppLockerPolicy | RuleCollection count > 0 |
| Firewall | Get-NetFirewallProfile | All profiles enabled |
| UAC | Registry query | ConsentPromptBehaviorAdmin >= 2 |

## Blocked Software Patterns
chrome, firefox, spotify, steam, vlc, zoom, slack, dropbox, itunes, whatsapp, telegram

## Dependencies
No external packages — Python standard library only.
Requires: Windows 10/11 Enterprise with PowerShell 5.1+
