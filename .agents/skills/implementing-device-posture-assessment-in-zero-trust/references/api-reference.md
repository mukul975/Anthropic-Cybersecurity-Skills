# API Reference: Device Posture Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| (stdlib only) | Python 3.8+ | Platform detection, subprocess for OS security checks |

## CLI Usage

```bash
python scripts/agent.py --output-dir /reports/ --output device_posture.json
```

## Functions

### `check_os_version() -> dict`
Uses `platform.system()`, `platform.version()` for OS identification.

### `check_disk_encryption() -> dict`
Windows: `manage-bde -status C:` (BitLocker). macOS: `fdesetup status` (FileVault). Linux: `lsblk` for LUKS.

### `check_firewall_status() -> dict`
Windows: `netsh advfirewall show allprofiles state`. Linux: `ufw status`.

### `check_antivirus() -> dict`
Windows: PowerShell `Get-MpComputerStatus` for Defender real-time protection.

### `check_screen_lock() -> dict`
Windows: Registry `InactivityTimeoutSecs` check.

### `compute_posture_score(checks) -> dict`
Weighted scoring: encryption (25), firewall (20), AV (25), screen lock (15), OS (15). Returns COMPLIANT/PARTIAL/NON_COMPLIANT.

## Posture Checks

| Check | Weight | Tool |
|-------|--------|------|
| Disk Encryption | 25 | BitLocker/FileVault/LUKS |
| Firewall | 20 | Windows Firewall/UFW |
| Antivirus/EDR | 25 | Defender/endpoint agent |
| Screen Lock | 15 | OS policy |
| OS Supported | 15 | Platform detection |

## Output Schema

```json
{
  "hostname": "WORKSTATION-01",
  "posture": {"score": 85, "compliance": "COMPLIANT"},
  "recommendations": ["Enable disk encryption"]
}
```
