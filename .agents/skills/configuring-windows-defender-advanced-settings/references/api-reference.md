# Windows Defender Advanced Settings — API Reference

## PowerShell Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `Get-MpComputerStatus` | Defender service status, signature version |
| `Get-MpPreference` | All Defender configuration preferences |
| `Set-MpPreference` | Modify Defender settings |
| `Get-MpThreatDetection` | Recent threat detections |
| `Add-MpPreference -AttackSurfaceReductionRules_Ids` | Enable ASR rules |

## Critical ASR Rule GUIDs

| GUID | Rule |
|------|------|
| `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Block executable from email |
| `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Block Office child processes |
| `3b576869-a4ec-4529-8536-b80a7769e899` | Block Office executable creation |
| `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Block obfuscated scripts |
| `56a863a9-875e-4185-98a7-b882c64b5ce5` | Block exploited signed drivers |

## ASR Rule Actions

| Value | Action |
|-------|--------|
| 0 | Disabled |
| 1 | Block |
| 2 | Audit |
| 6 | Warn |

## External References

- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Defender PowerShell Reference](https://learn.microsoft.com/en-us/powershell/module/defender/)
- [Tamper Protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
