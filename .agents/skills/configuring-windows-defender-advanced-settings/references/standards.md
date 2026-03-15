# Standards & References - Configuring Windows Defender Advanced Settings

## Primary Standards

### Microsoft Defender for Endpoint Documentation
- **Publisher**: Microsoft
- **URL**: https://learn.microsoft.com/en-us/defender-endpoint/
- **Scope**: Complete reference for MDE deployment, configuration, and management
- **Key sections**: ASR rules, exploit protection, network protection, controlled folder access

### MITRE ATT&CK Mapping for ASR Rules
- **Relevance**: Each ASR rule maps to specific ATT&CK techniques it mitigates
- **Key mappings**:
  - Block Office child processes → T1566.001 (Spearphishing Attachment)
  - Block credential stealing from LSASS → T1003.001 (OS Credential Dumping: LSASS)
  - Block PSExec/WMI → T1047 (WMI), T1570 (Lateral Tool Transfer)
  - Block WMI persistence → T1546.003 (WMI Event Subscription)

### CIS Microsoft Windows 11 Benchmark - Section 18.10
- **Publisher**: CIS
- **Relevance**: CIS benchmark sections covering Windows Defender configuration settings

## Compliance Mappings

| Framework | Requirement | MDE Coverage |
|-----------|------------|-------------|
| PCI DSS 4.0 | 5.2 - Anti-malware mechanisms | Defender AV + ASR rules + cloud protection |
| PCI DSS 4.0 | 5.3.1 - Anti-malware kept current | Automatic signature and engine updates |
| NIST 800-53 | SI-3 Malicious Code Protection | Defender real-time protection + BAFS |
| NIST 800-53 | SI-4 System Monitoring | MDE telemetry + advanced hunting |
| HIPAA | 164.308(a)(5)(ii)(B) - Malware protection | Defender AV + ransomware protection |
| ISO 27001 | A.12.2.1 - Controls against malware | Full MDE stack |
| ACSC E8 | Configure Microsoft Office macro settings | ASR rules for Office macro blocking |

## ASR Rule Reference

| GUID | Rule Name | Recommended Mode |
|------|----------|-----------------|
| BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 | Block executable content from email | Block |
| D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Block Office child processes | Block |
| 3B576869-A4EC-4529-8536-B80A7769E899 | Block Office from creating executables | Block |
| 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Block Office from injecting into processes | Block |
| D3E037E1-3EB8-44C8-A917-57927947596D | Block JS/VBS launching executables | Block |
| 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC | Block obfuscated scripts | Audit first |
| 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B | Block Win32 API calls from macros | Block |
| 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | Block credential stealing from LSASS | Block |
| D1E49AAC-8F56-4280-B9BA-993A6D77406C | Block PSExec/WMI process creation | Audit first |
| B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 | Block untrusted USB processes | Block |
| E6DB77E5-3DF2-4CF1-B95A-636979351E5B | Block WMI event subscription persistence | Block |
| 56A863A9-875E-4185-98A7-B882C64B5CE5 | Block vulnerable signed drivers | Block |

## Supporting References

- **ASR Rules Reference**: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- **Controlled Folder Access**: https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders
- **Network Protection**: https://learn.microsoft.com/en-us/defender-endpoint/network-protection
- **Exploit Protection**: https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection
