# Windows Defender Advanced Configuration Template

## Environment Information

| Field | Value |
|-------|-------|
| Endpoint OS | Windows 10/11 Enterprise |
| MDE License | E5 / Defender P2 / Standalone |
| Deployment Method | Intune / SCCM / GPO |
| Configuration Date | |
| Configured By | |

## ASR Rule Configuration

| GUID | Rule Name | Mode | Exclusions |
|------|----------|------|------------|
| BE9BA2D9-... | Block executable content from email | Block / Audit | |
| D4F940AB-... | Block Office child processes | Block / Audit | |
| 3B576869-... | Block Office executable creation | Block / Audit | |
| 75668C1F-... | Block Office code injection | Block / Audit | |
| D3E037E1-... | Block JS/VBS launching executables | Block / Audit | |
| 5BEB7EFE-... | Block obfuscated scripts | Block / Audit | |
| 92E97FA1-... | Block Win32 API from macros | Block / Audit | |
| 9E6C4E1F-... | Block LSASS credential stealing | Block / Audit | |
| D1E49AAC-... | Block PSExec/WMI processes | Block / Audit | |
| B2B3F03D-... | Block untrusted USB processes | Block / Audit | |
| E6DB77E5-... | Block WMI persistence | Block / Audit | |
| 56A863A9-... | Block vulnerable signed drivers | Block / Audit | |

## Controlled Folder Access

| Setting | Value |
|---------|-------|
| Mode | Enabled / Audit |
| Protected Folders | Default + custom |
| Allowed Applications | |

### Custom Protected Folders

| Path | Justification |
|------|--------------|
| | |

### Allowed Applications

| Application Path | Reason |
|-----------------|--------|
| | |

## Network Protection

| Setting | Value |
|---------|-------|
| Network Protection | Enabled / Audit |
| Web Content Filtering | Enabled / Disabled |
| Blocked Categories | |

## Cloud Protection

| Setting | Value |
|---------|-------|
| MAPS Reporting | Advanced |
| Sample Submission | SendAllSamples |
| Block at First Sight | Enabled |
| Cloud Block Level | High |
| Cloud Timeout | 50 seconds |
| Tamper Protection | On |

## Exclusions Register

| Type | Value | Reason | Approved By | Review Date |
|------|-------|--------|-------------|-------------|
| Path | | | | |
| Process | | | | |
| Extension | | | | |

## Validation Checklist

- [ ] All ASR rules active (Block or Audit)
- [ ] Controlled Folder Access enabled
- [ ] Network Protection enabled
- [ ] Cloud protection set to Advanced
- [ ] Tamper Protection enabled in M365 portal
- [ ] Signature update interval set to hourly
- [ ] PUA protection enabled
- [ ] No excessive exclusions configured

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Security Engineer | | |
| Endpoint Admin | | |
