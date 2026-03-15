# Malware Eradication Report

## Incident Information
| Field | Value |
|-------|-------|
| Incident ID | |
| Malware Family | |
| Eradication Date | YYYY-MM-DD |
| Eradication Lead | |
| Systems Affected | [count] |

## Artifacts Removed

### Malware Files
| System | File Path | SHA256 | Removal Status |
|--------|-----------|--------|----------------|
| | | | Removed/Failed |

### Persistence Mechanisms Removed
| System | Type | Location | Details | Status |
|--------|------|----------|---------|--------|
| | Registry | | | |
| | Scheduled Task | | | |
| | Service | | | |
| | WMI Subscription | | | |
| | Cron Job | | | |

### Accounts Remediated
| Account | Type | Action | Status |
|---------|------|--------|--------|
| | User/Service/Admin | Disabled/Reset/Deleted | |

## Credential Rotation
- [ ] KRBTGT password reset (first reset)
- [ ] KRBTGT password reset (second reset, 12+ hours later)
- [ ] Domain admin passwords rotated
- [ ] Service account passwords rotated
- [ ] Compromised user passwords reset
- [ ] API keys/tokens revoked and reissued
- [ ] SSL/TLS certificates rotated (if compromised)

## Root Cause Remediation
| Vulnerability | CVE | Patch/Fix Applied | Verified |
|--------------|-----|-------------------|----------|
| | | | Yes/No |

## Validation Results
- [ ] Full EDR scan clean on all systems
- [ ] YARA scan clean on all systems
- [ ] No suspicious autostart entries remain
- [ ] No unauthorized processes running
- [ ] No unauthorized network connections
- [ ] All patches verified applied
- [ ] Credential rotation confirmed

## Systems Cleared for Recovery
| System | Eradication Method | Validation Status | Cleared By |
|--------|-------------------|-------------------|------------|
| | Clean/Re-image | Pass/Fail | |

## Approvals
| Role | Name | Date |
|------|------|------|
| Incident Commander | | |
| Forensic Analyst | | |
