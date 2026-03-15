# Credential Dumping Hunt Template

## Hunt Metadata

| Field | Value |
|-------|-------|
| Hunt ID | TH-CRED-DUMP-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis

> [e.g., "Adversaries have used Mimikatz or similar tools to dump LSASS memory on compromised endpoints to harvest domain credentials."]

## Target Techniques

- [ ] T1003.001 - LSASS Memory
- [ ] T1003.002 - SAM Database
- [ ] T1003.003 - NTDS.dit
- [ ] T1003.004 - LSA Secrets
- [ ] T1003.005 - Cached Domain Credentials
- [ ] T1003.006 - DCSync

## Data Sources

- [ ] Sysmon Event ID 10 (Process Access)
- [ ] Sysmon Event ID 1 (Process Creation)
- [ ] Windows Security 4656/4663
- [ ] Windows Security 4662 (DCSync)
- [ ] EDR Telemetry: _______________

## LSASS Access Findings

| # | Timestamp | Host | User | Source Process | Access Mask | Risk | Verdict |
|---|-----------|------|------|---------------|-------------|------|---------|
| 1 | | | | | | | |
| 2 | | | | | | | |

## Tool Detection Findings

| # | Timestamp | Host | User | Tool | Command Line | Technique | Verdict |
|---|-----------|------|------|------|-------------|-----------|---------|
| 1 | | | | | | | |
| 2 | | | | | | | |

## DCSync Findings

| # | Timestamp | Source Host | User | Replication Right | Is Legitimate DC? | Verdict |
|---|-----------|------------|------|-------------------|-------------------|---------|
| 1 | | | | | | |

## Compromised Credentials Assessment

| Account | Type | Hash Type | Exposure Scope | Reset Required? |
|---------|------|-----------|---------------|----------------|
| | | | | |

## Recommendations

1. **Immediate Actions**: [Password resets, account lockouts]
2. **Containment**: [Isolate affected systems]
3. **Detection Improvements**: [New rules, LSASS protection]
4. **Hardening**: [Credential Guard, PPL, ASR rules]
