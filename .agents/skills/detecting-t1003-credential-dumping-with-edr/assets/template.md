# T1003 Credential Dumping Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-CRED-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> An adversary with elevated privileges is dumping credentials from LSASS memory, SAM database, or NTDS.dit to enable lateral movement and privilege escalation.

## LSASS Access Findings

| # | Time | Host | Source Process | Access Mask | User | Severity |
|---|------|------|---------------|-------------|------|----------|
| 1 | | | | | | |

## Credential Tool Detections

| # | Time | Host | Tool | Command Line | Technique | Severity |
|---|------|------|------|-------------|-----------|----------|
| 1 | | | | | | |

## Impact Assessment
- [ ] LSASS memory potentially dumped
- [ ] Local SAM hashes at risk
- [ ] Domain NTDS.dit compromised
- [ ] Service account credentials exposed
- [ ] Kerberos tickets extracted

## Recommendations
1. **Reset**: [All credentials on affected systems]
2. **Enable**: [Credential Guard, RunAsPPL, ASR rules]
3. **Investigate**: [Lateral movement from compromised credentials]
4. **Rotate**: [KRBTGT if domain-level compromise]
