# Lateral Movement Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-LATMOV-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> [e.g., "Adversaries are moving laterally via SMB admin shares using compromised domain admin credentials."]

## Techniques Investigated
- [ ] T1021.001 - RDP
- [ ] T1021.002 - SMB/Admin Shares
- [ ] T1021.006 - WinRM
- [ ] T1047 - WMI
- [ ] T1569.002 - PsExec/Service Execution
- [ ] T1550.002 - Pass the Hash
- [ ] T1570 - Lateral Tool Transfer

## Lateral Movement Path Map

```
[Source A] --RDP--> [Host B] --SMB--> [Host C] --WMI--> [Host D]
     |                                    |
     +--PsExec--> [Host E]               +--WinRM--> [Server F]
```

## Findings

| # | Source | Destination | Account | Method | Logon Type | Time | Risk |
|---|--------|------------|---------|--------|-----------|------|------|
| 1 | | | | | | | |

## Affected Accounts
| Account | Type | Hosts Accessed | Movement Method |
|---------|------|---------------|----------------|
| | | | |

## Recommendations
1. **Containment**: [Isolate systems, disable accounts]
2. **Credential Reset**: [Scope of password resets needed]
3. **Detection**: [New rules for identified patterns]
