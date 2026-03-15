# WMI Subscription Persistence Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-WMI-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> Adversaries have established persistence via WMI permanent event subscriptions to execute malicious code triggered by system events such as startup or user logon.

## WMI Subscription Findings

| # | Host | Subscription Name | Filter Query | Consumer Type | Consumer Action | Severity |
|---|------|-------------------|-------------|---------------|----------------|----------|
| 1 | | | | | | |

## WmiPrvSe.exe Child Process Findings

| # | Host | Child Process | Command Line | User | Timestamp |
|---|------|--------------|-------------|------|-----------|
| 1 | | | | | |

## Recommendations
1. **Remove**: [Malicious WMI subscriptions]
2. **Investigate**: [Initial infection vector]
3. **Harden**: [Restrict WMI subscription creation]
4. **Monitor**: [Deploy Sysmon Events 19/20/21 rules]
