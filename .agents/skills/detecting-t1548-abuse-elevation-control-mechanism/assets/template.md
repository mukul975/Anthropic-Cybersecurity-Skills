# T1548 Elevation Control Abuse Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-UAC-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> Adversaries are bypassing User Account Control or other elevation mechanisms to gain administrative privileges without triggering user consent prompts.

## Registry Modification Findings

| # | Time | Host | Registry Key | Value Set | Modifying Process | Severity |
|---|------|------|-------------|-----------|-------------------|----------|
| 1 | | | | | | |

## Auto-Elevate Process Abuse

| # | Time | Host | Auto-Elevate Binary | Unexpected Parent | Child Process | Severity |
|---|------|------|--------------------|--------------------|---------------|----------|
| 1 | | | | | | |

## Recommendations
1. **Remediate**: [Revert registry modifications]
2. **Investigate**: [Actions taken with elevated privileges]
3. **Harden**: [Set UAC to Always Notify, deploy ASR rules]
4. **Monitor**: [Registry keys and auto-elevate process chains]
