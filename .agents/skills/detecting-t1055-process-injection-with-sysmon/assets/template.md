# T1055 Process Injection Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-INJECT-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> Adversaries are injecting malicious code into legitimate system processes to evade detection and execute with elevated privileges.

## Injection Findings

| # | Time | Host | Source Process | Target Process | Event Type | Access Mask | Technique | Severity |
|---|------|------|---------------|----------------|------------|-------------|-----------|----------|
| 1 | | | | | | | | |

## Process Tampering Findings

| # | Time | Host | Image | Tampering Type | Severity |
|---|------|------|-------|----------------|----------|
| 1 | | | | | |

## Recommendations
1. **Isolate**: [Affected endpoints]
2. **Analyze**: [Memory dumps of injected processes]
3. **Detect**: [New Sysmon rules for observed patterns]
4. **Harden**: [Credential Guard, PPL for LSASS]
