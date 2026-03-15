# DLL Sideloading Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-SIDELOAD-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |

## Hypothesis
> [e.g., "Adversaries are using DLL sideloading with legitimate signed applications to execute malicious payloads while evading detection."]

## Findings
| # | Host | Application | Sideloaded DLL | DLL Path | Signed | Risk | Verdict |
|---|------|------------|---------------|----------|--------|------|---------|
| 1 | | | | | | | |

## Recommendations
1. **Block**: [Quarantine malicious DLLs]
2. **Harden**: [Application directory permissions, DLL safe search mode]
3. **Detect**: [Sysmon Event ID 7 rules for known targets]
