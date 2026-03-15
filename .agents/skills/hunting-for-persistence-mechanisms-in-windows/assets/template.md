# Windows Persistence Hunt Template

## Hunt Metadata

| Field | Value |
|-------|-------|
| Hunt ID | TH-PERSIST-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis

> [e.g., "Adversaries have established persistence via registry Run keys or WMI event subscriptions on compromised endpoints."]

## Persistence Categories Investigated

- [ ] T1547.001 - Registry Run Keys / Startup Folder
- [ ] T1543.003 - Windows Services
- [ ] T1053.005 - Scheduled Tasks
- [ ] T1546.003 - WMI Event Subscriptions
- [ ] T1546.015 - COM Hijacking
- [ ] T1546.012 - IFEO Injection
- [ ] T1546.010 - AppInit DLLs
- [ ] T1547.004 - Winlogon Helper
- [ ] T1547.005 - Security Support Provider
- [ ] T1574.001 - DLL Search Order Hijacking

## Registry Persistence Findings

| # | Host | Key Path | Value | Modifying Process | Signed? | Risk | Verdict |
|---|------|----------|-------|-------------------|---------|------|---------|
| 1 | | | | | | | |

## Service Persistence Findings

| # | Host | Service Name | Binary Path | Account | Start Type | Risk | Verdict |
|---|------|-------------|-------------|---------|-----------|------|---------|
| 1 | | | | | | | |

## Scheduled Task Findings

| # | Host | Task Name | Action | Trigger | Risk | Verdict |
|---|------|-----------|--------|---------|------|---------|
| 1 | | | | | | |

## WMI Subscription Findings

| # | Host | Filter | Consumer | Binding | Risk | Verdict |
|---|------|--------|----------|---------|------|---------|
| 1 | | | | | | |

## Summary

| Persistence Type | Total Found | Malicious | Suspicious | Benign |
|-----------------|-------------|-----------|------------|--------|
| Registry | | | | |
| Services | | | | |
| Scheduled Tasks | | | | |
| WMI | | | | |
| COM Hijack | | | | |
| Other | | | | |

## Recommendations

1. **Remove Malicious Persistence**: [Specific entries to remove]
2. **Harden**: [GPO restrictions, Sysmon rules to add]
3. **Monitor**: [New detection rules for identified gaps]
