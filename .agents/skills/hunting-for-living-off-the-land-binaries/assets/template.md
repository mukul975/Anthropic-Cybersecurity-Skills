# LOLBin Threat Hunt Template

## Hunt Metadata

| Field | Value |
|-------|-------|
| Hunt ID | TH-LOLBIN-YYYY-MM-DD-NNN |
| Analyst | |
| Date Started | |
| Date Completed | |
| Status | [ ] In Progress / [ ] Complete |
| Priority | [ ] Critical / [ ] High / [ ] Medium / [ ] Low |

## Hypothesis

> **Hypothesis Statement**: [e.g., "Adversaries are using certutil.exe to download second-stage payloads from external infrastructure, bypassing web proxy controls."]

**Basis for Hypothesis**:
- [ ] Threat Intelligence Report: [Reference]
- [ ] Previous Incident Finding
- [ ] MITRE ATT&CK Gap Analysis
- [ ] Red Team Exercise Result
- [ ] Anomaly in Monitoring Data

## Scope

**Target LOLBins**:
- [ ] certutil.exe (T1140)
- [ ] mshta.exe (T1218.005)
- [ ] rundll32.exe (T1218.011)
- [ ] regsvr32.exe (T1218.010)
- [ ] msiexec.exe (T1218.007)
- [ ] bitsadmin.exe (T1197)
- [ ] cmstp.exe (T1218.003)
- [ ] wmic.exe (T1047)
- [ ] msbuild.exe (T1127.001)
- [ ] installutil.exe (T1218.004)
- [ ] forfiles.exe (T1202)
- [ ] Other: _______________

**Time Range**: [Start Date/Time] to [End Date/Time]
**Endpoints in Scope**: [All / Specific OUs / High-Value Targets]
**Data Sources Used**:
- [ ] Sysmon Event ID 1 (Process Creation)
- [ ] Sysmon Event ID 3 (Network Connection)
- [ ] Sysmon Event ID 7 (Image Loaded)
- [ ] Sysmon Event ID 11 (File Create)
- [ ] Windows Security 4688
- [ ] EDR Telemetry: _______________
- [ ] Network Proxy Logs
- [ ] DNS Query Logs
- [ ] Firewall Logs

## Queries Executed

### Query 1: [Description]
```
[Query text]
```
**Results**: [Count] events returned
**Time to Execute**: [Duration]

### Query 2: [Description]
```
[Query text]
```
**Results**: [Count] events returned
**Time to Execute**: [Duration]

## Findings

### Finding 1
| Attribute | Details |
|-----------|---------|
| Severity | [ ] Critical / [ ] High / [ ] Medium / [ ] Low |
| LOLBin | |
| MITRE ATT&CK | |
| Host(s) | |
| User(s) | |
| Command Line | |
| Parent Process | |
| Network IOCs | |
| File IOCs | |
| Timestamp | |
| Evidence | |

**Analysis**: [Detailed description of finding]
**Verdict**: [ ] True Positive / [ ] False Positive / [ ] Benign True Positive

### Finding 2
| Attribute | Details |
|-----------|---------|
| Severity | |
| LOLBin | |
| MITRE ATT&CK | |
| Host(s) | |
| User(s) | |
| Command Line | |
| Parent Process | |
| Network IOCs | |
| File IOCs | |
| Timestamp | |
| Evidence | |

**Analysis**: [Detailed description]
**Verdict**: [ ] True Positive / [ ] False Positive / [ ] Benign True Positive

## IOC List

### Network IOCs
| Type | Value | Context |
|------|-------|---------|
| IP | | |
| Domain | | |
| URL | | |

### File IOCs
| Type | Value | Context |
|------|-------|---------|
| SHA256 | | |
| Filename | | |
| File Path | | |

### Behavioral IOCs
| LOLBin | Argument Pattern | Parent Process |
|--------|-----------------|----------------|
| | | |

## Hunt Results Summary

| Metric | Count |
|--------|-------|
| Total Events Analyzed | |
| Anomalies Identified | |
| True Positives | |
| False Positives | |
| Benign True Positives | |
| New IOCs Discovered | |
| Detection Rules Created | |
| Detection Rules Updated | |

## Recommendations

1. **Detection Improvements**: [New rules or tuning needed]
2. **Visibility Gaps**: [Missing data sources or coverage]
3. **Response Actions**: [Incidents to escalate, containment needed]
4. **Follow-up Hunts**: [Related hypotheses to investigate next]

## Hypothesis Outcome

- [ ] **Confirmed**: Evidence found supporting the hypothesis
- [ ] **Partially Confirmed**: Some evidence found, requires further investigation
- [ ] **Refuted**: No evidence found, hypothesis disproven
- [ ] **Inconclusive**: Insufficient data to confirm or refute
