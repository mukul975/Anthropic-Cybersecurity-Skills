# Process Hollowing Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-HOLLOW-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> [e.g., "Adversaries have used process hollowing to inject malicious code into svchost.exe instances to evade detection."]

## Findings

| # | Host | Process | Parent | Expected Parent | Network Activity | Risk | Verdict |
|---|------|---------|--------|----------------|-----------------|------|---------|
| 1 | | | | | | | |

## Memory Analysis Results
| Process (PID) | Image Mismatch | Injected Code | VAD Anomaly | Verdict |
|--------------|----------------|---------------|-------------|---------|
| | | | | |

## Recommendations
1. **Memory Dump**: [Collect memory from affected hosts]
2. **Containment**: [Isolate compromised endpoints]
3. **Detection**: [Deploy Sysmon v13+ with Event ID 25]
4. **Prevention**: [Enable Attack Surface Reduction rules]
