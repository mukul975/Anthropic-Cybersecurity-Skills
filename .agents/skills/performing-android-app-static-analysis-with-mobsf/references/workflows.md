# Workflows: Android Static Analysis with MobSF

## Workflow 1: Standalone APK Assessment

```
[Obtain APK] --> [Deploy MobSF Docker] --> [Upload via API] --> [Run Static Scan]
     |                                                               |
     v                                                               v
[Verify APK integrity]                                    [Review Manifest Analysis]
[Check signing certificate]                               [Review Code Analysis]
                                                          [Review Binary Analysis]
                                                          [Review Network Analysis]
                                                                     |
                                                                     v
                                                          [Triage HIGH/CRITICAL findings]
                                                          [Validate false positives]
                                                          [Generate PDF report]
```

## Workflow 2: CI/CD Pipeline Integration

```
[Developer pushes code] --> [Build APK] --> [Upload to MobSF] --> [Static Scan]
                                                                      |
                                                          +-----------+-----------+
                                                          |                       |
                                                   [Score >= 60]           [Score < 60]
                                                          |                       |
                                                   [Pass gate]            [Fail build]
                                                   [Archive report]       [Notify developer]
                                                   [Continue pipeline]    [Block deployment]
```

## Workflow 3: Third-Party App Vetting

```
[Receive third-party APK] --> [MobSF Static Scan] --> [Automated scoring]
                                                            |
                                                            v
                                                    [Manual review of:]
                                                    - Excessive permissions
                                                    - Data exfiltration indicators
                                                    - Known malware signatures
                                                    - C2 communication patterns
                                                            |
                                                            v
                                                    [Risk assessment report]
                                                    [Approve/Reject for enterprise use]
```

## Workflow 4: Comparative Analysis Across Versions

```
[APK v1.0] --> [MobSF Scan] --> [Baseline report]
                                       |
[APK v2.0] --> [MobSF Scan] --> [Compare findings] --> [New vulnerabilities introduced?]
                                       |                        |
                                       v                 [Yes: Block release]
                                [Regression report]      [No: Approve release]
```

## Decision Matrix: When to Escalate

| Finding Severity | MobSF Category | Action |
|-----------------|----------------|--------|
| CRITICAL | Hardcoded production API keys | Immediate key rotation, block release |
| HIGH | Exported activity with sensitive data | Manual verification, fix before release |
| MEDIUM | Missing certificate pinning | Add to sprint backlog, risk acceptance if internal app |
| LOW | Debug logging of non-sensitive data | Track in issue tracker, fix in next release |
| INFO | Missing ProGuard rules | Recommend but do not block |
