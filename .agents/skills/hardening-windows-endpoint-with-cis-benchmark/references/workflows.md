# Workflows - Hardening Windows Endpoint with CIS Benchmark

## Workflow 1: Initial Baseline Deployment

```
[Select Windows Version & CIS Benchmark]
    │
    ▼
[Choose Profile Level (L1 or L2)]
    │
    ▼
[Download CIS Build Kit GPOs from CIS WorkBench]
    │
    ▼
[Import GPOs into Active Directory via GPMC]
    │
    ▼
[Link GPO to Pilot OU with 5-10 test endpoints]
    │
    ▼
[Run CIS-CAT assessment on pilot endpoints]
    │
    ├── Score >= 95% ──► [Test application compatibility for 2 weeks]
    │                         │
    │                         ├── No issues ──► [Deploy GPO to production OUs]
    │                         │
    │                         └── Issues found ──► [Document exceptions, add compensating controls]
    │                                                  │
    │                                                  ▼
    │                                              [Redeploy with exceptions]
    │
    └── Score < 95% ──► [Investigate GPO application failures]
                              │
                              ▼
                         [Fix WMI filters, security filtering, or GPO precedence]
                              │
                              ▼
                         [Re-run CIS-CAT assessment]
```

## Workflow 2: Continuous Compliance Monitoring

```
[Weekly CIS-CAT Scheduled Scan]
    │
    ▼
[Parse XML results → ingest into SIEM]
    │
    ▼
[Compare against baseline score]
    │
    ├── Score drift > 2% ──► [Generate compliance drift alert]
    │                              │
    │                              ▼
    │                         [Identify changed settings via GPResult /H]
    │                              │
    │                              ▼
    │                         [Determine if change was authorized]
    │                              │
    │                              ├── Authorized ──► [Update baseline, document exception]
    │                              │
    │                              └── Unauthorized ──► [Revert change, investigate as security incident]
    │
    └── Score stable ──► [Log compliance status, update dashboard]
```

## Workflow 3: New CIS Benchmark Version Upgrade

```
[CIS releases new benchmark version]
    │
    ▼
[Download updated benchmark and Build Kit]
    │
    ▼
[Diff new vs. current benchmark recommendations]
    │
    ▼
[Identify new/changed/removed recommendations]
    │
    ▼
[Impact assessment: Will new settings break applications?]
    │
    ├── Yes ──► [Lab test, document new exceptions]
    │
    └── No ──► [Update GPO with new Build Kit]
                    │
                    ▼
               [Deploy to pilot OU first]
                    │
                    ▼
               [Run CIS-CAT with new benchmark profile]
                    │
                    ▼
               [Production rollout after 2-week pilot]
```

## Workflow 4: Standalone Endpoint Hardening (Non-Domain)

```
[Identify standalone Windows endpoint]
    │
    ▼
[Download LGPO.exe from Microsoft SCT]
    │
    ▼
[Export CIS Build Kit GPO to local policy format]
    │
    ▼
[Apply via LGPO.exe: LGPO.exe /g C:\CIS-Policy]
    │
    ▼
[Run CIS-CAT Lite assessment]
    │
    ▼
[Document results and exceptions]
    │
    ▼
[Schedule quarterly manual reassessment]
```
