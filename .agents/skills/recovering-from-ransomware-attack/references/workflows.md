# Workflows - Recovering from Ransomware Attack

## Workflow 1: Recovery Decision and Planning

```
Containment Complete + Forensics Initiated
  |
  v
[Assess backup availability]
  |-- Immutable copies intact? --> Primary recovery path
  |-- Air-gapped copies available? --> Secondary recovery path
  |-- No clean backups? --> Consider decryption key (paid or NoMoreRansom)
  |
  v
[Determine recovery scope]
  |-- Full rebuild vs. selective restore
  |-- Identify minimum viable recovery set
  |
  v
[Map system dependencies]
  |-- AD/DNS -> Database -> Application -> Web
  |
  v
[Estimate recovery timeline per tier]
  |
  v
[Brief executive team on recovery plan and timeline]
  |
  v
[Begin recovery]
```

## Workflow 2: System Recovery Execution

```
[Establish clean recovery VLAN]
  |
  v
[Phase 1: Identity Recovery]
  |-- Restore DCs from verified backup
  |-- Reset krbtgt (2x)
  |-- Reset all admin passwords
  |-- Validate AD health (dcdiag)
  |
  v
[Phase 2: Critical Systems]
  |-- Restore databases
  |-- Verify data consistency
  |-- Restore core applications
  |-- Test application functionality
  |
  v
[Phase 3: Important Systems]
  |-- Restore in groups of 5-10
  |-- Validate each before proceeding
  |
  v
[Phase 4: Remaining Systems]
  |
  v
[Each system: Scan for persistence -> Patch -> Deploy EDR -> Connect]
  |
  v
[Post-recovery monitoring (7-14 days elevated alert)]
```
