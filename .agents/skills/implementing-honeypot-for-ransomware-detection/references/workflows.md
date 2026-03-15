# Workflows - Honeypot for Ransomware Detection

## Workflow 1: Canary File Deployment

```
Start
  |
  v
[Inventory all file shares] --> Map share names, paths, user population
  |
  v
[Select canary file placement strategy]
  |-- Root of each share (first files encrypted)
  |-- Key subdirectories (finance, HR, executive)
  |-- Alphabetically early names (!_, 000_, AAA_)
  |
  v
[Generate canary files with realistic content]
  |-- .docx, .xlsx, .pdf formats
  |-- Realistic filenames matching share context
  |-- Hidden attribute to prevent user interaction
  |
  v
[Deploy monitoring]
  |-- FSRM file screens for ransomware extensions
  |-- FileSystemWatcher for canary file changes
  |-- Audit logging on canary files
  |
  v
[Integrate with SIEM and automated containment]
  |
  v
[Test with controlled encryption tool]
  |
  v
End
```

## Workflow 2: Honeypot Alert Response

```
Canary Alert Triggered
  |
  v
[Identify source IP and user from alert]
  |
  v
[Automated containment (within 30 seconds)]
  |-- NAC: Quarantine source IP
  |-- EDR: Isolate endpoint
  |-- AD: Disable user account
  |
  v
[SOC validates alert]
  |-- Check for legitimate activity (file migration, AV scan)
  |-- If FP --> Restore access, tune alerting
  |-- If TP --> Escalate to IR team
  |
  v
[IR team assesses scope]
  |-- How many canary files triggered?
  |-- How many endpoints involved?
  |-- Is encryption spreading?
  |
  v
[Full incident response activation]
  |
  v
End
```
