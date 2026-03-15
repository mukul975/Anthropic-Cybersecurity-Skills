# Workflows - Metasploit Vulnerability Exploitation

## Workflow 1: Vulnerability Validation Pipeline

```
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ Import Scan   │──>│ Filter Top    │──>│ Search MSF    │
│ Results to DB │   │ Priority CVEs │   │ Modules       │
└───────────────┘   └───────────────┘   └───────────────┘
                                              │
       ┌─────────────────────────────────────┘
       v
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ Run `check`   │──>│ Exploit if    │──>│ Document      │
│ Command       │   │ Authorized    │   │ Evidence      │
└───────────────┘   └───────────────┘   └───────────────┘
       │
       v
┌───────────────┐   ┌───────────────┐
│ Update Risk   │──>│ Prioritize    │
│ Assessment    │   │ Remediation   │
└───────────────┘   └───────────────┘
```

## Workflow 2: Patch Verification

```
Patch Deployed
    │
    ├──> Re-run `check` command against patched host
    │        │
    │        ├──> NOT VULNERABLE → Patch verified ✓
    │        └──> STILL VULNERABLE → Patch failed ✗
    │                 │
    │                 └──> Escalate to remediation team
    │
    └──> Re-run auxiliary scanner
             │
             ├──> No findings → Remediation confirmed
             └──> Findings persist → Incomplete patch
```

## Workflow 3: Metasploit Module Selection

```
CVE Identified
    │
    ├──> search cve:CVE-YYYY-NNNNN
    │        │
    │        ├──> Exploit module found → Use for validation
    │        ├──> Auxiliary scanner found → Use for bulk check
    │        └──> No module found → Manual validation required
    │
    └──> Alternative: search for related modules
             │
             ├──> search type:exploit platform:windows target:smb
             └──> search type:auxiliary name:scanner
```
