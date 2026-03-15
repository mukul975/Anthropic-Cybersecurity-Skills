# Workflows - LaZagne Credential Access

## Credential Harvesting Workflow

```
1. Pre-Execution
   ├── Verify access level (standard user vs. admin/SYSTEM)
   ├── Check AV/EDR status on target
   ├── Prepare output directory for results
   └── Plan exfiltration method for credential data

2. Execution
   ├── Run lazagne.exe all -oJ for full extraction
   ├── Run specific modules if full scan is too noisy
   ├── Elevate to SYSTEM if needed for DPAPI/LSA
   └── Collect output files

3. Analysis
   ├── Parse JSON output
   ├── Deduplicate credentials
   ├── Categorize by source (browser, email, system, etc.)
   └── Prioritize by value (domain creds > local > web)

4. Validation
   ├── Test domain credentials with CrackMapExec
   ├── Verify cloud credentials (AWS CLI, Azure CLI)
   ├── Check VPN/remote access credentials
   └── Map credentials to BloodHound attack paths

5. Lateral Movement
   ├── Use validated credentials for next hop
   ├── Repeat credential harvesting on new targets
   └── Document credential chain for report
```

## Module Execution Priority

```
High Priority (run first):
  browsers    → Web application credentials, SSO tokens
  windows     → Domain cached credentials, DPAPI
  sysadmin    → SSH keys, RDP credentials, PuTTY

Medium Priority:
  databases   → Database connection strings
  mails       → Email credentials for BEC
  git         → Source code repository access

Low Priority:
  wifi        → Network access but limited value
  chat        → Communication platform access
  svn         → Legacy source control
```
