# Workflows - Implementing Application Whitelisting with AppLocker

## Workflow 1: Initial AppLocker Deployment

```
[Application Inventory]
    │
    ├── Scan reference endpoints for installed applications
    ├── Catalog all approved software by publisher/path/hash
    ├── Identify admin tools vs. standard user applications
    │
    ▼
[Policy Design]
    │
    ├── Create default allow rules (Program Files, Windows)
    ├── Create publisher rules for third-party vendors
    ├── Create deny rules for LOLBins (standard users only)
    ├── Create script control rules
    │
    ▼
[Audit Mode Deployment]
    │
    ├── Deploy via GPO to pilot OU (Audit Only)
    ├── Enable Application Identity service
    ├── Monitor for 2-4 weeks
    │
    ▼
[Audit Log Analysis]
    │
    ├── Export blocked events (8003, 8006)
    ├── Identify legitimate applications being blocked
    │
    ├── Blocked app is legitimate ──► [Create allow rule]
    │                                       │
    │                                       ▼
    │                                  [Re-audit 1 week]
    │
    └── All blocked apps are unauthorized ──► [Proceed to enforcement]
                                                    │
                                                    ▼
                                               [Switch to Enforce mode (phased)]
                                                    │
                                                    ├── Week 1: EXE rules
                                                    ├── Week 2: Script rules
                                                    ├── Week 3: MSI rules
                                                    └── Week 4: DLL rules (optional)
```

## Workflow 2: New Application Approval

```
[User requests new application]
    │
    ▼
[Security review of application]
    │
    ├── Is it signed by trusted publisher? ──► [Create publisher rule]
    │
    ├── Unsigned but necessary? ──► [Create hash rule + document exception]
    │
    └── Fails security review ──► [Deny request, document reason]
    │
    ▼
[Add rule to AppLocker GPO]
    │
    ▼
[Deploy to pilot OU, verify no conflicts]
    │
    ▼
[Deploy to production OU]
    │
    ▼
[Update application inventory]
```

## Workflow 3: AppLocker Bypass Incident Response

```
[Detection: Unauthorized execution despite AppLocker]
    │
    ▼
[Identify bypass technique]
    │
    ├── LOLBin not blocked ──► [Add deny rule for specific binary]
    │
    ├── Execution from allowed path ──► [Restrict path rule scope]
    │
    ├── Admin user bypass ──► [Evaluate WDAC migration for admin enforcement]
    │
    └── DLL side-loading ──► [Enable DLL rules or deploy WDAC]
    │
    ▼
[Update AppLocker policy with fix]
    │
    ▼
[Verify fix in audit mode on test endpoint]
    │
    ▼
[Deploy fix to production]
    │
    ▼
[Update threat model and rule documentation]
```

## Workflow 4: AppLocker to WDAC Migration

```
[Decision: Migrate from AppLocker to WDAC]
    │
    ▼
[Audit current AppLocker policy]
    │
    ├── Export AppLocker rules as XML
    ├── Identify rules that need WDAC equivalents
    │
    ▼
[Create WDAC policy using WDAC Wizard]
    │
    ├── Convert publisher rules to WDAC signer rules
    ├── Convert path rules to WDAC filepath rules
    ├── Add Microsoft recommended block rules
    │
    ▼
[Deploy WDAC in Audit mode alongside AppLocker]
    │
    ▼
[Monitor WDAC audit events for 4 weeks]
    │
    ▼
[Resolve WDAC audit findings]
    │
    ▼
[Switch WDAC to Enforce mode]
    │
    ▼
[Disable AppLocker policy]
```
