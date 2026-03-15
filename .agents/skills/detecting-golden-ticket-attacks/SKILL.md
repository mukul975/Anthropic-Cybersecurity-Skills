---
name: detecting-golden-ticket-attacks
description: >-
  Detect Kerberos golden ticket attacks by analyzing Windows Security event logs for anomalous
  TGT usage patterns. Parses Event IDs 4624, 4672, and 4768 from EVTX files to identify tickets
  with abnormal lifetimes, domain SID mismatches, and privilege escalation sequences where
  non-admin accounts receive admin-level privileges without corresponding group membership changes.
domain: cybersecurity
subdomain: security-operations
tags: [detecting, golden, ticket, attacks]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install python-evtx lxml`
2. Collect Windows Security EVTX logs from domain controllers.
3. Parse Event IDs:
   - 4768: Kerberos TGT requests (authentication service requests)
   - 4624: Logon events (look for LogonType 3 with NTLM or Kerberos)
   - 4672: Special privileges assigned (admin logon indicators)
4. Detect golden ticket indicators:
   - TGT with lifetime >10 hours (default max is 10h)
   - Event 4672 for accounts not in Domain Admins
   - Logon events with no corresponding 4768 TGT request
   - Domain SID inconsistencies in ticket data
5. Generate detection report with timeline reconstruction.

```bash
python scripts/agent.py --evtx-file /path/to/Security.evtx --output golden_ticket_report.json
```

## Examples

### Detect Anomalous Privilege Assignment
Event 4672 for a standard user account receiving SeDebugPrivilege, SeTcbPrivilege, or SeBackupPrivilege indicates potential golden ticket usage.

### TGT Without Corresponding AS-REQ
A logon event (4624) with Kerberos authentication but no matching 4768 (TGT request) on the DC suggests a forged TGT.
