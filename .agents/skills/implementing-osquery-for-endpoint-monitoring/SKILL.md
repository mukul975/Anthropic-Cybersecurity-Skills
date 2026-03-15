---
name: implementing-osquery-for-endpoint-monitoring
description: >-
  Deploy osquery scheduled queries for continuous endpoint monitoring covering process inventory,
  network connections, file integrity, and persistence mechanisms. Generates osquery.conf with
  query packs, configures differential result logging, and analyzes query results to detect
  suspicious processes, unauthorized listeners, and file modifications in system directories.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, osquery, for, endpoint]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install requests` (osquery installed on endpoints)
2. Generate `osquery.conf` with scheduled query packs for:
   - Process monitoring: new processes, unusual parent-child relationships
   - Network listeners: unexpected listening ports and outbound connections
   - File integrity: modifications in /etc, /usr/bin, system32
   - Persistence: cron jobs, startup items, scheduled tasks, services
3. Deploy configuration to endpoints.
4. Analyze differential results from osquery log output.
5. Generate security findings report.

```bash
python scripts/agent.py --results-dir /var/log/osquery/results/ --output osquery_report.json
```

## Examples

### Osquery Scheduled Query
```json
{"schedule": {"process_snapshot": {"query": "SELECT pid, name, path, cmdline, uid FROM processes WHERE on_disk = 0;", "interval": 300}}}
```
