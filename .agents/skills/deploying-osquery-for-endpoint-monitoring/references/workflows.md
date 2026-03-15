# Workflows

## Workflow 1: Osquery Fleet Deployment
```
[Install FleetDM server] → [Generate enrollment secret]
  → [Package osquery with fleet config] → [Deploy to pilot group]
  → [Verify enrollment and scheduled queries] → [Deploy to production]
  → [Create dashboards from query results] → [Ongoing monitoring]
```

## Workflow 2: Threat Hunt with Osquery
```
[Define hypothesis] → [Write SQL query targeting hypothesis]
  → [Execute via FleetDM live query across fleet]
  → [Analyze results] → [Investigate anomalies]
  → [Document findings] → [Create scheduled detection if recurrent]
```
