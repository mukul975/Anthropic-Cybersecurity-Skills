# Falco Container Escape Detection Runbook

## Alert Triage Template

### Alert Details
| Field | Value |
|-------|-------|
| Alert Time | |
| Rule Name | |
| Priority | |
| Container Name | |
| Container Image | |
| Pod Name | |
| Namespace | |
| Node | |
| User | |
| Process Command | |
| MITRE Technique | |

## Triage Steps

### Immediate Actions (0-5 minutes)
- [ ] Acknowledge alert in SIEM/SOAR
- [ ] Verify alert is not a false positive (check known exceptions list)
- [ ] Identify the affected pod and node
- [ ] Check if the container is still running

### Investigation (5-30 minutes)
- [ ] Capture pod spec: `kubectl get pod <name> -n <ns> -o yaml`
- [ ] Review container security context
- [ ] Check if container is privileged
- [ ] Review mounted volumes for host paths
- [ ] Examine process tree from Falco output
- [ ] Check for other alerts from same container/node
- [ ] Review Kubernetes audit logs for the same timeframe

### Containment (if confirmed)
- [ ] Isolate pod with network policy deny-all
- [ ] Cordon affected node: `kubectl cordon <node>`
- [ ] Capture forensic data from container
- [ ] Kill compromised container: `kubectl delete pod <name> -n <ns>`
- [ ] Review other pods on same node for compromise

### Recovery
- [ ] Scan node for rootkits
- [ ] Rebuild node if compromise confirmed
- [ ] Patch vulnerable container image
- [ ] Update network policies
- [ ] Uncordon node after verification

## False Positive Exceptions

| Container Image | Rule | Justification | Approved By | Date |
|----------------|------|---------------|-------------|------|
| | | | | |

## Escalation Matrix

| Priority | Response Time | Notify |
|----------|--------------|--------|
| CRITICAL | Immediate | Security On-Call + Engineering Lead |
| WARNING | 15 minutes | Security On-Call |
| NOTICE | 1 hour | Security Team queue |
| INFO | Next business day | Review in daily standup |
