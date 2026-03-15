# Workflows - Runtime Security with Tetragon

## Deployment Workflow

### Phase 1: Observation Mode
1. Install Tetragon with default TracingPolicies (no enforcement)
2. Collect baseline process execution data for 7-14 days
3. Analyze event patterns to identify normal vs anomalous behavior
4. Document expected processes per namespace and workload type

### Phase 2: Detection Policies
1. Create TracingPolicies for known attack patterns (container escape, privilege escalation)
2. Configure event export to SIEM (Elasticsearch, Splunk, or Datadog)
3. Build alerting rules based on TracingPolicy matches
4. Validate detection accuracy with red team exercises

### Phase 3: Enforcement
1. Enable Sigkill actions for high-confidence threats (known malware binaries)
2. Enable Override actions for dangerous syscalls in non-privileged containers
3. Implement graduated response -- alert first, block after confirmation
4. Monitor enforcement actions for false positives

## TracingPolicy Development Workflow

```
1. Identify Threat -> Map to MITRE ATT&CK technique
2. Determine Kernel Hook -> kprobe, tracepoint, or LSM hook
3. Define Selectors -> Binary, namespace, capability filters
4. Set Action -> Post (observe), Sigkill (block), Override (deny)
5. Test in Staging -> Deploy to non-production namespace first
6. Validate with Attack Simulation -> Confirm detection
7. Deploy to Production -> Apply via GitOps
8. Monitor False Positives -> Tune selectors as needed
```

## Incident Response Integration

### When Tetragon Detects a Threat
1. Event is generated with full context (pod, namespace, binary, args, capabilities)
2. Event exported to SIEM via JSON log export or Prometheus metric
3. SOAR platform receives alert and triggers playbook
4. Automated actions: isolate pod network (via Cilium NetworkPolicy), capture forensic data
5. Security team receives enriched alert with Kubernetes context

### Forensic Data Collection
```bash
# Export recent events for a specific pod
tetra getevents --namespace <ns> --pod <pod-name> \
  --since 1h -o json > /forensics/tetragon-events.json

# Get process tree for suspicious activity
tetra getevents --process-pid <pid> --ancestors 5 -o compact
```

## Operational Runbook

### Daily Checks
- Review `tetragon_missed_events_total` metric for event buffer overflows
- Check Tetragon DaemonSet health across all nodes
- Review new TracingPolicy match counts

### Weekly Checks
- Analyze top 10 most frequent event types
- Review enforcement action logs for false positives
- Update TracingPolicies based on new threat intelligence

### Monthly Checks
- Performance impact assessment (CPU/memory overhead per node)
- TracingPolicy effectiveness review with red team
- Update Tetragon to latest stable release
