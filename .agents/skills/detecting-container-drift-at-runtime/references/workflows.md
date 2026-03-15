# Workflows - Container Drift Detection

## Detection Workflow

1. Container image deployed with known-good state
2. Runtime monitor (Falco/Sysdig) tracks all process executions and file changes
3. Events compared against baseline: original image manifest + expected runtime behavior
4. Drift events classified by severity (binary drift = HIGH, config drift = MEDIUM)
5. Alerts sent to SIEM/SOC with full container context
6. Automated response: isolate pod network, capture forensics, evict pod

## Implementation Phases

### Phase 1: Visibility (Weeks 1-2)
- Deploy Falco with drift detection rules in alert-only mode
- Collect baseline of normal container behavior per workload
- Identify legitimate runtime changes (log files, temp files, caches)
- Create allowlists for expected runtime modifications

### Phase 2: Detection (Weeks 3-4)
- Enable drift detection alerts with tuned thresholds
- Integrate with SIEM for correlation and dashboarding
- Build runbooks for drift investigation
- Conduct tabletop exercises with container drift scenarios

### Phase 3: Prevention (Weeks 5-8)
- Enable readOnlyRootFilesystem on all production workloads
- Deploy Pod Security Standards in enforce mode
- Implement image digest pinning in all manifests
- Enable automated pod eviction for confirmed drift events

## Incident Response for Drift Events

1. **Triage**: Is the drift from a legitimate operation or potential compromise?
2. **Contain**: Apply NetworkPolicy deny-all to affected pod
3. **Collect**: Capture container filesystem diff, process tree, network connections
4. **Analyze**: Compare drifted files against malware signatures and IoCs
5. **Remediate**: Delete compromised pod, scan all pods in namespace
6. **Recover**: Deploy clean image, verify no persistence mechanisms
