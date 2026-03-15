# Tetragon Runtime Security Assessment Template

## Cluster Information

| Field | Value |
|-------|-------|
| Cluster Name | |
| Kubernetes Version | |
| Node Count | |
| Tetragon Version | |
| Kernel Version | |
| Assessment Date | |
| Assessed By | |

## Pre-Deployment Checklist

- [ ] Linux kernel version >= 5.4 (5.10+ preferred)
- [ ] BTF (BPF Type Format) enabled in kernel
- [ ] Helm 3.x installed and configured
- [ ] kubectl access with cluster-admin privileges
- [ ] SIEM/log aggregation endpoint configured
- [ ] Alerting channels established (PagerDuty, Slack, etc.)

## Deployment Configuration

### Helm Values

```yaml
tetragon:
  enableProcessCred: true
  enableProcessNs: true
  grpc:
    address: "localhost:54321"
  export:
    mode: "json"
  resources:
    limits:
      cpu: "1"
      memory: "1Gi"
    requests:
      cpu: "250m"
      memory: "256Mi"
```

## TracingPolicy Inventory

| Policy Name | Type | Hooks | Action | Target Namespaces |
|-------------|------|-------|--------|------------------|
| | kprobe/tracepoint | | Post/Sigkill/Override | |
| | | | | |
| | | | | |

## Baseline Metrics

| Metric | Value | Date Captured |
|--------|-------|--------------|
| Average events/sec per node | | |
| CPU overhead per node (%) | | |
| Memory usage per node (MB) | | |
| Event buffer miss rate | | |

## Detection Validation Results

| Attack Scenario | MITRE ATT&CK ID | Detected | Action Taken | Notes |
|----------------|------------------|----------|-------------- |-------|
| Container escape via nsenter | T1611 | Yes/No | | |
| Crypto-miner execution | T1496 | Yes/No | | |
| Sensitive file read (/etc/shadow) | T1552.001 | Yes/No | | |
| Shell in non-shell container | T1059.004 | Yes/No | | |
| Privilege escalation via sudo | T1548.003 | Yes/No | | |
| Network reconnaissance (nmap) | T1046 | Yes/No | | |

## Risk Findings

### Critical

| Finding | Namespace | Pod | Recommended Action |
|---------|-----------|-----|-------------------|
| | | | |

### High

| Finding | Namespace | Pod | Recommended Action |
|---------|-----------|-----|-------------------|
| | | | |

### Medium

| Finding | Namespace | Pod | Recommended Action |
|---------|-----------|-----|-------------------|
| | | | |

## Recommendations

1. **Immediate Actions**
   - [ ]

2. **Short-term (30 days)**
   - [ ]

3. **Long-term (90 days)**
   - [ ]

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Engineer | | | |
| Platform Engineer | | | |
| Security Manager | | | |
