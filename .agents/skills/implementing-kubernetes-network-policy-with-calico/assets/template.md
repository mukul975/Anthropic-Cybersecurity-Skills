# Network Policy Design Template

## Application Traffic Flow Matrix

| Source | Destination | Port | Protocol | Justification |
|--------|-------------|------|----------|---------------|
| frontend | backend-api | 8080 | TCP | REST API calls |
| backend-api | postgres-db | 5432 | TCP | Database queries |
| backend-api | redis-cache | 6379 | TCP | Session caching |
| all pods | kube-dns | 53 | UDP/TCP | DNS resolution |
| ingress-nginx | frontend | 80 | TCP | External traffic |
| prometheus | all pods | 9090 | TCP | Metrics scraping |

## Namespace Policy Checklist

### Per Namespace
- [ ] Default deny ingress applied
- [ ] Default deny egress applied
- [ ] DNS egress allowed
- [ ] Required ingress rules created per traffic flow
- [ ] Required egress rules created per traffic flow
- [ ] Cross-namespace policies documented
- [ ] Policies tested with connectivity checks

### Cluster-Wide (GlobalNetworkPolicy)
- [ ] Block external access to non-ingress namespaces
- [ ] Allow monitoring namespace to scrape metrics
- [ ] Allow kube-system health checks
- [ ] Emergency isolation policy prepared

## Policy Naming Convention

```
{action}-{source}-to-{destination}-{port}
```

Examples:
- `allow-frontend-to-backend-8080`
- `deny-external-to-database-5432`
- `allow-monitoring-to-all-9090`

## Emergency Isolation Policy

```yaml
# Apply this to immediately isolate a compromised namespace
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: emergency-isolate-NAMESPACE
spec:
  order: 1
  selector: "projectcalico.org/namespace == 'NAMESPACE'"
  types:
    - Ingress
    - Egress
  ingress:
    - action: Deny
  egress:
    - action: Deny
```

## Review Schedule

| Review Type | Frequency | Owner |
|-------------|-----------|-------|
| Policy audit | Monthly | Security Team |
| Traffic flow validation | After each deployment | DevOps |
| Compliance check | Quarterly | GRC Team |
| Emergency drill | Semi-annually | Security + SRE |
