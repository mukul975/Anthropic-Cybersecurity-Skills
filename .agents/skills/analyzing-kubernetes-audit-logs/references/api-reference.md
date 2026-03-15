# API Reference: Analyzing Kubernetes Audit Logs

## Audit Log Format (JSON Lines)

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "verb": "create",
  "user": {"username": "admin", "groups": ["system:masters"]},
  "sourceIPs": ["10.0.0.5"],
  "objectRef": {
    "resource": "pods",
    "subresource": "exec",
    "namespace": "default",
    "name": "web-pod"
  },
  "responseStatus": {"code": 200},
  "requestReceivedTimestamp": "2025-03-15T14:00:00Z"
}
```

## Security-Critical Audit Events

| Event | objectRef | Severity |
|-------|-----------|----------|
| Pod exec | `resource: pods, subresource: exec` | HIGH |
| Secret access | `resource: secrets, verb: get/list` | HIGH |
| RBAC change | `resource: clusterrolebindings` | CRITICAL |
| Privileged pod | `requestObject.spec.containers[].securityContext.privileged` | CRITICAL |
| Anonymous access | `user.username: system:anonymous` | CRITICAL |

## Audit Policy Levels

| Level | Captures |
|-------|----------|
| None | No logging |
| Metadata | Timestamp, user, verb, resource |
| Request | Metadata + request body |
| RequestResponse | Request + response body |

## Python Parsing

```python
import json
with open("audit.log") as f:
    for line in f:
        event = json.loads(line)
        print(event["verb"], event["objectRef"]["resource"])
```

### References

- K8s Auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- Audit policy: https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- Datadog k8s audit: https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/
