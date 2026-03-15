---
name: analyzing-kubernetes-audit-logs
description: >
  Parses Kubernetes API server audit logs (JSON lines) to detect exec-into-pod, secret
  access, RBAC modifications, privileged pod creation, and anonymous API access. Builds
  threat detection rules from audit event patterns. Use when investigating Kubernetes
  cluster compromise or building k8s-specific SIEM detection rules.
domain: cybersecurity
subdomain: container-security
tags: [analyzing, kubernetes, audit, logs]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Kubernetes Audit Logs

## Instructions

Parse Kubernetes audit log files (JSON lines format) to detect security-relevant
events including unauthorized access, privilege escalation, and data exfiltration.

```python
import json

with open("/var/log/kubernetes/audit.log") as f:
    for line in f:
        event = json.loads(line)
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        user = event.get("user", {}).get("username")
        if verb == "create" and resource == "pods/exec":
            print(f"Pod exec by {user}")
```

Key events to detect:
1. pods/exec and pods/attach (shell into containers)
2. secrets access (get/list/watch)
3. clusterrolebindings creation (RBAC escalation)
4. Privileged pod creation
5. Anonymous or system:unauthenticated access

## Examples

```python
# Detect secret enumeration
if verb in ("get", "list") and resource == "secrets":
    print(f"Secret access: {user} -> {event['objectRef'].get('name')}")
```
