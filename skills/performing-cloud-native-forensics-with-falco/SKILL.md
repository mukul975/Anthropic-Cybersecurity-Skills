---
name: performing-cloud-native-forensics-with-falco
description: >
  Uses Falco YAML rules for runtime threat detection in containers and Kubernetes,
  monitoring syscalls for shell spawns, file tampering, network anomalies, and privilege
  escalation. Manages Falco rules via the Falco gRPC API and parses Falco alert output.
  Use when building container runtime security or investigating k8s cluster compromises.
domain: cybersecurity
subdomain: cloud-security
tags: [performing, cloud, native, forensics]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Cloud Native Forensics with Falco

## Instructions

Deploy and manage Falco rules for runtime security detection in containerized
environments. Parse Falco alerts for incident response.

```yaml
# Custom Falco rule for detecting shell in container
- rule: Shell Spawned in Container
  desc: Detect shell process started in a container
  condition: >
    spawned_process and container
    and proc.name in (bash, sh, zsh, dash, csh)
    and not proc.pname in (docker-entrypo, supervisord)
  output: >
    Shell spawned in container
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

Key detection rules:
1. Shell spawn in non-interactive containers
2. Sensitive file access (/etc/shadow, /etc/passwd)
3. Outbound connections from unexpected containers
4. Privilege escalation via setuid/setgid
5. Container escape via mount or ptrace

## Examples

```bash
# Run Falco with custom rules
falco -r /etc/falco/custom_rules.yaml -o json_output=true
# Parse JSON alerts
cat /var/log/falco/alerts.json | python3 -c "import json,sys; [print(json.loads(l)['output']) for l in sys.stdin]"
```
