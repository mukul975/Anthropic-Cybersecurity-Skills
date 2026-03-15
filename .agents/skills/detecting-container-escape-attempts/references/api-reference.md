# API Reference: Detecting Container Escape Attempts

## Common Escape Vectors (MITRE ATT&CK)

| Vector | Technique | MITRE ID |
|--------|-----------|----------|
| Privileged container | Mount host FS, load modules | T1611 |
| Docker socket mount | Create privileged container | T1610 |
| Kernel exploits | CVE-2022-0185, Dirty Pipe | T1068 |
| Capability abuse | SYS_ADMIN, SYS_PTRACE | T1548 |
| Sensitive mounts | /proc/sysrq-trigger, cgroup release_agent | T1611 |
| Namespace escape | nsenter, unshare | T1611 |

## Docker CLI Inspection

```bash
# Check if container is privileged
docker inspect --format='{{.HostConfig.Privileged}}' <container>

# Check added capabilities
docker inspect --format='{{.HostConfig.CapAdd}}' <container>

# Check PID namespace mode
docker inspect --format='{{.HostConfig.PidMode}}' <container>

# Check volume mounts
docker inspect --format='{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' <container>
```

## Falco JSON Alert Format

```json
{
  "time": "2024-01-15T10:30:00.000Z",
  "rule": "Container Escape via Privileged Mode",
  "priority": "Critical",
  "output": "Container escape attempt...",
  "output_fields": {
    "container.name": "attacker-pod",
    "container.image.repository": "alpine",
    "proc.cmdline": "nsenter -t 1 -m -u -i -n"
  },
  "tags": ["container", "escape", "T1611"]
}
```

## Linux Audit Rules for Escape Detection

```bash
# /etc/audit/rules.d/container-escape.rules
-a always,exit -F arch=b64 -S setns -S unshare -k container_escape
-a always,exit -F arch=b64 -S mount -S umount2 -k container_mount
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module
-w /var/run/docker.sock -p rwxa -k docker_socket
```

## Dangerous Linux Capabilities

| Capability | Escape Risk |
|------------|-------------|
| CAP_SYS_ADMIN | Mount filesystems, manage cgroups |
| CAP_SYS_PTRACE | Trace/debug any process |
| CAP_NET_ADMIN | Network namespace manipulation |
| CAP_SYS_MODULE | Load/unload kernel modules |
| CAP_DAC_READ_SEARCH | Bypass file read permissions |

## CLI Usage

```bash
python agent.py --falco-log /var/log/falco/events.json
python agent.py --audit-log /var/log/audit/audit.log
python agent.py --check-containers
python agent.py --container-id abc123
```
