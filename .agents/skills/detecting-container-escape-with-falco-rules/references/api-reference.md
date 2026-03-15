# API Reference: Detecting Container Escape with Falco Rules

## Falco CLI

```bash
falco --version                           # check version
falco --validate /path/to/rules.yaml      # validate rules syntax
falco -r /etc/falco/rules.d/escape.yaml   # load specific rules
falco --list                              # list all available fields
falco --list-events                       # list supported syscalls
```

## Falco Rule Syntax

```yaml
- rule: <name>
  desc: <description>
  condition: <filter expression>
  output: <alert message with fields>
  priority: <Emergency|Alert|Critical|Error|Warning|Notice|Informational|Debug>
  tags: [tag1, tag2]
  enabled: true
```

## Key Falco Filter Fields

| Field | Description |
|-------|-------------|
| `container` | True if event is from a container |
| `spawned_process` | True if new process spawned |
| `proc.name` | Process name |
| `proc.cmdline` | Full command line |
| `proc.pname` | Parent process name |
| `fd.name` | File descriptor name/path |
| `container.name` | Container name |
| `container.image.repository` | Image repository |
| `container.privileged` | True if privileged |
| `proc.is_exe_upper_layer` | Binary not in original image |
| `evt.type` | Syscall type (setns, unshare, mount) |

## Falco JSON Output Format

```json
{
  "time": "2024-01-15T10:30:00.000Z",
  "rule": "Container Escape Binary Execution",
  "priority": "Critical",
  "source": "syscall",
  "output": "Escape binary in container...",
  "output_fields": {
    "user.name": "root",
    "proc.cmdline": "nsenter -t 1 -m -u -i -n",
    "container.name": "attacker-pod"
  },
  "tags": ["container", "escape", "T1611"]
}
```

## Falcosidekick Alert Routing

```yaml
config:
  slack:
    webhookurl: "https://hooks.slack.com/services/XXX"
    minimumpriority: "critical"
  elasticsearch:
    hostport: "https://es:9200"
    index: "falco-alerts"
```

## Helm Deployment

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true
```

## CLI Usage

```bash
python agent.py --check-status
python agent.py --validate-rules /etc/falco/rules.d/escape.yaml
python agent.py --parse-alerts /var/log/falco/events.json --min-priority Warning
python agent.py --generate-rules > escape-rules.yaml
```
