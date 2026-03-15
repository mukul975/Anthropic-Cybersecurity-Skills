# API Reference: Detecting Container Drift at Runtime

## Docker SDK for Python

```python
import docker
client = docker.from_env()

# List running containers
containers = client.containers.list()

# Get container details
container = client.containers.get("container_id")
container.attrs         # full inspection dict
container.image.id      # image SHA256
container.image.tags    # ['app:v1.0']

# Filesystem diff (vs original image)
diff = container.diff()
# Returns: [{"Path": "/tmp/new_file", "Kind": 1}]
# Kind: 0=Modified, 1=Added, 2=Deleted

# Container inspection fields
container.attrs["HostConfig"]["Privileged"]       # bool
container.attrs["HostConfig"]["ReadonlyRootfs"]   # bool
container.attrs["Config"]["Image"]                # image reference
```

## Docker CLI Commands

```bash
# Filesystem changes since creation
docker diff <container>     # A=Added, C=Changed, D=Deleted

# Running processes
docker top <container> -eo pid,user,comm,args

# Image digest verification
docker inspect --format='{{.Image}}' <container>
```

## Falco Drift Detection Rules

```yaml
# Detect binary not in original image
condition: spawned_process and container and proc.is_exe_upper_layer = true

# Detect package manager usage
condition: spawned_process and container and proc.name in (apt, yum, pip, npm)

# Detect shell spawn
condition: spawned_process and container and proc.name in (bash, sh, dash)
```

## Kubernetes Security Context

```yaml
securityContext:
  readOnlyRootFilesystem: true     # prevent drift
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

## Drift Severity Classification

| Indicator | Severity |
|-----------|----------|
| Privileged container | CRITICAL |
| Sensitive file modified (/etc/shadow) | CRITICAL |
| Binary added to system path | HIGH |
| Package manager executed | HIGH |
| Root shell active | MEDIUM |
| Mutable root filesystem | MEDIUM |

## CLI Usage

```bash
python agent.py --container my-app-container
python agent.py --container abc123 --all
```
