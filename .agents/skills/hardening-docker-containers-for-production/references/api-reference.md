# API Reference: Docker Container Hardening

## Docker CLI

### List Containers
```bash
docker ps --format '{{json .}}'
```

### Inspect Container
```bash
docker inspect <container_id>
```

### Key Inspect Fields
| Path | Description |
|------|-------------|
| `.HostConfig.Privileged` | Privileged mode |
| `.HostConfig.NetworkMode` | Network namespace |
| `.HostConfig.CapAdd` | Added capabilities |
| `.HostConfig.ReadonlyRootfs` | Read-only filesystem |
| `.HostConfig.Memory` | Memory limit (bytes) |
| `.Config.User` | Container user |

## CIS Docker Benchmark Checks

| Check | Description | Severity |
|-------|-------------|----------|
| 4.1 | Non-root user | HIGH |
| 5.3 | Restrict capabilities | HIGH |
| 5.4 | No privileged containers | CRITICAL |
| 5.5 | No sensitive host mounts | HIGH |
| 5.10 | No host network | HIGH |
| 5.12 | Read-only root FS | MEDIUM |
| 5.13 | CPU limits set | LOW |
| 5.14 | Memory limits set | MEDIUM |

## Secure Dockerfile Practices

### Non-Root User
```dockerfile
FROM alpine:3.18
RUN adduser -D appuser
USER appuser
```

### Read-Only Filesystem
```bash
docker run --read-only --tmpfs /tmp:rw,noexec,nosuid myimage
```

### Drop Capabilities
```bash
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE myimage
```

### Resource Limits
```bash
docker run --memory=512m --cpus=1.0 myimage
```

## Docker Bench Security

### Run Audit
```bash
docker run --rm --net host --pid host --userns host \
    --cap-add audit_control \
    -v /var/lib:/var/lib \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /etc:/etc \
    docker/docker-bench-security
```

## Seccomp and AppArmor

### Custom Seccomp Profile
```bash
docker run --security-opt seccomp=profile.json myimage
```

### AppArmor Profile
```bash
docker run --security-opt apparmor=docker-default myimage
```
