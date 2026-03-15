---
name: hardening-docker-containers-for-production
description: Hardening Docker containers for production involves applying security best practices aligned with CIS Docker Benchmark v1.8.0 to minimize attack surface, prevent privilege escalation, and enforce leas
domain: cybersecurity
subdomain: container-security
tags: [containers, docker, security, hardening, CIS-benchmark]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Hardening Docker Containers for Production

## Overview

Hardening Docker containers for production involves applying security best practices aligned with CIS Docker Benchmark v1.8.0 to minimize attack surface, prevent privilege escalation, and enforce least-privilege principles across Docker daemon, images, containers, and runtime configurations.

## Prerequisites

- Docker Engine 24.0+ installed
- Docker Compose v2
- Linux host with kernel 5.10+
- Root or sudo access on Docker host
- docker-bench-security tool
- Hadolint for Dockerfile linting
- Dockle for image linting

## Core Concepts

### CIS Docker Benchmark Sections

1. **Host Configuration** - Audit Docker daemon files, restrict access to /var/run/docker.sock
2. **Docker Daemon Configuration** - Enable TLS, restrict inter-container communication, configure logging
3. **Docker Daemon Configuration Files** - Set ownership and permissions on daemon.json
4. **Container Images and Build File** - Use trusted base images, scan for vulnerabilities, multi-stage builds
5. **Container Runtime** - Drop capabilities, read-only rootfs, restrict syscalls
6. **Docker Security Operations** - Monitor, audit, and rotate credentials

### Key Hardening Principles

- **Least Privilege**: Run containers as non-root, drop all capabilities except required
- **Immutability**: Use read-only root filesystem, tmpfs for writable directories
- **Minimalism**: Use distroless or Alpine base images, multi-stage builds
- **Isolation**: Apply seccomp profiles, AppArmor/SELinux, namespace restrictions
- **Auditability**: Enable content trust, log all container activity

## Implementation Steps

### Step 1: Harden the Dockerfile

```dockerfile
# Use specific digest for reproducibility
FROM python:3.12-slim@sha256:abc123... AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage - minimal image
FROM gcr.io/distroless/python3-debian12

# Copy only necessary artifacts
COPY --from=builder /root/.local /root/.local
COPY --from=builder /app /app

WORKDIR /app

# Create non-root user
USER 65534:65534

# Set read-only filesystem expectation
LABEL org.opencontainers.image.source="https://github.com/org/app"

ENTRYPOINT ["python", "app.py"]
```

### Step 2: Harden Docker Daemon Configuration

```json
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 1024,
      "Soft": 1024
    }
  },
  "seccomp-profile": "/etc/docker/seccomp-default.json",
  "tls": true,
  "tlscacert": "/etc/docker/tls/ca.pem",
  "tlscert": "/etc/docker/tls/server-cert.pem",
  "tlskey": "/etc/docker/tls/server-key.pem",
  "tlsverify": true
}
```

### Step 3: Harden Container Runtime

```bash
docker run -d \
  --name production-app \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /var/run:rw,noexec,nosuid,size=10m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/etc/docker/seccomp-default.json \
  --security-opt apparmor=docker-default \
  --pids-limit 100 \
  --memory 512m \
  --memory-swap 512m \
  --cpus 1.0 \
  --user 65534:65534 \
  --network custom-bridge \
  --restart on-failure:3 \
  --health-cmd "curl -f http://localhost:8080/health || exit 1" \
  --health-interval 30s \
  --health-timeout 10s \
  --health-retries 3 \
  myapp:latest
```

### Step 4: Enable Docker Content Trust

```bash
export DOCKER_CONTENT_TRUST=1
export DOCKER_CONTENT_TRUST_SERVER=https://notary.example.com

# Sign and push image
docker trust sign myregistry.com/myapp:v1.0.0

# Verify image signature before pull
docker trust inspect --pretty myregistry.com/myapp:v1.0.0
```

### Step 5: Configure Host-Level Auditing

```bash
# Add audit rules for Docker files and directories
cat >> /etc/audit/rules.d/docker.rules << 'EOF'
-w /usr/bin/docker -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /lib/systemd/system/docker.service -k docker
-w /lib/systemd/system/docker.socket -k docker
-w /etc/default/docker -k docker
-w /etc/docker/daemon.json -k docker
-w /usr/bin/containerd -k docker
-w /usr/bin/runc -k docker
EOF

systemctl restart auditd
```

## Validation Commands

```bash
# Run Docker Bench Security
docker run --rm --net host --pid host \
  --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security

# Lint Dockerfile
hadolint Dockerfile

# Lint built image
dockle myapp:latest

# Verify no containers running as root
docker ps -q | xargs docker inspect --format '{{.Id}}: User={{.Config.User}}'
```

## Key Security Controls

| Control | Implementation | CIS Section |
|---------|---------------|-------------|
| Non-root user | USER instruction in Dockerfile | 4.1 |
| Read-only rootfs | --read-only flag | 5.12 |
| Drop capabilities | --cap-drop ALL | 5.3 |
| Resource limits | --memory, --cpus, --pids-limit | 5.10 |
| No new privileges | --security-opt no-new-privileges | 5.25 |
| Content trust | DOCKER_CONTENT_TRUST=1 | 4.5 |
| TLS for daemon | daemon.json TLS config | 2.6 |
| Audit logging | auditd rules | 1.1 |

## References

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Docker Bench Security Tool](https://github.com/docker/docker-bench-security)
- [Hadolint - Dockerfile Linter](https://github.com/hadolint/hadolint)
