---
name: performing-container-image-hardening
description: >
  This skill covers hardening container images by minimizing attack surface, removing
  unnecessary packages, implementing multi-stage builds, configuring non-root users,
  and applying CIS Docker Benchmark recommendations to produce secure production-ready images.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, container-hardening, docker, cis-benchmark, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing Container Image Hardening

## When to Use

- When building production container images that need minimal attack surface
- When compliance requires CIS Docker Benchmark adherence for container configurations
- When reducing image size to minimize vulnerability exposure from unused packages
- When implementing defense-in-depth for containerized workloads
- When migrating from fat base images to distroless or minimal images

**Do not use** for runtime container security monitoring (use Falco), for host-level Docker daemon hardening (use CIS Docker Benchmark host checks), or for container orchestration security (use Kubernetes security scanning).

## Prerequisites

- Docker or BuildKit for multi-stage builds
- Base image options: distroless, Alpine, slim, or scratch
- Container scanning tool (Trivy) for validation
- CIS Docker Benchmark reference

## Workflow

### Step 1: Use Multi-Stage Builds to Minimize Image Size

```dockerfile
# Build stage with all dependencies
FROM python:3.12-bookworm AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
COPY src/ ./src/
RUN python -m compileall src/

# Production stage with minimal base
FROM python:3.12-slim-bookworm AS production
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false

COPY --from=builder /install /usr/local
COPY --from=builder /build/src /app/src

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser
RUN chown -R appuser:appuser /app

USER appuser
WORKDIR /app

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080
ENTRYPOINT ["python", "-m", "src.main"]
```

### Step 2: Use Distroless Base Images

```dockerfile
# Go application with distroless
FROM golang:1.22 AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

### Step 3: Remove Unnecessary Components

```dockerfile
# Hardened image checklist
FROM ubuntu:24.04 AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libssl3 && \
    # Remove package manager to prevent runtime package installation
    apt-get purge -y --auto-remove apt dpkg && \
    rm -rf /var/lib/apt/lists/* \
           /var/cache/apt/* \
           /tmp/* \
           /var/tmp/* \
           /usr/share/doc/* \
           /usr/share/man/* \
           /usr/share/info/* \
           /root/.cache

# Remove shells if not needed
RUN rm -f /bin/sh /bin/bash /usr/bin/sh 2>/dev/null || true

# Remove setuid/setgid binaries
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
```

### Step 4: Configure Read-Only Filesystem

```yaml
# Kubernetes deployment with read-only root filesystem
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: app:hardened
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /app/cache
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
        - name: cache
          emptyDir:
            sizeLimit: 50Mi
```

### Step 5: Pin Base Image by Digest

```dockerfile
# Pin to exact image digest for reproducibility
FROM python:3.12-slim-bookworm@sha256:abcdef1234567890 AS production
# This ensures the exact same base image is used every time
```

### Step 6: Validate Hardening with Automated Scanning

```bash
# Scan hardened image with Trivy
trivy image --severity HIGH,CRITICAL hardened-app:latest

# Check CIS Docker Benchmark compliance
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/docker-bench-security

# Verify no root processes
docker run --rm hardened-app:latest whoami
# Expected: appuser (NOT root)

# Verify read-only filesystem
docker run --rm hardened-app:latest touch /test 2>&1
# Expected: Read-only file system error
```

## Key Concepts

| Term | Definition |
|------|------------|
| Multi-Stage Build | Docker build technique using multiple FROM stages to separate build and runtime, reducing final image size |
| Distroless | Google-maintained minimal container images containing only the application and runtime dependencies |
| Non-Root User | Running container processes as unprivileged user to limit impact of container escape exploits |
| Read-Only Root | Mounting the container root filesystem as read-only to prevent runtime modification |
| Image Digest | SHA256 hash uniquely identifying an exact image version, more precise than mutable tags |
| Scratch Image | Empty Docker base image used for statically compiled binaries requiring no OS |
| Security Context | Kubernetes pod/container-level security settings controlling privileges, filesystem, and capabilities |

## Tools & Systems

- **Docker BuildKit**: Advanced Docker build engine supporting multi-stage builds and build secrets
- **Distroless Images**: Google's minimal container base images (static, base, java, python, nodejs)
- **docker-bench-security**: Script checking CIS Docker Benchmark compliance
- **Trivy**: Container image vulnerability and misconfiguration scanner
- **Hadolint**: Dockerfile linter enforcing best practices

## Common Scenarios

### Scenario: Reducing a 1.2GB Python Image to Under 150MB

**Context**: A data science team uses `python:3.12` as base image (1.2GB) with scientific computing packages. The image has 200+ known CVEs from unnecessary system packages.

**Approach**:
1. Switch to `python:3.12-slim-bookworm` as base (150MB) and install only required system libraries
2. Use multi-stage build: compile C extensions in builder stage, copy wheels to production
3. Pin numpy, pandas, and scipy to pre-built wheels to avoid build dependencies in production
4. Remove pip, setuptools, and wheel from the final image
5. Create non-root user and set filesystem permissions
6. Validate with Trivy: expect CVE count to drop from 200+ to under 20

**Pitfalls**: Some Python packages require shared libraries at runtime (libgomp, libstdc++). Test the application thoroughly after removing system packages. Alpine-based images use musl libc which can cause compatibility issues with numpy and pandas.

## Output Format

```
Container Image Hardening Report
==================================
Image: app:hardened
Base: python:3.12-slim-bookworm
Date: 2026-02-23

SIZE COMPARISON:
  Before hardening: 1,247 MB (python:3.12)
  After hardening:  143 MB  (python:3.12-slim + multi-stage)
  Reduction: 88.5%

SECURITY CHECKS:
  [PASS] Non-root user configured (appuser:1000)
  [PASS] HEALTHCHECK instruction present
  [PASS] No setuid/setgid binaries found
  [PASS] Package manager removed
  [PASS] Base image pinned by digest
  [PASS] No shell access (/bin/sh removed)
  [WARN] /tmp writable (emptyDir mounted)

VULNERABILITY COMPARISON:
  Before: 234 CVEs (12 Critical, 45 High)
  After:  18 CVEs (0 Critical, 3 High)
  Reduction: 92.3%
```
