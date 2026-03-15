---
name: implementing-container-image-minimal-base-with-distroless
description: Reduce container attack surface by building application images on Google distroless base images that contain only the application runtime with no shell, package manager, or unnecessary OS utilities.
domain: cybersecurity
subdomain: container-security
tags: [distroless, container-images, minimal-base, attack-surface, docker, security-hardening, supply-chain, kubernetes]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Container Image Minimal Base with Distroless

## Overview

Google distroless images contain only your application and its runtime dependencies, without package managers, shells, or other programs found in standard Linux distributions. By eliminating unnecessary OS components, distroless images achieve up to 95% reduction in attack surface compared to traditional base images like ubuntu or debian. Major projects including Kubernetes itself, Knative, and Tekton use distroless images in production. As of 2025, Docker also offers Hardened Images (DHI) as an open-source alternative for minimal container bases.

## Prerequisites

- Docker 20.10+ or compatible container build tool (Buildah, Kaniko)
- Multi-stage Dockerfile knowledge
- Application compiled as a static binary or with runtime bundled
- Container registry for image storage

## Available Distroless Images

| Image | Use Case | Size |
|-------|----------|------|
| `gcr.io/distroless/static-debian12` | Statically compiled binaries (Go, Rust) | ~2MB |
| `gcr.io/distroless/base-debian12` | Dynamically linked binaries needing glibc | ~20MB |
| `gcr.io/distroless/cc-debian12` | C/C++ applications needing libstdc++ | ~25MB |
| `gcr.io/distroless/java21-debian12` | Java 21 applications | ~220MB |
| `gcr.io/distroless/python3-debian12` | Python 3 applications | ~50MB |
| `gcr.io/distroless/nodejs22-debian12` | Node.js 22 applications | ~130MB |

## Multi-Stage Build Patterns

### Go Application

```dockerfile
# Build stage
FROM golang:1.22-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server

# Runtime stage - static distroless
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

### Java Application

```dockerfile
# Build stage
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage - Java distroless
FROM gcr.io/distroless/java21-debian12:nonroot
COPY --from=builder /app/target/app.jar /app.jar
USER nonroot:nonroot
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

### Python Application

```dockerfile
# Build stage
FROM python:3.12-bookworm AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt
COPY . .

# Runtime stage - Python distroless
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=builder /deps /deps
COPY --from=builder /app /app
ENV PYTHONPATH=/deps
USER nonroot:nonroot
ENTRYPOINT ["python3", "/app/main.py"]
```

### Node.js Application

```dockerfile
# Build stage
FROM node:22-bookworm AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .

# Runtime stage - Node distroless
FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=builder /app .
USER nonroot:nonroot
CMD ["server.js"]
```

## Security Benefits

### Attack Surface Comparison

| Component | Ubuntu | Alpine | Distroless |
|-----------|--------|--------|-----------|
| Shell (bash/sh) | Yes | Yes | No |
| Package manager | apt | apk | No |
| coreutils | Full | BusyBox | No |
| curl/wget | Yes | Yes | No |
| User management | Yes | Yes | No |
| Known CVEs (typical) | 50-200+ | 5-20 | 0-5 |
| Image size (base) | ~77MB | ~7MB | ~2-20MB |

### Security Implications

- **No shell**: Attackers cannot exec into containers to run commands
- **No package manager**: Cannot install additional tools or malware
- **No coreutils**: No `cat`, `ls`, `find`, `curl` for reconnaissance
- **Minimal CVEs**: Fewer packages means fewer vulnerabilities to patch
- **Non-root by default**: `:nonroot` tag runs as UID 65534

## Debugging Distroless Containers

Since distroless has no shell, use these techniques for debugging:

### Debug Image Variant

```dockerfile
# Use debug variant in non-production environments only
FROM gcr.io/distroless/base-debian12:debug
# Includes busybox shell at /busybox/sh
```

```bash
# Exec into debug variant
kubectl exec -it pod-name -- /busybox/sh
```

### Ephemeral Debug Containers (Kubernetes 1.25+)

```bash
# Attach a debug container with full tooling
kubectl debug -it pod-name --image=busybox:1.36 --target=app-container
```

### Crane/Dive for Image Inspection

```bash
# Inspect image layers without running
crane export gcr.io/distroless/static-debian12 - | tar -tf - | head -50

# Analyze image layers
dive gcr.io/distroless/static-debian12
```

## Image Scanning Results

Typical vulnerability comparison using Trivy:

```bash
# Scan Ubuntu-based image
trivy image myapp:ubuntu
# Result: 47 vulnerabilities (3 CRITICAL, 12 HIGH)

# Scan Distroless-based image
trivy image myapp:distroless
# Result: 2 vulnerabilities (0 CRITICAL, 0 HIGH)
```

## References

- [GoogleContainerTools/distroless GitHub](https://github.com/GoogleContainerTools/distroless)
- [Distroless Images - Docker Documentation](https://docs.docker.com/dhi/core-concepts/distroless/)
- [Alpine, Distroless, or Scratch? - Google Cloud](https://medium.com/google-cloud/alpine-distroless-or-scratch-caac35250e0b)
- [Docker Hardened Images](https://www.infoq.com/news/2025/12/docker-hardened-images/)
