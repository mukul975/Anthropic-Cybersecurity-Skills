# Docker Container Hardening Assessment Template

## Project Information

| Field | Value |
|-------|-------|
| Application Name | |
| Docker Image | |
| Base Image | |
| Environment | Development / Staging / Production |
| Assessment Date | |
| Assessor | |

## Pre-Hardening Checklist

### Dockerfile Security
- [ ] Using minimal base image (distroless, Alpine, scratch)
- [ ] Specific image tag with digest pinning (not :latest)
- [ ] Multi-stage build implemented
- [ ] Non-root USER instruction present
- [ ] COPY used instead of ADD
- [ ] No secrets in Dockerfile or image layers
- [ ] HEALTHCHECK instruction present
- [ ] Unnecessary packages removed
- [ ] setuid/setgid binaries removed

### Daemon Configuration (/etc/docker/daemon.json)
- [ ] icc set to false
- [ ] TLS authentication enabled (tlsverify: true)
- [ ] Live restore enabled
- [ ] Userland proxy disabled
- [ ] no-new-privileges enabled
- [ ] Log rotation configured (max-size, max-file)
- [ ] Default ulimits configured
- [ ] Seccomp profile specified

### Runtime Security Flags
- [ ] --read-only enabled
- [ ] --cap-drop ALL applied
- [ ] Minimum --cap-add for required capabilities only
- [ ] --security-opt no-new-privileges:true
- [ ] --security-opt seccomp=<profile>
- [ ] --memory limit set
- [ ] --cpus limit set
- [ ] --pids-limit set
- [ ] --user set to non-root UID:GID
- [ ] --tmpfs for writable directories
- [ ] --network set to custom bridge (not host)
- [ ] --restart on-failure with max retries

### Host Security
- [ ] Separate partition for /var/lib/docker
- [ ] Docker group membership restricted
- [ ] Audit rules configured for Docker files
- [ ] Docker socket not exposed to containers
- [ ] Content Trust enabled (DOCKER_CONTENT_TRUST=1)

## Vulnerability Scan Results

### Trivy Scan
```
trivy image <image-name>
```

| Severity | Count | Action Required |
|----------|-------|----------------|
| CRITICAL | | Immediate fix |
| HIGH | | Fix before production |
| MEDIUM | | Plan remediation |
| LOW | | Accept or fix |

### Docker Bench Score
```
docker run --rm docker/docker-bench-security
```

| Section | Score | Notes |
|---------|-------|-------|
| Host Configuration | /10 | |
| Daemon Configuration | /10 | |
| Container Images | /10 | |
| Container Runtime | /10 | |
| Docker Security Ops | /10 | |

## Risk Acceptance

| Finding | Severity | Justification | Approved By | Date |
|---------|----------|---------------|-------------|------|
| | | | | |

## Remediation Plan

| Priority | Finding | Action | Owner | Target Date | Status |
|----------|---------|--------|-------|-------------|--------|
| P1 | | | | | |
| P2 | | | | | |
| P3 | | | | | |

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Security Engineer | | | |
| DevOps Lead | | | |
| Application Owner | | | |
