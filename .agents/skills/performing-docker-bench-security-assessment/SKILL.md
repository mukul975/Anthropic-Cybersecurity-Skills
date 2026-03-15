---
name: performing-docker-bench-security-assessment
description: Docker Bench for Security is an open-source script that checks dozens of common best practices around deploying Docker containers in production. Based on the CIS Docker Benchmark, it audits host confi
domain: cybersecurity
subdomain: container-security
tags: [containers, docker, security, CIS-benchmark, assessment]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Docker Bench Security Assessment

## Overview

Docker Bench for Security is an open-source script that checks dozens of common best practices around deploying Docker containers in production. Based on the CIS Docker Benchmark, it audits host configuration, Docker daemon settings, container images, runtime configurations, and security operations to generate a compliance report with pass/fail/warn results.

## Prerequisites

- Docker Engine installed and running
- Root or sudo access on Docker host
- Docker Bench Security script or container image

## Implementation Steps

### Step 1: Run Docker Bench Security

```bash
# Run as a container (recommended)
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security

# Run with JSON output
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security -l /dev/stdout 2>/dev/null | tee docker-bench-results.json

# Run specific sections only
docker run --rm --net host --pid host --userns host \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security -c container_images,container_runtime
```

### Step 2: Interpret Results

```
[INFO] 1 - Host Configuration
[PASS] 1.1.1 - Ensure a separate partition for containers has been created
[WARN] 1.1.2 - Ensure only trusted users are allowed to control Docker daemon
[PASS] 1.1.3 - Ensure auditing is configured for the Docker daemon

[INFO] 2 - Docker daemon configuration
[FAIL] 2.1 - Run the Docker daemon as a non-root user
[PASS] 2.2 - Ensure network traffic is restricted between containers on the default bridge
```

### Step 3: Remediate Common Failures

```bash
# Fix 2.2: Restrict inter-container communication
echo '{"icc": false}' | sudo tee /etc/docker/daemon.json

# Fix 2.17: Restrict containers from acquiring new privileges
echo '{"no-new-privileges": true}' | sudo tee -a /etc/docker/daemon.json

# Fix 5.3: Restrict Linux kernel capabilities
# Use --cap-drop ALL in docker run commands

# Fix 5.12: Mount container's root filesystem as read only
# Use --read-only flag in docker run commands

# Restart Docker daemon after configuration changes
sudo systemctl restart docker
```

### Step 4: Automate Scheduled Assessments

```yaml
# docker-compose for scheduled assessment
version: '3.8'
services:
  bench-security:
    image: docker/docker-bench-security
    network_mode: host
    pid: host
    userns_mode: host
    cap_add:
      - audit_control
    volumes:
      - /etc:/etc:ro
      - /var/lib:/var/lib:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./results:/results
    command: -l /results/bench-$(date +%Y%m%d).log
    deploy:
      restart_policy:
        condition: none
```

## Validation Commands

```bash
# Verify remediation
docker run --rm docker/docker-bench-security 2>&1 | grep -E "(PASS|FAIL|WARN)" | sort | uniq -c

# Count results by type
docker run --rm docker/docker-bench-security 2>&1 | grep -c "PASS"
docker run --rm docker/docker-bench-security 2>&1 | grep -c "FAIL"
docker run --rm docker/docker-bench-security 2>&1 | grep -c "WARN"
```

## References

- [Docker Bench Security](https://github.com/docker/docker-bench-security)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
