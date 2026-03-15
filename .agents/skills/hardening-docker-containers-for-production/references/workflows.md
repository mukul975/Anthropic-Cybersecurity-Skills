# Workflows - Docker Container Hardening

## Workflow 1: New Container Hardening Pipeline

```
[Dockerfile Created] --> [Hadolint Lint] --> [Build Image] --> [Dockle Scan]
        |                      |                    |               |
        v                      v                    v               v
  Use multi-stage        Fix warnings         Tag with digest   Fix findings
  Non-root USER          No ADD, use COPY     Sign image        Remove setuid
  Minimal base           Pin versions         Push to registry  Drop caps
        |                      |                    |               |
        +----------+-----------+--------------------+               |
                   |                                                |
                   v                                                v
          [Trivy Vulnerability Scan] -----> [Docker Bench Assessment]
                   |                                    |
                   v                                    v
          Fix HIGH/CRITICAL CVEs              Remediate CIS failures
                   |                                    |
                   +------------------------------------+
                   |
                   v
          [Deploy to Production with Hardened Runtime Flags]
                   |
                   v
          [Continuous Monitoring with Falco]
```

## Workflow 2: Existing Container Remediation

```
Step 1: Assess Current State
  - Run docker-bench-security against host
  - Run Trivy scan against all running images
  - Audit all running containers for root users
  - Check daemon.json configuration

Step 2: Prioritize Remediation
  - Critical: Privileged containers, root users, exposed daemon socket
  - High: Missing seccomp profiles, no resource limits, capability escalation
  - Medium: Missing health checks, no content trust, excessive open ports
  - Low: Missing labels, audit rules, log rotation

Step 3: Apply Fixes
  - Update Dockerfiles with non-root users
  - Rebuild images with multi-stage builds
  - Update docker-compose or orchestrator configs
  - Configure daemon.json with TLS and security options

Step 4: Validate
  - Re-run docker-bench-security
  - Confirm score improvement
  - Document remaining accepted risks
```

## Workflow 3: CI/CD Integration

```yaml
# GitHub Actions hardening pipeline
name: Container Hardening Pipeline
on: [push]

jobs:
  lint-dockerfile:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile

  build-and-scan:
    needs: lint-dockerfile
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Dockle lint
        uses: erzz/dockle-action@v1
        with:
          image: myapp:${{ github.sha }}
          failure-threshold: WARN

      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: table
          exit-code: 1
          severity: CRITICAL,HIGH

      - name: Sign image with Cosign
        if: github.ref == 'refs/heads/main'
        uses: sigstore/cosign-installer@v3
        run: cosign sign --yes myapp:${{ github.sha }}
```

## Workflow 4: Runtime Hardening Checklist

```
Pre-deployment:
  [ ] Image built from minimal base (distroless/Alpine)
  [ ] Non-root USER specified in Dockerfile
  [ ] No secrets in image layers
  [ ] Image signed and verified
  [ ] Vulnerability scan shows no CRITICAL/HIGH CVEs
  [ ] Hadolint and Dockle pass with zero errors

Runtime configuration:
  [ ] --read-only flag enabled
  [ ] --cap-drop ALL with minimum cap-add
  [ ] --security-opt no-new-privileges:true
  [ ] --security-opt seccomp=<profile>
  [ ] --memory and --cpus limits set
  [ ] --pids-limit configured
  [ ] --user flag set to non-root UID
  [ ] --tmpfs for writable directories only
  [ ] Health check configured
  [ ] Restart policy set (on-failure with max retries)

Host configuration:
  [ ] Docker daemon TLS enabled
  [ ] Inter-container communication disabled (icc=false)
  [ ] User namespace remapping enabled
  [ ] Audit rules for Docker binaries and directories
  [ ] Docker socket not exposed to containers
```
