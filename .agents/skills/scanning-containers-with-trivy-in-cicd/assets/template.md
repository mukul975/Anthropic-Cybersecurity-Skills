# Trivy Container Scanning Templates

## GitHub Actions: Full Container Security Pipeline

```yaml
# .github/workflows/container-security.yml
name: Container Security

on:
  push:
    branches: [main]
  pull_request:
    paths: ['Dockerfile', 'docker-compose*.yml', 'src/**']

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-scan-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build image
        uses: docker/build-push-action@v6
        with:
          context: .
          load: true
          tags: ${{ env.IMAGE_NAME }}:scan
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Cache Trivy DB
        uses: actions/cache@v4
        with:
          path: /tmp/trivy
          key: trivy-db-${{ github.run_id }}
          restore-keys: trivy-db-

      - name: Trivy vulnerability scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ${{ env.IMAGE_NAME }}:scan
          format: sarif
          output: trivy-vuln.sarif
          severity: CRITICAL,HIGH
          exit-code: '1'
          ignore-unfixed: true
          cache-dir: /tmp/trivy

      - name: Upload vulnerability SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-vuln.sarif
          category: trivy-vulnerabilities

      - name: Trivy misconfiguration scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: .
          format: sarif
          output: trivy-config.sarif
          severity: CRITICAL,HIGH
          exit-code: '1'

      - name: Upload config SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-config.sarif
          category: trivy-misconfigurations

      - name: Generate SBOM
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ${{ env.IMAGE_NAME }}:scan
          format: cyclonedx
          output: sbom.cdx.json

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cdx.json

      - name: Login to GHCR
        if: github.event_name == 'push'
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Push image
        if: github.event_name == 'push'
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: |
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
```

## Trivy Ignore File Template

```yaml
# .trivyignore.yaml
vulnerabilities:
  # Accepted risk: mitigated at infrastructure level
  - id: CVE-YYYY-NNNNN
    statement: "Mitigated by WAF rules. Risk accepted by security team."
    expires: 2026-12-31

misconfigurations:
  # Init containers require root
  - id: DS002
    paths:
      - "docker/init/*.Dockerfile"
    statement: "Init containers need root for volume permissions"
```

## Secure Dockerfile Template

```dockerfile
# syntax=docker/dockerfile:1

# Build stage
FROM python:3.12-slim-bookworm AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Production stage
FROM python:3.12-slim-bookworm AS production

# Security: Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -s /bin/false appuser

# Security: Install only runtime dependencies, remove cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
WORKDIR /app
COPY --chown=appuser:appuser src/ ./src/

# Security: Run as non-root
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080
ENTRYPOINT ["python", "-m", "src.main"]
```

## Trivy Operator for Kubernetes

```yaml
# Install Trivy Operator via Helm
# helm repo add aqua https://aquasecurity.github.io/helm-charts/
# helm install trivy-operator aqua/trivy-operator \
#   --namespace trivy-system --create-namespace \
#   --set trivy.severity=CRITICAL,HIGH

# Sample VulnerabilityReport CRD
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  name: cis-benchmark
spec:
  cron: "0 */6 * * *"
  compliance:
    id: cis
    title: CIS Kubernetes Benchmark
    platform: k8s
```
