# Workflow - Container Image Scanning with Grype

## Phase 1: Environment Setup

### Install Grype and Syft
```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft for SBOM generation
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify
grype version
syft version
```

### Configure Grype
```bash
# Create config directory
mkdir -p ~/.grype

# Create configuration file
cat > ~/.grype/.grype.yaml <<EOF
check-for-app-update: false
fail-on-severity: "high"
db:
  auto-update: true
  cache-dir: "/tmp/grype-db"
  max-allowed-built-age: 120h
ignore:
  # Add known false positives here
  []
EOF
```

## Phase 2: Image Scanning Workflow

### Step 1 - Generate SBOM
```bash
syft ${IMAGE_REF} -o spdx-json > sbom.spdx.json
syft ${IMAGE_REF} -o cyclonedx-json > sbom.cdx.json
```

### Step 2 - Run Vulnerability Scan
```bash
# Scan directly
grype ${IMAGE_REF} -o json > vulnerability-report.json

# Or scan from SBOM (faster for repeated scans)
grype sbom:sbom.spdx.json -o json > vulnerability-report.json
```

### Step 3 - Evaluate Results
```bash
# Count by severity
cat vulnerability-report.json | jq '.matches | group_by(.vulnerability.severity) | map({severity: .[0].vulnerability.severity, count: length})'

# List critical and high findings
cat vulnerability-report.json | jq '[.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High") | {id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name, version: .artifact.version, fix: .vulnerability.fix.versions}]'
```

### Step 4 - Gate Decision
```bash
# Automated gate check
grype ${IMAGE_REF} --fail-on high
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "GATE FAILED: High or Critical vulnerabilities found"
    exit 1
fi
```

## Phase 3: CI/CD Integration

### GitHub Actions Complete Workflow
```yaml
name: Container Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: myapp:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Scan for vulnerabilities
        uses: anchore/scan-action@v4
        id: scan
        with:
          image: myapp:${{ github.sha }}
          fail-build: true
          severity-cutoff: high
          output-format: sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.scan.outputs.sarif }}

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json
```

## Phase 4: Reporting and Remediation

### Generate Human-Readable Report
```bash
# Table output with full details
grype ${IMAGE_REF} -o table > scan-report.txt

# Generate custom HTML report using template
grype ${IMAGE_REF} -o template -t report.tmpl > report.html
```

### Remediation Workflow
1. Review critical/high findings from scan output
2. Check if fix versions are available (`fix.versions` in JSON output)
3. Update base image to latest patched version
4. Update application dependencies
5. Rebuild and rescan to verify remediation
6. Add accepted risks to `.grype.yaml` ignore list with documented justification

## Phase 5: Continuous Monitoring

### Scheduled Rescans
```yaml
# GitHub Actions scheduled scan
name: Scheduled Vulnerability Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM

jobs:
  rescan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan production images
        run: |
          for image in $(cat image-inventory.txt); do
            grype ${image} --fail-on critical -o json > "report-$(echo $image | tr '/:' '-').json"
          done
```
