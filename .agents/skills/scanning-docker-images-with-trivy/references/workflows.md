# Workflows - Docker Image Scanning with Trivy

## Workflow 1: Developer Local Scan

```
[Developer builds image] --> [trivy image myapp:latest]
         |                            |
         v                            v
    Fix Dockerfile              Review findings
    Update deps                      |
         |                    +------+------+
         |                    |             |
         v                    v             v
    Rebuild image       CRITICAL/HIGH    MEDIUM/LOW
         |               found?           found?
         |                 |               |
         v                 v               v
    Re-scan          Fix immediately   Add to backlog
                     before commit     or .trivyignore
```

## Workflow 2: CI/CD Gate Scan

```yaml
# Pipeline stages
Build --> Scan --> Gate Decision --> Deploy/Block

# Gate policy
CRITICAL: Block deployment, fail pipeline (exit-code 1)
HIGH: Block deployment to production
MEDIUM: Warn, allow deployment to staging
LOW: Informational only
```

## Workflow 3: Registry Continuous Scanning

```
[Images in Registry]
        |
        v
[Scheduled Trivy Scan (daily/weekly)]
        |
        +--> [New CVE detected in existing image]
        |            |
        |            v
        |     [Create JIRA/GitHub issue]
        |            |
        |            v
        |     [Rebuild and push patched image]
        |
        +--> [No new CVEs]
                     |
                     v
              [Log clean scan result]
```

## Workflow 4: Full SBOM + Vulnerability Pipeline

```bash
#!/bin/bash
IMAGE="myapp:v1.0.0"

# Step 1: Generate SBOM
trivy image --format cyclonedx --output sbom.cdx.json "$IMAGE"

# Step 2: Vulnerability scan
trivy image --format json --output vuln-report.json "$IMAGE"

# Step 3: License scan
trivy image --scanners license --format json --output license-report.json "$IMAGE"

# Step 4: Secret scan
trivy image --scanners secret --format json --output secret-report.json "$IMAGE"

# Step 5: Config scan (if Dockerfile available)
trivy config --format json --output config-report.json Dockerfile

# Step 6: Generate HTML report
trivy image --format template \
  --template "@contrib/html.tpl" \
  --output report.html "$IMAGE"

# Step 7: Upload to dependency tracking (e.g., Dependency-Track)
curl -X POST "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -F "project=$PROJECT_UUID" \
  -F "bom=@sbom.cdx.json"
```

## Workflow 5: Multi-Image Fleet Scanning

```bash
#!/bin/bash
# Scan all images in a Kubernetes cluster

# Get unique images
IMAGES=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u)

echo "Scanning $(echo "$IMAGES" | wc -l) unique images..."

for IMAGE in $IMAGES; do
  echo "=== Scanning: $IMAGE ==="
  trivy image --severity CRITICAL,HIGH --exit-code 0 \
    --format json --output "scan_$(echo $IMAGE | tr '/:' '_').json" \
    "$IMAGE" 2>/dev/null
done

# Aggregate results
echo "Generating aggregate report..."
python3 aggregate_trivy_results.py scan_*.json > fleet_report.json
```

## Workflow 6: Trivy Operator for Kubernetes

```yaml
# Install Trivy Operator via Helm
# helm install trivy-operator aquasecurity/trivy-operator \
#   --namespace trivy-system --create-namespace

# VulnerabilityReport is created automatically for each workload
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  name: pod-myapp-myapp
  namespace: default
spec:
  scanner:
    name: Trivy
    version: 0.50.0
report:
  summary:
    criticalCount: 2
    highCount: 5
    mediumCount: 12
    lowCount: 8
```
