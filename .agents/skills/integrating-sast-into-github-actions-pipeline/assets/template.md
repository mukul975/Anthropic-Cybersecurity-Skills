# SAST Pipeline Configuration Templates

## GitHub Actions: Combined CodeQL + Semgrep Workflow

```yaml
# .github/workflows/sast-pipeline.yml
name: "SAST Security Pipeline"

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'

concurrency:
  group: sast-${{ github.ref }}
  cancel-in-progress: true

jobs:
  # ─────────────── CodeQL Analysis ───────────────
  codeql:
    name: CodeQL (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: ['javascript', 'python']
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended
          config-file: .github/codeql/codeql-config.yml

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"

  # ─────────────── Semgrep Scan ───────────────
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    container:
      image: semgrep/semgrep:latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep ci \
            --config auto \
            --config p/owasp-top-ten \
            --config p/cwe-top-25 \
            --config .semgrep/ \
            --sarif --output semgrep.sarif \
            --severity ERROR \
            --error
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
          category: semgrep

  # ─────────────── Quality Gate ───────────────
  security-gate:
    name: Security Quality Gate
    needs: [codeql, semgrep]
    runs-on: ubuntu-latest
    if: always()
    steps:
      - name: Check SAST Results
        run: |
          if [ "${{ needs.codeql.result }}" == "failure" ] || [ "${{ needs.semgrep.result }}" == "failure" ]; then
            echo "::error::SAST security gate failed. Review findings in the Security tab."
            exit 1
          fi
          echo "Security gate passed."
```

## CodeQL Custom Configuration

```yaml
# .github/codeql/codeql-config.yml
name: "Organization CodeQL Config"

queries:
  - uses: security-extended
  - uses: security-and-quality

paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/spec/**'
  - '**/vendor/**'
  - '**/node_modules/**'
  - '**/__mocks__/**'
  - '**/*.test.js'
  - '**/*.test.ts'
  - '**/*.spec.py'
  - '**/migrations/**'

query-filters:
  - exclude:
      id: js/unused-local-variable
  - exclude:
      id: py/unused-import
```

## Semgrep Ignore File

```
# .semgrepignore
# Test files
*_test.go
*_test.py
*.test.js
*.test.ts
*.spec.js
*.spec.ts
test/
tests/
__tests__/
spec/

# Generated code
*_generated.go
*.pb.go
**/generated/**

# Vendored dependencies
vendor/
node_modules/
third_party/

# Build artifacts
dist/
build/
out/
```

## Branch Protection Configuration (Terraform)

```hcl
# branch-protection.tf
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_status_checks {
    strict   = true
    contexts = [
      "CodeQL (javascript)",
      "CodeQL (python)",
      "Semgrep Scan",
      "Security Quality Gate"
    ]
  }

  required_pull_request_reviews {
    required_approving_review_count = 1
    dismiss_stale_reviews           = true
  }

  enforce_admins = true

  allows_deletions    = false
  allows_force_pushes = false
}
```

## SARIF Report Aggregation Script

```bash
#!/bin/bash
# aggregate-sarif.sh - Merge multiple SARIF files for unified upload
set -euo pipefail

OUTPUT="merged-results.sarif"
SARIF_FILES=($(find . -name "*.sarif" -type f))

if [ ${#SARIF_FILES[@]} -eq 0 ]; then
  echo "No SARIF files found"
  exit 0
fi

# Use jq to merge SARIF runs
jq -s '{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [.[].runs[]]
}' "${SARIF_FILES[@]}" > "$OUTPUT"

echo "Merged ${#SARIF_FILES[@]} SARIF files into $OUTPUT"
TOTAL=$(jq '[.runs[].results | length] | add' "$OUTPUT")
echo "Total findings: $TOTAL"
```
