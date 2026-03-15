# API Reference: SAST in GitHub Actions Pipeline

## Semgrep CLI

### Installation
```bash
pip install semgrep
```

### Scan Commands
```bash
semgrep scan --config auto --json .           # Auto-detect rules
semgrep scan --config p/owasp-top-ten --json . # OWASP rules
semgrep scan --config p/ci --sarif .           # CI-optimized rules
```

### JSON Output Structure
```json
{"results": [{"check_id": "rule-id", "path": "file.py",
  "start": {"line": 10}, "extra": {"severity": "ERROR",
  "message": "...", "metadata": {"cwe": ["CWE-89"], "owasp": ["A03"]}}}]}
```

### Severity Levels
| Level | Action |
|-------|--------|
| ERROR | Block merge |
| WARNING | Require review |
| INFO | Advisory only |

## GitHub Actions Integration

### Semgrep Action
```yaml
- uses: returntocorp/semgrep-action@v1
  with:
    config: auto
    generateSarif: "1"
```

### SARIF Upload
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: semgrep.sarif
```

### SARIF 2.1.0 Schema
| Field | Description |
|-------|-------------|
| `runs[].tool.driver.name` | Scanner name |
| `runs[].tool.driver.rules` | Rule definitions |
| `runs[].results` | Finding instances |
| `results[].ruleId` | Matching rule ID |
| `results[].level` | `error`, `warning`, `note` |

## References
- Semgrep: https://semgrep.dev/docs/
- GitHub Code Scanning: https://docs.github.com/en/code-security/code-scanning
- SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
