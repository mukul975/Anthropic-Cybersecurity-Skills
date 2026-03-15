# SCA Dependency Scanning with Snyk - API Reference

## Snyk CLI Commands

### snyk test
Scans project dependencies for known vulnerabilities.

```bash
snyk test --json --severity-threshold=high
snyk test --json --all-projects          # Monorepo support
snyk test --json --file=package-lock.json
```

Exit codes:
- 0: No vulnerabilities found
- 1: Vulnerabilities found
- 2: Failure (missing manifest, auth error)

### snyk monitor
Creates a project snapshot for continuous monitoring on snyk.io.

```bash
snyk monitor --json --project-name="my-app"
```

### snyk auth
Authenticate with Snyk API token.

```bash
snyk auth <API_TOKEN>
export SNYK_TOKEN=<API_TOKEN>
```

## JSON Output Structure

### Test Result Fields

| Field | Type | Description |
|-------|------|-------------|
| `vulnerabilities` | array | List of vulnerability objects |
| `ok` | boolean | True if no vulns found |
| `dependencyCount` | int | Total dependencies scanned |
| `packageManager` | string | npm, pip, maven, etc. |
| `uniqueCount` | int | Unique vulnerability count |

### Vulnerability Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Snyk vulnerability ID (e.g., `SNYK-JS-LODASH-590103`) |
| `title` | string | Human-readable title |
| `severity` | string | critical, high, medium, low |
| `cvssScore` | float | CVSS v3.1 score (0-10) |
| `packageName` | string | Affected package name |
| `version` | string | Installed version |
| `fixedIn` | array | Versions with fix available |
| `exploit` | string | Exploit maturity: Mature, Proof of Concept, Not Defined |
| `isUpgradable` | boolean | Can be fixed by upgrading direct dependency |
| `isPatchable` | boolean | Snyk patch available |
| `from` | array | Dependency path from root |

## SARIF Integration

Snyk results can be converted to SARIF 2.1.0 for GitHub Code Scanning. The SARIF schema is at:
`https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`

## Severity Mapping

| Snyk Severity | CVSS Range | SARIF Level |
|---------------|-----------|-------------|
| critical | 9.0 - 10.0 | error |
| high | 7.0 - 8.9 | error |
| medium | 4.0 - 6.9 | warning |
| low | 0.1 - 3.9 | warning |

## CLI Usage

```bash
python agent.py --project /app --severity high --max-critical 0 --max-high 5 --output report.json
```
