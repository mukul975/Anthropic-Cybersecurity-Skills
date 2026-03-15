# Supply Chain Attack Simulation Reference

## Tool Installation

```bash
pip install pip-audit python-Levenshtein requests
```

## PyPI JSON API

```bash
# Get package metadata
curl https://pypi.org/pypi/{package_name}/json

# Get specific version
curl https://pypi.org/pypi/{package_name}/{version}/json
```

### Response Structure

```json
{
  "info": {
    "name": "requests",
    "version": "2.31.0",
    "author": "Kenneth Reitz",
    "author_email": "me@kennethreitz.org",
    "home_page": "https://requests.readthedocs.io",
    "summary": "Python HTTP for Humans."
  },
  "urls": [
    {
      "filename": "requests-2.31.0.tar.gz",
      "packagetype": "sdist",
      "digests": {
        "sha256": "942c5a758f98d790eaed1a29cb6eefc7f0edf3fcb0fce8aea3fbd5951d bfcfeb"
      }
    }
  ]
}
```

## pip-audit CLI

```bash
# Audit current environment
pip-audit

# JSON output
pip-audit --format json

# Audit requirements file
pip-audit -r requirements.txt

# Hash-checking mode (pinned deps only)
pip-audit --require-hashes -r requirements.txt

# Fix vulnerabilities automatically
pip-audit --fix
```

## pip Hash Verification

```bash
# Download with hash verification
pip download --no-deps --require-hashes -r requirements.txt

# requirements.txt with hashes
requests==2.31.0 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7f0edf3fcb0fce8aea3fbd5951dbfcfeb
```

## pypi-scan Typosquatting Detection

```bash
# Install
pip install pypi-scan

# Scan for typosquatting of a package
pypi-scan --package requests

# Scan with custom edit distance
pypi-scan --package numpy --edit-distance 2
```

## Levenshtein Distance Examples

| Package | Target | Distance | Risk |
|---------|--------|----------|------|
| `reqeusts` | `requests` | 1 | High |
| `requets` | `requests` | 1 | High |
| `request` | `requests` | 1 | High |
| `numpys` | `numpy` | 1 | High |
| `pandsa` | `pandas` | 1 | High |
| `flaask` | `flask` | 1 | High |

## Dependency Confusion Test Structure

```json
[
  {"name": "my-internal-lib", "version": "1.2.0"},
  {"name": "company-utils", "version": "0.5.3"},
  {"name": "private-auth-sdk", "version": "2.1.0"}
]
```

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Supply Chain Compromise | T1195.001 | Compromise software dependencies |
| Trusted Developer Utilities | T1127 | Abuse package manager trust |
| Ingress Tool Transfer | T1105 | Download malicious packages |

## Metadata Anomaly Indicators

| Indicator | Risk | Description |
|-----------|------|-------------|
| Disposable email author | High | Author uses throwaway email service |
| No homepage/repo URL | Medium | Package has no verifiable source |
| No author info | Medium | Anonymous package publication |
| Very short description | Low | Minimal package documentation |
| Recent first upload + popular name variant | Critical | Likely typosquatting attempt |
