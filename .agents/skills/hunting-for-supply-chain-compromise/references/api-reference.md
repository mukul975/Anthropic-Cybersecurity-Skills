# API Reference: Hunting for Supply Chain Compromise

## NPM Lock File Analysis

```python
import json
data = json.load(open("package-lock.json"))
packages = data.get("packages", {})
for name, info in packages.items():
    resolved = info.get("resolved", "")
    has_script = info.get("hasInstallScript", False)
```

## pip-audit

```bash
pip-audit --format=json --output=audit.json
pip-audit --require=requirements.txt --desc
```

```python
# Programmatic usage
from pip_audit._cli import audit
# Or parse JSON output
import subprocess, json
result = subprocess.run(["pip-audit", "--format=json"], capture_output=True, text=True)
vulns = json.loads(result.stdout)
```

## Hash Verification

```python
import hashlib
sha = hashlib.sha256()
with open("binary.exe", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        sha.update(chunk)
print(sha.hexdigest())
```

## Dependency Confusion Checks

| Registry | Check Command | Risk |
|----------|---------------|------|
| npm | `npm view <pkg> name` | Package exists publicly |
| PyPI | `pip index versions <pkg>` | Package exists publicly |
| Maven | `mvn dependency:resolve` | Artifact on Maven Central |

## Splunk SPL - Build Anomaly Detection

```spl
index=cicd sourcetype=build_logs
| where match(_raw, "(?i)(curl.*\|.*sh|wget.*chmod|--registry\s+http)")
| table _time build_id job_name _raw
```

## Supply Chain Indicators

| Indicator | Severity | Category |
|-----------|----------|----------|
| Known compromised package | CRITICAL | Package takeover |
| Non-standard registry URL | HIGH | Dependency confusion |
| Install scripts in deps | MEDIUM | Post-install hooks |
| Git URL dependencies | MEDIUM | Unpinned source |
| Pipe to shell in CI | CRITICAL | Remote code execution |

### References

- MITRE T1195: https://attack.mitre.org/techniques/T1195/
- pip-audit: https://github.com/pypa/pip-audit
- npm audit: https://docs.npmjs.com/cli/v9/commands/npm-audit
