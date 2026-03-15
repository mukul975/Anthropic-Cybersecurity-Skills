# API Reference: Detecting Supply Chain Attacks in CI/CD

## GitHub Actions Workflow Parsing

```python
import yaml

with open(".github/workflows/ci.yml") as f:
    wf = yaml.safe_load(f)

# Key fields
wf["permissions"]           # Workflow-level permissions
wf["jobs"]["build"]["steps"] # Step list
step["uses"]                # Action reference (owner/repo@ref)
step["run"]                 # Shell script
step["env"]                 # Environment variables
```

## Supply Chain Risk Patterns

| Risk | Pattern | Severity |
|------|---------|----------|
| Unpinned action | `uses: owner/action@main` | CRITICAL |
| Mutable tag | `uses: owner/action@v1` | MEDIUM |
| Script injection | `run: echo ${{ github.event.issue.title }}` | CRITICAL |
| Write permissions | `permissions: write-all` | HIGH |
| Curl pipe bash | `RUN curl \| bash` | HIGH |
| Latest image tag | `FROM image:latest` | MEDIUM |

## Dependency Confusion Check

```python
import requests
# Check if private package exists on public registry
resp = requests.get(f"https://registry.npmjs.org/{pkg}")
exists = resp.status_code == 200

resp = requests.get(f"https://pypi.org/pypi/{pkg}/json")
exists = resp.status_code == 200
```

## Pinning Actions to SHA

```yaml
# Bad: mutable reference
uses: actions/checkout@main
# Good: pinned to commit SHA
uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
```

### References

- GitHub Actions security hardening: https://docs.github.com/en/actions/security-guides
- StepSecurity: https://github.com/step-security/harden-runner
- Dependency confusion: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
