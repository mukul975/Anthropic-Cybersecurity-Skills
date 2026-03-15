# Workflow Reference: SCA Dependency Scanning with Snyk

## Dependency Scanning Pipeline

```
Code Push / PR
       │
       ▼
┌──────────────────┐
│ Install Deps     │
│ (npm ci, pip     │
│  install, etc.)  │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ Snyk Test        │──── Report JSON ───> Artifact Storage
│ (vuln scan)      │
└──────┬───────────┘
       │
  ┌────┴────┐
  │         │
PASS      FAIL ──────> PR Comment with vuln details
  │                     │
  │                     ▼
  │              ┌──────────────┐
  │              │ Snyk Fix PR  │
  │              │ (auto-gen)   │
  │              └──────────────┘
  ▼
┌──────────────────┐
│ Snyk Monitor     │
│ (continuous)     │
└──────┬───────────┘
       │
       ▼
  Ongoing alerts for
  new disclosures
```

## Snyk CLI Command Reference

### Scanning Commands
```bash
# Basic vulnerability test
snyk test

# Test with severity filter
snyk test --severity-threshold=high

# Test with exploit maturity filter
snyk test --severity-threshold=high

# Test specific manifest
snyk test --file=package-lock.json

# Test all projects in monorepo
snyk test --all-projects

# Test with dev dependencies excluded
snyk test --production

# Output in JSON
snyk test --json --json-file-output=results.json

# Output in SARIF
snyk test --sarif --sarif-file-output=results.sarif
```

### Monitoring Commands
```bash
# Monitor project for new vulnerabilities
snyk monitor --project-name="my-app-prod"

# Monitor specific branch
snyk monitor --target-reference=main

# Monitor with tags
snyk monitor --project-tags=env=production,team=platform
```

### Fix Commands
```bash
# Preview available fixes
snyk fix --dry-run

# Apply fixes to direct dependencies
snyk fix

# Apply fixes including dev dependencies
snyk fix --dev
```

## Vulnerability Prioritization Matrix

| Factor | Score Weight | Description |
|--------|-------------|-------------|
| CVSS Score | 30% | Base vulnerability severity |
| Exploit Maturity | 25% | Mature > POC > No Known Exploit |
| Reachability | 20% | Function called > Imported > Present |
| Fix Availability | 15% | Upgrade available > Patch > None |
| Dependency Depth | 10% | Direct > Transitive (1 hop) > Deep transitive |

## Snyk Integration Options

| Platform | Integration Method | Features |
|----------|--------------------|----------|
| GitHub | GitHub App | Auto-scan PRs, fix PRs, SARIF upload |
| GitLab | GitLab Integration | MR comments, dependency scanning |
| Jenkins | Snyk Plugin | Pipeline step, HTML reports |
| Azure DevOps | Extension | Pipeline task, dashboard widget |
| Bitbucket | Bitbucket App | PR checks, fix PRs |
| CLI | npm/binary | Local scanning, CI/CD integration |

## Remediation Strategy by Vulnerability Type

### Direct Dependency Vulnerability
1. Check if upgrade is available: `snyk test --json | jq '.vulnerabilities[] | select(.isUpgradable)'`
2. If upgradable: run `snyk fix` or manually upgrade
3. Verify no breaking changes in the upgrade
4. If not upgradable: check for patch or accept risk with ignore

### Transitive Dependency Vulnerability
1. Identify the dependency chain: `snyk test --json | jq '.vulnerabilities[].from'`
2. Check if upgrading the direct dependency resolves it
3. If not: use version overrides in package manager
4. npm: `overrides` in package.json
5. Maven: `dependencyManagement` in pom.xml
6. Gradle: `constraints` in build.gradle
7. Poetry: `tool.poetry.extras` or constraint resolution
