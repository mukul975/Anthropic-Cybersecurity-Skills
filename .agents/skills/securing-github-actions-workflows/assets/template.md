# GitHub Actions Security Templates

## Hardened Workflow Template

```yaml
name: Secure CI Pipeline
permissions: {}

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: step-security/harden-runner@17d0e2bd7d51742c71671bd19fa12bdc9d40a3d6  # v2.8.1
        with:
          egress-policy: audit
      - name: Build
        run: make build
      - name: Test
        run: make test
```

## Dependabot for Actions

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
```

## CODEOWNERS for Workflow Protection

```
# .github/CODEOWNERS
.github/workflows/ @org/security-team @org/platform-team
.github/actions/ @org/security-team
.github/dependabot.yml @org/platform-team
```
