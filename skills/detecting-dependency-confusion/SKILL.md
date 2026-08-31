---
name: detecting-dependency-confusion
description: Detect and prevent dependency confusion (public-over-private package name resolution) in npm, PyPI, and Maven by enumerating claimable internal package names with tools like `confused` and OWASP `dep-scan`, then enforcing source restrictions via `.npmrc`, `pip.conf`/`pyproject.toml`, and Maven `settings.xml`. Use when onboarding a repo to a supply-chain security program, auditing lockfiles/manifests for confusable dependencies, or after an incident that may have leaked internal package names. Do not use for offensively simulating a supply chain attack - use performing-supply-chain-attack-simulation.
domain: cybersecurity
subdomain: supply-chain-security
tags:
- supply-chain-security
- dependency-confusion
- npm
- pypi
- maven
- package-management
- devsecops
- namespace-hijacking
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-09
mitre_attack:
- T1195.001
---
# Detecting Dependency Confusion

> **Legal Notice:** This skill is for authorized security testing, defensive engineering, and educational purposes only. Registering or claiming package namespaces you do not own, or testing build pipelines without written authorization, may be illegal and may violate the terms of service of public registries. Only run namespace-claiming or resolution-testing activities against names and infrastructure you control or are explicitly authorized to assess.

## Overview

Dependency confusion (also called a substitution or namespace-shadowing attack) was popularized by Alex Birsan in 2021 when he forced malicious code into the internal build systems of Apple, Microsoft, PayPal, and dozens of others. The root cause is that many package managers, when configured to resolve from both an internal/private registry and a public one, will prefer whichever copy has the **higher version number** rather than honoring the source. An attacker who learns the name of a private package (`@acme/internal-utils`, `acme-billing-sdk`) can publish a malicious package of the **same name** to the public registry (npmjs.com, PyPI, Maven Central) with a very high version (e.g. `99.0.0`). When the victim's CI/CD runner or a developer machine resolves dependencies, it pulls the attacker's public package, executes its install scripts, and the supply chain is compromised.

This skill covers both halves of the problem: **detection** — enumerating internal package names that are not registered (squatted defensively) on public registries and are therefore claimable, using `confused` and OWASP `dep-scan` — and **prevention** — pinning scopes/namespaces to private registries, registering placeholder packages, and enforcing source restrictions in `.npmrc`, `pip.conf`/`pyproject.toml`, and Maven `settings.xml`. Internal package names leak constantly: in committed lockfiles, sourcemaps, public JS bundles, Docker layers, and error stack traces, so this is treated as an attack-surface management problem, not a one-time check.

## When to Use

- When onboarding a repository or organization to a supply-chain security program and you need to baseline which internal packages are claimable on public registries.
- When CI/CD pipelines resolve dependencies from both private and public registries (mixed/hybrid feeds).
- After any incident where internal package names may have been exposed (leaked source, public bundle, breached repo).
- When auditing `package.json`, `requirements.txt`, `pom.xml`, `composer.json`, or `Gemfile.lock` files for confusable dependencies.
- As a recurring scheduled control to detect newly added internal packages that have not yet been defensively registered.

## Prerequisites

- Go 1.20+ to install `confused`:
  ```bash
  go install github.com/visma-prodsec/confused@latest
  # binary lands in $(go env GOPATH)/bin/confused
  ```
- Python 3.10+ for OWASP dep-scan:
  ```bash
  pip install owasp-depscan
  # or container: docker pull ghcr.io/owasp-dep-scan/dep-scan
  ```
- Node.js + npm (for `.npmrc` and `npm config` remediation) and access to your private registry (Artifactory, Nexus, Azure Artifacts, GitHub Packages, AWS CodeArtifact).
- Read access to the repositories / lockfiles being assessed and write access to your private registry for defensive registration.

## Objectives

- Enumerate every internal dependency declared in project manifests across npm, PyPI, Maven, Composer, and RubyGems.
- Determine which internal names are **not** present on the corresponding public registry and are therefore claimable.
- Distinguish true exposure from false positives (scoped packages, already-mirrored names).
- Apply registry-pinning and scope-restriction controls that make public substitution impossible.
- Defensively register placeholder packages for unclaimed internal names.
- Establish a recurring detection control in CI to catch newly introduced confusable dependencies.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Core technique — attacker substitutes a malicious public package for an internal dependency. |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Broader category covering the compromised build artifacts produced once confusion succeeds. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | npm `preinstall`/`postinstall` lifecycle scripts execute attacker JavaScript on resolution. |
| T1071.001 | Application Layer Protocol: Web Protocols | Substituted package beacons stolen environment/credentials to attacker HTTP(S) endpoint. |

## Workflow

### 1. Inventory manifests across the codebase
Locate every dependency manifest so nothing is missed.
```bash
# Find all supported manifests in a monorepo
find . -type f \( \
  -name package.json -o \
  -name requirements.txt -o \
  -name pom.xml -o \
  -name composer.json -o \
  -name Gemfile.lock \
\) -not -path '*/node_modules/*' -print
```

### 2. Scan npm manifests with confused
`confused` reads the manifest and reports every dependency name **not found** on the public registry — those are candidates for confusion.
```bash
# npm (default language is npm)
confused -l npm package.json

# Treat your known-good scopes as secure to suppress false positives (supports wildcards)
confused -l npm -s '@acme/*,@acme-internal/*' package.json

# Verbose, to see each lookup
confused -l npm -v package.json
```

### 3. Scan PyPI, Maven, Composer, and RubyGems manifests
The `-l` flag selects the ecosystem; each maps to its standard manifest file.
```bash
confused -l pip requirements.txt          # PyPI  -> requirements.txt
confused -l mvn pom.xml                    # Maven -> pom.xml
confused -l composer composer.json        # PHP   -> composer.json
confused -l rubygems Gemfile.lock         # Ruby  -> Gemfile.lock
```

### 4. Cross-check with OWASP dep-scan private-namespace mode
dep-scan confirms confusion exposure for declared private namespaces and folds it into a broader risk audit.
```bash
# Flag private namespaces accidentally claimable on public registries
depscan --src $PWD --reports-dir ./reports \
  --private-ns acme,acme_internal,@acme

# Enable deep package risk audit (npm + pypi): typosquats, takeover risk, etc.
depscan --src $PWD --reports-dir ./reports --risk-audit
```

### 5. Triage candidates and confirm claimability
For each flagged name, verify it is genuinely absent on the public registry (a 404 means claimable).
```bash
# npm: a 404 status means the name is unregistered on the public registry
curl -s -o /dev/null -w "%{http_code}\n" https://registry.npmjs.org/@acme%2finternal-utils

# PyPI: 404 from the JSON API means the project name is free
curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/acme-billing-sdk/json
```

### 6. Remediate npm with scope-to-registry pinning
Bind every internal scope to the private registry so a public package of the same name can never be resolved.
```ini
# .npmrc (project root, committed)
@acme:registry=https://artifactory.example.com/api/npm/npm-internal/
//artifactory.example.com/api/npm/npm-internal/:_authToken=${NPM_TOKEN}

# Force the default registry to a single proxy that does NOT merge public + private
registry=https://artifactory.example.com/api/npm/npm-virtual/
```
Verify the resolution source before installing:
```bash
npm config get @acme:registry
npm install --dry-run   # confirm @acme/* resolves from the private host
```

### 7. Remediate PyPI and Maven
Pin Python index resolution and Maven mirroring so public sources cannot shadow internal artifacts.
```toml
# pyproject.toml (PEP 621 / pip >= 23): explicit index pinning
[tool.pip]
index-url = "https://artifactory.example.com/api/pypi/pypi-internal/simple/"
# Do NOT use extra-index-url for internal packages — pip merges and picks highest version.
```
```xml
<!-- ~/.m2/settings.xml: mirror everything through a single virtual repo -->
<mirrors>
  <mirror>
    <id>internal-virtual</id>
    <mirrorOf>*</mirrorOf>
    <url>https://artifactory.example.com/artifactory/maven-virtual</url>
  </mirror>
</mirrors>
```

### 8. Defensively register placeholder packages
For names you cannot fully isolate, claim the public name yourself with an empty, non-functional placeholder so an attacker cannot.
```bash
# npm placeholder claim (scoped, public)
mkdir acme-internal-utils && cd acme-internal-utils
npm init -y
npm pkg set version=0.0.1-placeholder description="Reserved internal name. Do not use."
npm publish --access public
```

### 9. Wire detection into CI
Fail the pipeline if any new confusable dependency appears.
```yaml
# .github/workflows/depconfusion.yml
name: dependency-confusion
on: [push, pull_request]
jobs:
  confused:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go install github.com/visma-prodsec/confused@latest
      - name: Scan npm manifest
        run: $(go env GOPATH)/bin/confused -l npm -s '@acme/*' package.json
```

### 10. Run the bundled helper for batch triage
Use the included `agent.py` to scan a tree and emit a structured report combining `confused` and live registry probes.
```bash
python scripts/agent.py --path . --ecosystem npm \
  --secure-namespaces '@acme/*,@acme-internal/*' \
  --output report.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| confused | Detect lingering free namespaces for declared dependencies | https://github.com/visma-prodsec/confused |
| ConfusedDotnet | Same check for NuGet/.NET | https://github.com/visma-prodsec/ConfusedDotnet |
| OWASP dep-scan | Risk audit incl. `--private-ns` confusion check | https://github.com/owasp-dep-scan/dep-scan |
| OWASP CI/CD Top 10 | CICD-SEC-03 Dependency Chain Abuse | https://owasp.org/www-project-top-10-ci-cd-security-risks/ |
| Birsan research | Original dependency confusion writeup | https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 |
| npm scopes docs | Scope-to-registry pinning reference | https://docs.npmjs.com/cli/v10/using-npm/scope |

## Validation Criteria

- [ ] All dependency manifests in the codebase enumerated.
- [ ] `confused` run for every relevant ecosystem with secure namespaces supplied.
- [ ] OWASP dep-scan `--private-ns` run and reconciled with `confused` output.
- [ ] Each flagged name confirmed claimable (404) or dismissed as a false positive.
- [ ] Internal scopes pinned to the private registry in `.npmrc` / `pip` config / Maven mirror.
- [ ] `extra-index-url` and merged virtual feeds reviewed for highest-version pull risk.
- [ ] Placeholder packages registered for names that cannot be isolated.
- [ ] CI job enforces the check on every push/PR.
- [ ] Findings documented with owner and remediation status.
