# API Reference and Command Examples

## Package Manager CLI Commands

### npm (Node Package Manager)

#### Configuration
```bash
# View current npm configuration
npm config list
npm config get registry
npm config get @yourorg:registry

# Set scoped registry
npm config set @yourorg:registry https://npm.yourorg.com/

# Set authentication token
npm config set //npm.yourorg.com/:_authToken ${NPM_TOKEN}

# View effective configuration (merged from all .npmrc files)
npm config list --json

# Locate configuration files
npm config get userconfig   # ~/.npmrc
npm config get globalconfig # /usr/local/etc/npmrc
```

#### Package inspection
```bash
# View package metadata
npm view <package> --json

# Check if package exists on registry
npm view <package> version 2>/dev/null && echo "EXISTS" || echo "NOT FOUND"

# List all versions
npm view <package> versions --json

# Check for install scripts
npm view <package> scripts

# Download package without installing
npm pack <package>@<version>

# Extract and inspect
tar -xzf <package>-<version>.tgz
cd package/
cat package.json | jq '.scripts'
```

#### Security scanning
```bash
# Built-in audit (CVE-based only)
npm audit
npm audit --json
npm audit fix

# Socket.dev behavioral analysis
npx @socketsecurity/cli npm audit
npx @socketsecurity/cli npm install --bail-on-threat

# Snyk scanning
npx snyk test
npx snyk monitor
```

---

### pip (Python Package Installer)

#### Configuration
```bash
# View configuration
pip config list
pip config get global.index-url

# Set private registry
pip config set global.index-url https://pypi.yourorg.com/simple

# Set fallback public registry
pip config set global.extra-index-url https://pypi.org/simple

# View all configuration files
pip config list -v

# Configuration file locations:
# Global:  /etc/pip.conf or /usr/pip.conf
# User:    ~/.config/pip/pip.conf or ~/.pip/pip.conf
# Venv:    $VIRTUAL_ENV/pip.conf
```

#### Package inspection
```bash
# Check if package exists on PyPI
pip index versions <package>

# Download package without installing
pip download <package> --no-deps

# Extract and inspect
tar -xzf <package>-<version>.tar.gz
cd <package>-<version>/
cat setup.py

# Check for malicious patterns in setup.py
grep -E "os.system|subprocess|eval|exec|__import__|urllib" setup.py
```

#### Security scanning
```bash
# pip-audit (CVE-based)
pip install pip-audit
pip-audit

# Safety (commercial, CVE-based)
pip install safety
safety check

# Snyk for Python
snyk test --file=requirements.txt
```

---

### Maven (Java)

#### Configuration
Check `~/.m2/settings.xml` and `pom.xml`:

```bash
# Validate settings.xml
xmllint --noout ~/.m2/settings.xml

# Extract repository URLs from pom.xml
xmllint --xpath "//repository/url/text()" pom.xml

# Check effective POM (merged from parent POMs)
mvn help:effective-pom
```

#### Package inspection
```bash
# Download dependency without installing
mvn dependency:get -Dartifact=groupId:artifactId:version

# Dependency tree
mvn dependency:tree

# Analyze dependencies
mvn dependency:analyze

# Check for known vulnerabilities (via OWASP Dependency-Check)
mvn org.owasp:dependency-check-maven:check
```

---

### RubyGems

#### Configuration
```bash
# List configured sources
gem sources --list

# Add private gem server
gem sources --add https://gems.yourorg.com/

# Remove public RubyGems (use with caution)
gem sources --remove https://rubygems.org/

# Check gem server priority
gem sources --list
# Order matters: first source is checked first
```

#### Package inspection
```bash
# Search for gem on registry
gem search <gem> --remote

# Show gem details
gem specification <gem> --remote

# Download gem without installing
gem fetch <gem>

# Extract and inspect
gem unpack <gem>-<version>.gem
cd <gem>-<version>/
cat <gem>.gemspec
```

#### Security scanning
```bash
# bundler-audit (CVE-based)
gem install bundler-audit
bundle audit check --update

# Snyk for Ruby
snyk test --file=Gemfile.lock
```

## Detection Scripts

### Check for Public Registry Collisions

**collision_check.sh**:
```bash
#!/bin/bash
# Checks if internal package names exist on public registries

INTERNAL_PACKAGES="internal_packages.txt"
ALERT_EMAIL="security@yourorg.com"

echo "Checking for dependency confusion risks..."

while IFS= read -r package; do
  # Check npm
  if npm view "$package" version &>/dev/null; then
    PUBLISH_DATE=$(npm view "$package" time.created --json | jq -r '.')
    echo "⚠️  COLLISION: $package exists on public npm (published $PUBLISH_DATE)"
    echo "$package,npm,$PUBLISH_DATE" >> collisions.csv
  fi
  
  # Check PyPI
  if pip index versions "$package" &>/dev/null; then
    echo "⚠️  COLLISION: $package exists on PyPI"
    echo "$package,pypi,unknown" >> collisions.csv
  fi
  
  # Check RubyGems
  if gem search "^$package$" --remote | grep -q "^$package "; then
    echo "⚠️  COLLISION: $package exists on RubyGems"
    echo "$package,rubygems,unknown" >> collisions.csv
  fi
done < "$INTERNAL_PACKAGES"

# Send alert if collisions found
if [ -f collisions.csv ]; then
  mail -s "Dependency Confusion Alert" "$ALERT_EMAIL" < collisions.csv
fi
```

---

### Monitor Install Script Behavior

**monitor_install.sh**:
```bash
#!/bin/bash
# Monitors network activity during npm install

PACKAGE=$1
PCAP_FILE="install_${PACKAGE}_$(date +%s).pcap"

echo "Installing $PACKAGE with network monitoring..."

# Start tcpdump
sudo tcpdump -i any -n -w "$PCAP_FILE" 'tcp port 80 or tcp port 443' &
TCPDUMP_PID=$!

# Install package
npm install "$PACKAGE" --ignore-scripts=false

# Stop tcpdump
sudo kill $TCPDUMP_PID

# Analyze captured traffic
echo "Analyzing network connections..."
tshark -r "$PCAP_FILE" -T fields -e ip.dst -e tcp.dstport | sort -u > connections.txt

# Check for suspicious destinations (not official registries)
SUSPICIOUS=$(grep -v "registry.npmjs.org\|npmjs.com\|github.com" connections.txt)

if [ -n "$SUSPICIOUS" ]; then
  echo "🚨 SUSPICIOUS CONNECTIONS DETECTED:"
  echo "$SUSPICIOUS"
  exit 1
else
  echo "✅ No suspicious connections"
  exit 0
fi
```

---

### Extract and Deobfuscate Install Scripts

**extract_scripts.py**:
```python
#!/usr/bin/env python3
"""
Extracts and deobfuscates install scripts from npm packages.
"""
import json
import subprocess
import sys
import base64
import re

def download_package(package_name, version=None):
    """Download package tarball."""
    if version:
        pkg_spec = f"{package_name}@{version}"
    else:
        pkg_spec = package_name
    
    result = subprocess.run(['npm', 'pack', pkg_spec], 
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error downloading {pkg_spec}", file=sys.stderr)
        return None
    
    tarball = result.stdout.strip()
    return tarball

def extract_package(tarball):
    """Extract npm tarball."""
    subprocess.run(['tar', '-xzf', tarball], check=True)

def analyze_scripts(package_json_path='package/package.json'):
    """Analyze install scripts from package.json."""
    with open(package_json_path) as f:
        pkg_data = json.load(f)
    
    scripts = pkg_data.get('scripts', {})
    dangerous_hooks = ['preinstall', 'install', 'postinstall', 
                      'preuninstall', 'uninstall', 'postuninstall']
    
    findings = []
    for hook in dangerous_hooks:
        if hook in scripts:
            script = scripts[hook]
            findings.append({
                'hook': hook,
                'command': script,
                'suspicious': check_suspicious(script)
            })
    
    return findings

def check_suspicious(script):
    """Check for suspicious patterns in install scripts."""
    patterns = {
        'network': r'curl|wget|http\.request|fetch|XMLHttpRequest',
        'env_access': r'process\.env|os\.environ|\$\{.*\}',
        'shell_exec': r'child_process|subprocess|eval|exec\(',
        'obfuscation': r'Buffer\.from|atob|fromCharCode',
        'file_access': r'fs\.readFile|fs\.writeFile|open\('
    }
    
    matches = {}
    for pattern_name, pattern in patterns.items():
        if re.search(pattern, script, re.IGNORECASE):
            matches[pattern_name] = True
    
    return matches

def deobfuscate(script):
    """Attempt to deobfuscate common patterns."""
    # Base64
    b64_pattern = r'Buffer\.from\([\'"]([A-Za-z0-9+/=]+)[\'"]\s*,\s*[\'"]base64[\'"]\)'
    matches = re.findall(b64_pattern, script)
    
    decoded = []
    for match in matches:
        try:
            decoded.append(base64.b64decode(match).decode())
        except:
            pass
    
    return decoded

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: extract_scripts.py <package-name> [version]")
        sys.exit(1)
    
    package = sys.argv[1]
    version = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Analyzing {package}...")
    
    tarball = download_package(package, version)
    if not tarball:
        sys.exit(1)
    
    extract_package(tarball)
    findings = analyze_scripts()
    
    if findings:
        print("\n🔍 Install Scripts Found:")
        for finding in findings:
            print(f"\n  Hook: {finding['hook']}")
            print(f"  Command: {finding['command']}")
            if finding['suspicious']:
                print(f"  ⚠️  Suspicious patterns: {', '.join(finding['suspicious'].keys())}")
            
            # Attempt deobfuscation
            decoded = deobfuscate(finding['command'])
            if decoded:
                print(f"  🔓 Deobfuscated:")
                for dec in decoded:
                    print(f"     {dec}")
    else:
        print("✅ No install scripts found")
```

## SBOM Generation and Analysis

### Generate SBOM with Syft
```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Generate SBOM from directory
syft dir:. -o cyclonedx-json > sbom.json

# Generate SBOM from container
syft nginx:latest -o spdx-json > nginx-sbom.json

# Generate SBOM from npm project
syft npm:package-lock.json -o cyclonedx-json > sbom.json
```

### Scan SBOM for Vulnerabilities with Grype
```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Scan SBOM
grype sbom:sbom.json

# Scan with specific severity threshold
grype sbom:sbom.json --fail-on high

# Output as JSON
grype sbom:sbom.json -o json > vulnerabilities.json
```

### Analyze SBOM for Dependency Confusion
```python
#!/usr/bin/env python3
"""
Checks SBOM for packages from unexpected registries.
"""
import json
import sys

APPROVED_REGISTRIES = [
    'registry.npmjs.org',
    'npm.yourorg.com',
    'pypi.org',
    'pypi.yourorg.com'
]

def analyze_sbom(sbom_path):
    """Analyze SBOM for registry sources."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    
    # CycloneDX format
    components = sbom.get('components', [])
    
    suspicious = []
    for component in components:
        # Check external references (download locations)
        ext_refs = component.get('externalReferences', [])
        for ref in ext_refs:
            if ref.get('type') == 'distribution':
                url = ref.get('url', '')
                
                # Extract registry from URL
                registry = extract_registry(url)
                if registry and registry not in APPROVED_REGISTRIES:
                    suspicious.append({
                        'name': component.get('name'),
                        'version': component.get('version'),
                        'registry': registry,
                        'url': url
                    })
    
    return suspicious

def extract_registry(url):
    """Extract registry hostname from URL."""
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: analyze_sbom.py <sbom.json>")
        sys.exit(1)
    
    suspicious = analyze_sbom(sys.argv[1])
    
    if suspicious:
        print("🚨 Packages from unapproved registries:")
        for pkg in suspicious:
            print(f"  - {pkg['name']}@{pkg['version']} from {pkg['registry']}")
        sys.exit(1)
    else:
        print("✅ All packages from approved registries")
        sys.exit(0)
```

## CI/CD Integration Examples

### GitHub Actions
```yaml
name: Dependency Confusion Check

on: [pull_request, push]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Verify .npmrc configuration
        run: |
          if [ ! -f .npmrc ]; then
            echo "::error::.npmrc missing"
            exit 1
          fi
          if ! grep -q "@yourorg:registry" .npmrc; then
            echo "::error::Scoped registry not configured"
            exit 1
          fi
      
      - name: Socket Security Scan
        uses: SocketDev/socket-action@v1
        with:
          token: ${{ secrets.SOCKET_TOKEN }}
          fail-on-threat: true
      
      - name: Check for public collisions
        run: |
          jq -r '.dependencies, .devDependencies | keys[]' package.json | \
          grep "@yourorg/" | \
          while read pkg; do
            public_name=${pkg#@yourorg/}
            if npm view "$public_name" version 2>/dev/null; then
              echo "::error::Public collision: $public_name"
              exit 1
            fi
          done
```

### GitLab CI
```yaml
dependency-security:
  stage: test
  image: node:20-alpine
  script:
    - npm install -g @socketsecurity/cli
    - socket npm audit
    - |
      # Check for unscoped internal packages
      jq -r '.dependencies, .devDependencies | keys[]' package.json | \
      grep -v "^@" | \
      while read pkg; do
        if [[ "$pkg" == company-* ]]; then
          echo "ERROR: Unscoped internal package: $pkg"
          exit 1
        fi
      done
  only:
    - merge_requests
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Dependency Scan') {
            steps {
                script {
                    // Socket.dev scan
                    sh 'npx @socketsecurity/cli npm audit'
                    
                    // Custom collision check
                    sh './scripts/collision_check.sh'
                    
                    // Verify registry configuration
                    def npmrc = readFile('.npmrc')
                    if (!npmrc.contains('@yourorg:registry')) {
                        error('.npmrc missing scoped registry configuration')
                    }
                }
            }
        }
    }
}
```

## Package Registry API Examples

### npm Registry API
```bash
# Get package metadata
curl https://registry.npmjs.org/<package>

# Get specific version
curl https://registry.npmjs.org/<package>/<version>

# Search packages
curl "https://registry.npmjs.org/-/v1/search?text=<query>"

# Check if package exists (HTTP 200 = exists, 404 = not found)
curl -I https://registry.npmjs.org/<package>
```

### PyPI API
```bash
# Get package metadata
curl https://pypi.org/pypi/<package>/json

# Get specific version
curl https://pypi.org/pypi/<package>/<version>/json

# Search packages (via warehouse API)
curl "https://pypi.org/search/?q=<query>"
```

### RubyGems API
```bash
# Get gem metadata
curl https://rubygems.org/api/v1/gems/<gem>.json

# Get all versions
curl https://rubygems.org/api/v1/versions/<gem>.json

# Search gems
curl "https://rubygems.org/api/v1/search.json?query=<query>"
```

## Alerting and Monitoring

### Slack Webhook Alert
```python
#!/usr/bin/env python3
import requests
import json

SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

def send_alert(package, registry, details):
    """Send dependency confusion alert to Slack."""
    message = {
        "text": "🚨 Dependency Confusion Alert",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Dependency Confusion Detected"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Package:*\n{package}"},
                    {"type": "mrkdwn", "text": f"*Registry:*\n{registry}"},
                    {"type": "mrkdwn", "text": f"*Details:*\n{details}"}
                ]
            }
        ]
    }
    
    requests.post(SLACK_WEBHOOK, json=message)

# Example usage
send_alert("company-utils", "npm (public)", 
          "Package with internal name found on public registry")
```

### Splunk Alert Query
```spl
index=ci_cd sourcetype=npm_install
| rex field=_raw "npm.*install.*(?<package>[a-z0-9\-]+)@"
| lookup internal_packages.csv package OUTPUT is_internal
| where is_internal=1
| rex field=_raw "registry\.npmjs\.org|pypi\.org"
| where match(_raw, "registry\.npmjs\.org|pypi\.org")
| stats count by package, host
| where count > 0
| eval severity="HIGH"
| sendalert email to="security@yourorg.com"
```

## References

- npm CLI Documentation: https://docs.npmjs.com/cli/
- pip User Guide: https://pip.pypa.io/en/stable/
- Maven Settings Reference: https://maven.apache.org/settings.html
- RubyGems Reference: https://guides.rubygems.org/
- Socket.dev CLI: https://github.com/SocketDev/socket-cli
- Syft SBOM Generator: https://github.com/anchore/syft
- Grype Vulnerability Scanner: https://github.com/anchore/grype
