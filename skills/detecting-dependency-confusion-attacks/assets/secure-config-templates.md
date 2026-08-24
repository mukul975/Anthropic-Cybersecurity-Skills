# Secure Package Manager Configuration Templates

## npm Configuration

### .npmrc (Project-Level - Recommended)
```ini
# Scoped packages to private registry
@yourorg:registry=https://npm.yourorg.com/
@yourorg:always-auth=true

# Authentication for private registry
//npm.yourorg.com/:_authToken=${NPM_TOKEN}

# Optional: Strict SSL (enable for production)
strict-ssl=true

# Optional: Audit level threshold
audit-level=moderate

# Optional: Package lock
package-lock=true
```

### .npmrc (User-Level)
```ini
# Location: ~/.npmrc

# Private registry for organization scope
@yourorg:registry=https://npm.yourorg.com/

# Authentication token (use environment variable in CI/CD)
//npm.yourorg.com/:_authToken=${NPM_TOKEN}

# Audit settings
audit-level=moderate

# Optional: Block deprecated packages
prefer-online=true
```

### .npmrc (CI/CD Environment)
```bash
# GitHub Actions example
echo "@yourorg:registry=https://npm.yourorg.com/" > .npmrc
echo "//npm.yourorg.com/:_authToken=${NPM_TOKEN}" >> .npmrc
npm ci --ignore-scripts  # Ignore install scripts in CI for security
```

---

## PyPI Configuration

### pip.conf (Recommended - Private First)
```ini
# Location: ~/.config/pip/pip.conf (Linux/macOS)
#           %APPDATA%\pip\pip.ini (Windows)

[global]
# Private registry FIRST (checked before public)
index-url = https://pypi.yourorg.com/simple

# Public PyPI as fallback
extra-index-url = https://pypi.org/simple

# Trusted hosts (if using HTTP registry)
trusted-host = pypi.yourorg.com

# Timeout settings
timeout = 60

# Require hashes for verification (high security)
# require-hashes = true
```

### pip.conf (Maximum Security - No Fallback)
```ini
[global]
# ONLY private registry (no public fallback)
index-url = https://pypi.yourorg.com/simple

# Disable PyPI entirely
no-index = false
# Note: Set no-index = true only if ALL packages in private registry

# Require package hash verification
require-hashes = true
```

### .pypirc (Publishing Configuration)
```ini
# Location: ~/.pypirc

[distutils]
index-servers =
    yourorg
    pypi

[yourorg]
repository = https://pypi.yourorg.com/
username = __token__
password = pypi-yourorg-token-here

[pypi]
username = __token__
password = pypi-public-token-here
```

### requirements.txt with Hashes
```txt
# Generate with: pip freeze --hash
requests==2.31.0 \
    --hash=sha256:abc123...

# Or use pip-tools for management:
# pip install pip-tools
# pip-compile --generate-hashes requirements.in
```

---

## Maven Configuration

### settings.xml (User-Level)
```xml
<!-- Location: ~/.m2/settings.xml -->
<settings>
  <servers>
    <server>
      <id>company-private</id>
      <username>${env.MAVEN_USER}</username>
      <password>${env.MAVEN_PASSWORD}</password>
    </server>
  </servers>
  
  <mirrors>
    <!-- Mirror ALL requests through private repository -->
    <mirror>
      <id>company-nexus</id>
      <name>Company Nexus Repository</name>
      <url>https://nexus.yourorg.com/repository/maven-public/</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
  
  <profiles>
    <profile>
      <id>company</id>
      <repositories>
        <repository>
          <id>company-private</id>
          <url>https://nexus.yourorg.com/repository/maven-private/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  
  <activeProfiles>
    <activeProfile>company</activeProfile>
  </activeProfiles>
</settings>
```

### pom.xml (Project-Level)
```xml
<project>
  <repositories>
    <!-- Private repository FIRST -->
    <repository>
      <id>company-private</id>
      <name>Company Private Repository</name>
      <url>https://nexus.yourorg.com/repository/maven-private/</url>
      <releases><enabled>true</enabled></releases>
      <snapshots><enabled>false</enabled></snapshots>
    </repository>
    
    <!-- Maven Central as fallback -->
    <repository>
      <id>central</id>
      <name>Maven Central</name>
      <url>https://repo.maven.apache.org/maven2</url>
      <releases><enabled>true</enabled></releases>
    </repository>
  </repositories>
  
  <pluginRepositories>
    <pluginRepository>
      <id>company-private</id>
      <url>https://nexus.yourorg.com/repository/maven-private/</url>
    </pluginRepository>
  </pluginRepositories>
</project>
```

---

## RubyGems Configuration

### Gemfile (Recommended - Explicit Sourcing)
```ruby
# Private gems from company server
source 'https://gems.yourorg.com' do
  gem 'company-auth'
  gem 'company-utils'
  gem 'company-db-connector'
end

# Public gems from RubyGems.org
source 'https://rubygems.org' do
  gem 'rails', '~> 7.0'
  gem 'devise'
  gem 'sidekiq'
end
```

### Gemfile (Single Source - Private First)
```ruby
# Primary source (private)
source 'https://gems.yourorg.com'

# Fallback to public
source 'https://rubygems.org'

# Gems will be resolved from private first, then public
gem 'company-auth'
gem 'rails'
```

### ~/.gemrc (User-Level)
```yaml
# Global gem configuration
---
:sources:
  - https://gems.yourorg.com/
  - https://rubygems.org/

# Credentials for private server
:yourorg:
  :username: <%= ENV['GEM_USER'] %>
  :password: <%= ENV['GEM_PASSWORD'] %>

# Security settings
:ssl_verify_mode: 1  # VERIFY_PEER
:bulk_threshold: 1000
```

### Bundle Configuration
```bash
# Set private gem server credentials
bundle config gems.yourorg.com $GEM_USER:$GEM_PASSWORD

# Force HTTPS
bundle config force_ruby_platform true

# Disable post-install messages (security)
bundle config silence_root_warning true
```

---

## NuGet Configuration (.NET)

### nuget.config (Project-Level)
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <!-- Clear default sources -->
    <clear />
    
    <!-- Private feed FIRST -->
    <add key="CompanyNuGet" value="https://nuget.yourorg.com/v3/index.json" />
    
    <!-- Public NuGet.org as fallback -->
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  
  <packageSourceCredentials>
    <CompanyNuGet>
      <add key="Username" value="%NUGET_USER%" />
      <add key="ClearTextPassword" value="%NUGET_PASSWORD%" />
    </CompanyNuGet>
  </packageSourceCredentials>
  
  <disabledPackageSources>
    <!-- Optionally disable public NuGet -->
    <!-- <add key="nuget.org" value="true" /> -->
  </disabledPackageSources>
</configuration>
```

---

## Go Modules (Go)

### .netrc (Private Module Authentication)
```bash
# Location: ~/.netrc
machine github.com login YOUR_GITHUB_TOKEN
machine gitlab.yourorg.com login YOUR_GITLAB_TOKEN password YOUR_PASSWORD
```

### GOPRIVATE Environment Variable
```bash
# Set private module patterns
export GOPRIVATE=github.com/yourorg/*,gitlab.yourorg.com/*

# Disable checksum database for private modules
export GONOSUMDB=github.com/yourorg/*

# Set proxy (optional)
export GOPROXY=https://proxy.golang.org,direct
```

### go.mod
```go
module github.com/yourorg/myproject

go 1.21

require (
    // Private internal modules
    github.com/yourorg/internal-lib v1.2.3
    
    // Public modules
    github.com/gin-gonic/gin v1.9.0
)

// Replace for local development
// replace github.com/yourorg/internal-lib => ../internal-lib
```

---

## Rust / Cargo

### .cargo/config.toml (Project or User-Level)
```toml
# Location: ~/.cargo/config.toml or {project}/.cargo/config.toml

[source.crates-io]
# Use private registry as primary source
replace-with = "company-registry"

[source.company-registry]
registry = "sparse+https://cargo.yourorg.com/index/"

[registries.company-registry]
index = "sparse+https://cargo.yourorg.com/index/"
token = "${CARGO_TOKEN}"

# Optional: Configure crates.io as fallback
# [source.crates-io]
# registry = "https://github.com/rust-lang/crates.io-index"
```

### Cargo.toml
```toml
[package]
name = "myproject"
version = "0.1.0"
edition = "2021"

[dependencies]
# Private crate
company-utils = { version = "1.0", registry = "company-registry" }

# Public crate
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }
```

---

## CI/CD Environment Variables

### GitHub Actions Secrets
```yaml
# .github/workflows/build.yml
env:
  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
  PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
  MAVEN_USER: ${{ secrets.MAVEN_USER }}
  MAVEN_PASSWORD: ${{ secrets.MAVEN_PASSWORD }}
  GEM_USER: ${{ secrets.GEM_USER }}
  GEM_PASSWORD: ${{ secrets.GEM_PASSWORD }}
```

### GitLab CI Variables
```yaml
# .gitlab-ci.yml
variables:
  NPM_TOKEN: $NPM_TOKEN
  PYPI_TOKEN: $PYPI_TOKEN
```

### Jenkins Credentials
```groovy
// Jenkinsfile
environment {
    NPM_TOKEN = credentials('npm-token-id')
    PYPI_TOKEN = credentials('pypi-token-id')
}
```

---

## Pre-Commit Hook (Enforce Configuration)

### .git/hooks/pre-commit
```bash
#!/bin/bash
# Enforce secure package manager configuration

echo "Checking package manager configurations..."

# Check .npmrc
if [ -f package.json ]; then
  if [ ! -f .npmrc ]; then
    echo "❌ ERROR: .npmrc missing"
    exit 1
  fi
  
  if ! grep -q "@yourorg:registry" .npmrc; then
    echo "❌ ERROR: .npmrc missing scoped registry configuration"
    exit 1
  fi
  
  # Block unscoped internal packages
  if grep -E '"(company-|internal-|yourorg-)' package.json | grep -v "@yourorg/"; then
    echo "❌ ERROR: Unscoped internal package detected"
    exit 1
  fi
fi

# Check pip.conf
if [ -f requirements.txt ]; then
  if ! pip config get global.index-url | grep -q "yourorg.com"; then
    echo "⚠️  WARNING: pip not configured with private registry"
  fi
fi

echo "✅ Configuration checks passed"
exit 0
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

---

## Security Checklist

### npm
- [ ] All internal packages use scoped names (`@yourorg/package`)
- [ ] `.npmrc` configures `@yourorg:registry`
- [ ] Authentication token uses environment variable (`${NPM_TOKEN}`)
- [ ] CI/CD runs `npm ci --ignore-scripts` to skip install scripts
- [ ] Pre-commit hook blocks unscoped internal package names

### PyPI
- [ ] `pip.conf` sets `index-url` to private registry FIRST
- [ ] `extra-index-url` points to public PyPI as fallback
- [ ] `requirements.txt` pinned to specific versions
- [ ] Hash verification enabled for critical projects (`--require-hashes`)
- [ ] CI/CD injects `PYPI_TOKEN` securely

### Maven
- [ ] `settings.xml` mirrors all requests through private repository
- [ ] `pom.xml` lists private repository before Maven Central
- [ ] Authentication uses environment variables
- [ ] OWASP Dependency-Check integrated in build

### RubyGems
- [ ] `Gemfile` uses explicit `source` blocks for private gems
- [ ] Private gem server listed before `rubygems.org`
- [ ] Credentials stored in `~/.gemrc` or environment variables
- [ ] `bundle config` set for private server authentication

---

## Testing Configuration

### Test npm Configuration
```bash
# Verify scoped package resolves to private registry
npm config get @yourorg:registry
# Expected: https://npm.yourorg.com/

# Test authentication
npm whoami --registry https://npm.yourorg.com/
# Expected: your username

# Simulate install (dry-run)
npm install --dry-run
```

### Test PyPI Configuration
```bash
# Verify index URL
pip config get global.index-url
# Expected: https://pypi.yourorg.com/simple

# Test authentication
pip search test --index https://pypi.yourorg.com/simple

# Simulate install
pip install --dry-run requests
```

### Test Maven Configuration
```bash
# Show effective settings
mvn help:effective-settings

# Show effective POM
mvn help:effective-pom

# Test dependency resolution
mvn dependency:tree
```

---

## Troubleshooting

### npm: "Unable to authenticate"
```bash
# Regenerate token
npm login --registry https://npm.yourorg.com/

# Verify token is set
npm config get //npm.yourorg.com/:_authToken
```

### PyPI: "Could not find a version"
```bash
# Check index order
pip config list -v

# Force specific index
pip install --index-url https://pypi.yourorg.com/simple package-name
```

### Maven: "Could not transfer artifact"
```bash
# Check credentials
mvn help:effective-settings | grep -A5 servers

# Test repository connection
curl -u $MAVEN_USER:$MAVEN_PASSWORD https://nexus.yourorg.com/repository/maven-private/
```

---

**Last Updated**: 2026-07-15  
**Version**: 1.0  
**Maintained by**: Security Team
