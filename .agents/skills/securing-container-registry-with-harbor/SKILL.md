---
name: securing-container-registry-with-harbor
description: Harbor is an open-source container registry that provides security features including vulnerability scanning (integrated Trivy), image signing (Notary/Cosign), RBAC, content trust policies, replicatio
domain: cybersecurity
subdomain: container-security
tags: [containers, kubernetes, docker, security, registry, harbor]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Securing Container Registry with Harbor

## Overview

Harbor is an open-source container registry that provides security features including vulnerability scanning (integrated Trivy), image signing (Notary/Cosign), RBAC, content trust policies, replication, and audit logging. Securing Harbor involves configuring these features to enforce image provenance, prevent vulnerable image deployment, and maintain registry access control.

## Prerequisites

- Harbor 2.10+ installed (Helm or Docker Compose)
- TLS certificates for HTTPS
- Trivy scanner integration
- OIDC/LDAP for authentication
- Kubernetes cluster (for deployment target)

## Implementation Steps

### Step 1: Install Harbor with Security Configuration

```yaml
# harbor-values.yaml for Helm deployment
expose:
  type: ingress
  tls:
    enabled: true
    certSource: secret
    secret:
      secretName: harbor-tls
      notarySecretName: harbor-tls
  ingress:
    hosts:
      core: harbor.example.com
      notary: notary.example.com

externalURL: https://harbor.example.com

persistence:
  enabled: true
  resourcePolicy: "keep"

harborAdminPassword: "<strong-password>"

trivy:
  enabled: true
  gitHubToken: "<github-token>"
  severity: "CRITICAL,HIGH,MEDIUM"
  autoScan: true

notary:
  enabled: true

core:
  secretKey: "<32-char-secret>"

database:
  type: external
  external:
    host: postgres.example.com
    port: "5432"
    username: harbor
    password: "<db-password>"
    sslmode: require
```

```bash
helm repo add harbor https://helm.getharbor.io
helm install harbor harbor/harbor -f harbor-values.yaml -n harbor --create-namespace
```

### Step 2: Configure Vulnerability Scanning Policies

```bash
# Enable auto-scan on push (via Harbor API)
curl -k -X PUT "https://harbor.example.com/api/v2.0/projects/myproject" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "auto_scan": "true",
      "severity": "critical",
      "prevent_vul": "true",
      "reuse_sys_cve_allowlist": "true"
    }
  }'
```

### Step 3: Configure Content Trust

```bash
# Enable content trust at project level
curl -k -X PUT "https://harbor.example.com/api/v2.0/projects/myproject" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "enable_content_trust": "true",
      "enable_content_trust_cosign": "true"
    }
  }'

# Sign image with Cosign
cosign sign --key cosign.key harbor.example.com/myproject/myapp:v1.0.0

# Verify signature
cosign verify --key cosign.pub harbor.example.com/myproject/myapp:v1.0.0
```

### Step 4: Configure RBAC and Project Isolation

```bash
# Create project with private visibility
curl -k -X POST "https://harbor.example.com/api/v2.0/projects" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "production",
    "metadata": {
      "public": "false",
      "auto_scan": "true",
      "prevent_vul": "true",
      "severity": "high"
    }
  }'

# Harbor roles: ProjectAdmin, Maintainer, Developer, Guest, LimitedGuest
# Add member with specific role
curl -k -X POST "https://harbor.example.com/api/v2.0/projects/production/members" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": 3,
    "member_user": {"username": "developer1"}
  }'
```

### Step 5: Configure Immutable Tags and Retention

```bash
# Create tag immutability rule (prevent overwriting release tags)
curl -k -X POST "https://harbor.example.com/api/v2.0/projects/production/immutabletagrules" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "tag_filter": "v*",
    "scope_selectors": {
      "repository": [{"kind": "doublestar", "decoration": "repoMatches", "pattern": "**"}]
    }
  }'

# Configure retention policy (keep last 10 tags, delete untagged after 7 days)
curl -k -X POST "https://harbor.example.com/api/v2.0/retentions" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "or",
    "rules": [
      {
        "action": "retain",
        "template": "latestPushedK",
        "params": {"latestPushedK": 10},
        "tag_selectors": [{"kind": "doublestar", "decoration": "matches", "pattern": "**"}],
        "scope_selectors": {"repository": [{"kind": "doublestar", "decoration": "repoMatches", "pattern": "**"}]}
      }
    ],
    "trigger": {"kind": "Schedule", "settings": {"cron": "0 0 * * *"}}
  }'
```

### Step 6: OIDC Authentication Integration

```yaml
# Harbor configuration for OIDC
auth_mode: oidc_auth
oidc_name: "Okta"
oidc_endpoint: "https://company.okta.com/oauth2/default"
oidc_client_id: "harbor-client-id"
oidc_client_secret: "harbor-client-secret"
oidc_groups_claim: "groups"
oidc_admin_group: "harbor-admins"
oidc_scope: "openid,profile,email,groups"
oidc_verify_cert: true
oidc_auto_onboard: true
```

## Validation Commands

```bash
# Test vulnerability prevention (should block pull of vulnerable image)
docker pull harbor.example.com/production/vulnerable-app:latest
# Expected: Error - image blocked due to vulnerabilities

# Verify content trust enforcement
DOCKER_CONTENT_TRUST=0 docker push harbor.example.com/production/unsigned:latest
# Expected: Push rejected due to content trust policy

# Check scan results via API
curl -k "https://harbor.example.com/api/v2.0/projects/production/repositories/myapp/artifacts/v1.0.0/additions/vulnerabilities" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)"

# Audit log check
curl -k "https://harbor.example.com/api/v2.0/audit-logs?page=1&page_size=10" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)"
```

## References

- [Harbor Documentation](https://goharbor.io/docs/)
- [Harbor Security Best Practices](https://goharbor.io/docs/2.10.0/administration/vulnerability-scanning/)
- [Harbor GitHub Repository](https://github.com/goharbor/harbor)
