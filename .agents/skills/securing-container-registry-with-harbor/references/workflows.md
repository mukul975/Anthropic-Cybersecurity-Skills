# Workflows - Harbor Registry Security

## Workflow 1: Secure Image Pipeline
```
[Build Image] --> [Push to Harbor] --> [Auto-Scan (Trivy)] --> [Sign (Cosign)]
                                              |
                                    +---------+---------+
                                    |                   |
                                    v                   v
                            Vulnerabilities?     No vulnerabilities
                            Block deployment     Allow pull
```

## Workflow 2: Registry Hardening
```
Step 1: Enable HTTPS with valid TLS certificates
Step 2: Configure OIDC/LDAP authentication
Step 3: Create projects with auto-scan enabled
Step 4: Enable vulnerability prevention policy
Step 5: Configure content trust (Cosign)
Step 6: Set immutable tag rules for release tags
Step 7: Configure retention policies
Step 8: Enable audit logging
Step 9: Create robot accounts for CI/CD
Step 10: Test with vulnerability gate check
```
