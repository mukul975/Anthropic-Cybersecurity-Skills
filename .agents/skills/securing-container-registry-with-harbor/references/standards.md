# Standards Reference - Harbor Container Registry Security

## NIST SP 800-190 - Container Security
- Use private registries with TLS
- Scan all images for vulnerabilities before deployment
- Sign images and verify signatures
- Implement RBAC on registry access
- Enable audit logging

## CIS Docker Benchmark
- 2.5: Ensure insecure registries are not used
- 4.2: Ensure containers use trusted base images
- 4.4: Ensure images are scanned for vulnerabilities
- 4.5: Ensure Content trust for Docker is enabled

## Harbor Security Features
| Feature | Purpose |
|---------|---------|
| Trivy Scanner | Vulnerability detection in images |
| Content Trust | Image signing with Notary/Cosign |
| RBAC | Role-based project access control |
| Vulnerability Prevention | Block deployment of vulnerable images |
| Immutable Tags | Prevent tag overwriting |
| Audit Logs | Track all registry operations |
| Replication | Secure cross-registry replication |
| Retention Policies | Automated cleanup of old images |
| Robot Accounts | Service-to-service authentication |
| OIDC/LDAP | Enterprise identity integration |
