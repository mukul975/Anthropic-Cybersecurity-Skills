# Google Cloud IAP - Configuration Checklist

## Project Information
| Field | Value |
|-------|-------|
| GCP Project | ecommerce-internal-prod |
| Organization | E-Commerce Corp |
| IAP OAuth Brand | Corporate Applications |
| Lead | Security Engineering |

## IAP Backend Service Configuration

| Service | Platform | IAP Enabled | Access Level | Re-auth | Groups |
|---------|----------|-------------|-------------|---------|--------|
| admin-dashboard | GKE | Yes | managed-device | 1h / SECURE_KEY | admins@ |
| internal-api | Cloud Run | Yes | corp-network | 8h / LOGIN | engineering@ |
| monitoring | GKE | Yes | None | 8h / LOGIN | sre@, engineering@ |
| hr-portal | Compute Engine | Yes | high-trust | 4h / LOGIN | hr@ |
| finance-app | Compute Engine | Yes | high-trust | 1h / SECURE_KEY | finance@ |
| wiki | App Engine | Yes | None | 8h / LOGIN | all-staff@ |

## Access Levels

| Level Name | Type | Device Policy | Encryption | IP Restriction | Region |
|-----------|------|--------------|------------|---------------|--------|
| managed-device | Basic | Admin-approved, Screen lock | ENCRYPTED | None | US, GB |
| corp-network | Basic | None | None | 203.0.113.0/24 | US |
| high-trust | Custom (CEL) | Admin-approved, Encrypted | ENCRYPTED | Corp network OR ChromeOS | US |

## IAP TCP Tunnel Access

| VM | Zone | IAP Tunnel | Groups | External IP Removed |
|----|------|-----------|--------|-------------------|
| bastion-1 | us-central1-a | SSH | sre@ | Yes |
| db-admin | us-central1-b | SSH | dba@ | Yes |
| windows-admin | us-east1-b | RDP | admins@ | Yes |

## Validation Checklist
- [x] IAP enabled on all internal backend services
- [x] Direct access blocked (no public IPs, firewall rules restrict to LB + IAP)
- [x] Access levels applied to sensitive services
- [x] Re-authentication configured per sensitivity tier
- [x] Break-glass IAM binding created without access level conditions
- [ ] Service account programmatic access tested
- [x] Audit logs enabled and flowing to BigQuery
- [x] Alert policies created for access denials

## Sign-Off
| Role | Name | Date | Approved |
|------|------|------|----------|
| Security Architect | _________________ | __________ | [ ] |
| Cloud Platform Lead | _________________ | __________ | [ ] |
