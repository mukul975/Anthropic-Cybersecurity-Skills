# GCP Binary Authorization Implementation Template

## Configuration
| Setting | Value |
|---------|-------|
| Project ID | |
| GKE Cluster | |
| Attestor Name | |
| KMS Key Location | |
| Policy Mode | Enforce / Dry-Run |

## Attestor Checklist
- [ ] KMS keyring and key created
- [ ] Container Analysis note created
- [ ] Attestor created and linked to note
- [ ] Public key added to attestor
- [ ] CI/CD pipeline creates attestations
- [ ] Break-glass procedure documented

## Policy Configuration
| Rule | Scope | Mode | Attestors Required |
|------|-------|------|--------------------|
| Default | All clusters | | |
| Production | prod-cluster | | |
| Staging | staging-cluster | | |
